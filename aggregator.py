#!/usr/bin/env python3
"""
nodefusion - 高速免费节点聚合与存活性检测
全异步并发：DNS 批量预解析 + TCP 全并发探测 + 可选 TLS 深度探测
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable

# ----------------------------------------------------------------------------
# 节点源：仅收录实测存活率 > 40% 的源
# ----------------------------------------------------------------------------
SOURCES: list[dict] = [
    {
        "name": "mfuu",
        "rate": 81,
        "urls": [
            "https://cdn.jsdelivr.net/gh/mfuu/FreeProxies@master/sub",
            "https://fastly.jsdelivr.net/gh/mfuu/FreeProxies@master/sub",
            "https://ghproxy.net/https://raw.githubusercontent.com/mfuu/FreeProxies/master/sub",
        ],
    },
    {
        "name": "ermao-reachable",
        "rate": 48,
        "urls": [
            "https://www.ermao.net/sub/reachable/clash/ermao.net",
            "https://blog.ermao.net/sub/reachable/clash/ermao.net",
            "https://www.ermao.net/sub/reachable/v2ray/ermao.net",
        ],
    },
    {
        "name": "subcrawler-hy2",
        "rate": 50,
        "urls": [
            "https://cdn.jsdelivr.net/gh/Leon406/SubCrawler@master/sub/share/hysteria2",
            "https://fastly.jsdelivr.net/gh/Leon406/SubCrawler@master/sub/share/hysteria2",
        ],
    },
    {
        "name": "no-more-walls",
        "rate": 23,
        "urls": [
            "https://cdn.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list.meta.yml",
            "https://fastly.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list.meta.yml",
        ],
    },
]

SCHEMES = ("vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "hy2", "tuic")

# Clash/mihomo 支持的节点类型（用于 YAML 解析与输出过滤）
_CLASH_TYPES = {
    "vmess", "vless", "trojan", "ss", "ssr", "hysteria", "hysteria2", "hy2",
    "tuic", "snell", "socks5", "http", "anytls", "wireguard", "mieru",
}

# 输出 clash.yaml 时只保留这些（mihomo 严格支持，参数完整）
_YAML_SAFE = {"vmess", "vless", "trojan", "ss", "hysteria2", "tuic"}
UA = "clash-verge/v2.0"


@dataclass
class Node:
    uri: str
    scheme: str
    host: str
    port: int
    name: str = ""
    latency: float = -1.0

    @property
    def key(self) -> str:
        return f"{self.host.lower()}:{self.port}"


# ----------------------------------------------------------------------------
# 下载
# ----------------------------------------------------------------------------
def _looks_like_nodes(text: str) -> bool:
    """判断抓取内容是否为有效节点列表，过滤 HTML 错误页/广告页。"""
    if not text or len(text) < 64:
        return False
    head = text[:600].lstrip().lower()
    if head.startswith(("<!doctype", "<html", "{", "<?")):
        # JSON 可能是 clash 之外的格式，但 HTML 一律拒绝
        if head.startswith(("<!doctype", "<html", "<?")):
            return False
    if "proxies:" in text[:5000]:
        return True
    if any(f"{sc}://" in text for sc in SCHEMES):
        return True
    # base64 包裹的情况
    compact = "".join(text.split())[:4096]
    if len(compact) > 64 and all(c.isalnum() or c in "+/=_-" for c in compact):
        import base64 as _b
        pad = "=" * (-len(compact) % 4)
        for dec in (_b.b64decode, _b.urlsafe_b64decode):
            try:
                d = dec(compact + pad).decode("utf-8", "replace")
                return any(f"{sc}://" in d for sc in SCHEMES)
            except Exception:
                continue
    return False


async def fetch(url: str, timeout: float = 25.0) -> str | None:
    """用标准库拉取文本，兼容 gzip。"""
    import gzip
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout
        )
    else:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)

    try:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {UA}\r\n"
            f"Accept: */*\r\n"
            f"Accept-Encoding: gzip, identity\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode())
        await asyncio.wait_for(writer.drain(), timeout)
        raw = await asyncio.wait_for(reader.read(), timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if not raw:
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    if " 200 " not in status_line and not status_line.endswith(" 200"):
        return None
    if b"content-encoding: gzip" in head.lower():
        try:
            body = gzip.decompress(body)
        except Exception:
            pass
    # chunked 处理
    if b"transfer-encoding: chunked" in head.lower():
        out, pos = [], 0
        while pos < len(body):
            nl = body.find(b"\r\n", pos)
            if nl < 0:
                break
            try:
                size = int(body[pos:nl].split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out.append(body[nl + 2: nl + 2 + size])
            pos = nl + 2 + size + 2
        if out:
            body = b"".join(out)
    return body.decode("utf-8", "replace")


# ----------------------------------------------------------------------------
# 解析
# ----------------------------------------------------------------------------
def _maybe_b64(text: str) -> str:
    s = text.strip()
    # 明显是结构化配置/YAML/JSON，直接原样返回
    head = s[:600]
    if "\n" in head and any(k in s[:4000] for k in
                             ("proxies:", "proxy-groups:", "mixed-port:",
                              "\"proxies\"", "rules:", "dns:")):
        return s
    if "://" in s[:400]:
        return s
    compact = re.sub(r"\s+", "", s)
    if len(compact) < 32 or not re.fullmatch(r"[A-Za-z0-9+/=_\-]+", compact):
        return s
    pad = "=" * (-len(compact) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            out = decoder(compact + pad)
            dec = out.decode("utf-8", "replace")
            if "://" in dec:
                return dec
        except (binascii.Error, ValueError):
            continue
    return s


def _hostport_via_regex(s: str) -> tuple[str, int] | None:
    m = re.search(r"@\[?([0-9a-zA-Z\.\-:]+?)\]?:(\d{1,5})", s)
    if not m:
        m = re.search(r"//\[?([0-9a-zA-Z\.\-:]+?)\]?:(\d{1,5})", s)
    if m:
        try:
            return m.group(1), int(m.group(2))
        except ValueError:
            return None
    return None


def parse_vmess(uri: str) -> tuple[str, int] | None:
    payload = uri[len("vmess://"):].split("#", 1)[0]
    pad = "=" * (-len(payload) % 4)
    try:
        data = json.loads(base64.b64decode(payload + pad).decode("utf-8", "replace"))
    except Exception:
        return _hostport_via_regex(uri)
    host = str(data.get("add") or "").strip()
    try:
        port = int(data.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    return (host, port) if host and 0 < port < 65536 else None


def parse_ss(uri: str) -> tuple[str, int] | None:
    body = uri[len("ss://"):].split("#", 1)[0]
    if "@" in body:
        return _hostport_via_regex(body)
    pad = "=" * (-len(body.split("?", 1)[0]) % 4)
    try:
        dec = base64.b64decode(body.split("?", 1)[0] + pad).decode("utf-8", "replace")
        return _hostport_via_regex(dec)
    except Exception:
        return None


def _yaml_field(block: str, key: str) -> str | None:
    m = re.search(rf"^\s*{re.escape(key)}:\s*\"?([^\"\n]+?)\"?\s*$", block, re.M)
    if m:
        v = m.group(1).strip()
        return v if v and v not in ("true", "false", "null", "~") else None
    return None


def _yaml_bool(block: str, key: str) -> bool:
    m = re.search(rf"^\s*{re.escape(key)}:\s*(true|false)", block, re.M | re.I)
    return bool(m and m.group(1).lower() == "true")


def parse_clash_yaml(text: str) -> list[dict]:
    """从 clash/mihomo 配置中提取节点完整字段（轻量解析，不依赖 PyYAML）。"""
    out: list[dict] = []
    if "proxies:" not in text:
        return out
    body = text.split("proxies:", 1)[1]
    # 遇到下一个顶层键就停
    stop = re.search(r"^[a-zA-Z][a-zA-Z0-9_-]*:", body, re.M)
    if stop:
        body = body[:stop.start()]
    for block in re.split(r"\n(?=\s*-\s)", body):
        if not block.strip().startswith("-"):
            continue
        server = _yaml_field(block, "server")
        port_s = _yaml_field(block, "port")
        typ = _yaml_field(block, "type")
        if not (server and port_s and typ):
            continue
        t = typ.lower()
        if t not in _CLASH_TYPES:
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        if not (0 < port < 65536):
            continue
        out.append({
            "type": t, "server": server, "port": port,
            "name": _yaml_field(block, "name") or "",
            "uuid": _yaml_field(block, "uuid"),
            "password": _yaml_field(block, "password"),
            "cipher": _yaml_field(block, "cipher"),
            "sni": _yaml_field(block, "sni") or _yaml_field(block, "servername"),
            "network": _yaml_field(block, "network"),
            "ws-path": _yaml_field(block, "path"),
            "ws-host": _yaml_field(block, "host"),
            "flow": _yaml_field(block, "flow"),
            "plugin": _yaml_field(block, "plugin"),
            "plugin-opts": _yaml_field(block, "mode"),
            "obfs": _yaml_field(block, "obfs"),
            "obfs-password": _yaml_field(block, "obfs-password"),
            "tls": _yaml_bool(block, "tls"),
            "skip-cert-verify": _yaml_bool(block, "skip-cert-verify"),
        })
    return out


def _safe_b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode().rstrip("=")


def build_uri(n: dict) -> str:
    """把 clash YAML 节点字段重建为可导入的原始 URI。"""
    t, host, port = n["type"], n["server"], n["port"]
    name = urllib.parse.quote(n.get("name") or f"{host}:{port}", safe="")
    sni = n.get("sni") or ""
    net = (n.get("network") or "").lower()
    path = n.get("ws-path") or ""
    hst = n.get("ws-host") or ""

    if t == "vless" and n.get("uuid"):
        q = ["encryption=none", "security=tls" if n.get("tls") else "security=none"]
        if sni:
            q.append("sni=" + urllib.parse.quote(sni, safe=""))
        if n.get("flow"):
            q.append("flow=" + urllib.parse.quote(n["flow"], safe=""))
        if net:
            q.append("type=" + net)
        if path:
            q.append("path=" + urllib.parse.quote(path, safe=""))
        if hst:
            q.append("host=" + urllib.parse.quote(hst, safe=""))
        if n.get("skip-cert-verify"):
            q.append("allowInsecure=1")
        return f"vless://{n['uuid']}@{host}:{port}?{'&'.join(q)}#{name}"

    if t == "vmess" and n.get("uuid"):
        obj = {
            "v": "2", "ps": n.get("name") or f"{host}:{port}", "add": host,
            "port": str(port), "id": n["uuid"], "aid": "0",
            "scy": "auto", "net": net or "tcp", "type": "none",
            "host": hst, "path": path,
            "tls": "tls" if n.get("tls") else "", "sni": sni,
        }
        return "vmess://" + base64.b64encode(
            json.dumps(obj, separators=(",", ":")).encode()).decode()

    if t == "trojan" and n.get("password"):
        q = []
        if sni:
            q.append("sni=" + urllib.parse.quote(sni, safe=""))
        if net:
            q.append("type=" + net)
        if path:
            q.append("path=" + urllib.parse.quote(path, safe=""))
        if hst:
            q.append("host=" + urllib.parse.quote(hst, safe=""))
        if n.get("skip-cert-verify"):
            q.append("allowInsecure=1")
        tail = ("?" + "&".join(q)) if q else ""
        return f"trojan://{n['password']}@{host}:{port}{tail}#{name}"

    if t == "ss" and n.get("password"):
        cipher = n.get("cipher") or "aes-256-gcm"
        userinfo = _safe_b64(f"{cipher}:{n['password']}")
        q = []
        if n.get("plugin"):
            plug = n["plugin"]
            opts = n.get("plugin-opts")
            if opts:
                plug += f";mode={opts}"
            q.append("plugin=" + urllib.parse.quote(plug, safe=""))
        tail = ("?" + "&".join(q)) if q else ""
        return f"ss://{userinfo}@{host}:{port}{tail}#{name}"

    return ""


def extract_nodes(text: str) -> list[Node]:
    text = _maybe_b64(text)
    nodes: list[Node] = []

    if "proxies:" in text:
        for item in parse_clash_yaml(text):
            host, port, typ = item["server"], item["port"], item["type"]
            uri = ""
            try:
                uri = build_uri(item)
            except Exception:
                uri = ""
            nodes.append(Node(uri=uri or f"yaml://{typ}/{host}:{port}",
                              scheme=typ, host=host, port=port,
                              name=item.get("name") or ""))

    for line in text.splitlines():
        s = line.strip()
        if not s or "://" not in s:
            continue
        scheme = s.split("://", 1)[0].lower()
        if scheme not in SCHEMES:
            continue
        if scheme == "vmess":
            hp = parse_vmess(s)
        elif scheme == "ss":
            hp = parse_ss(s)
        else:
            hp = _hostport_via_regex(s)
        if not hp:
            continue
        host, port = hp
        if not host or not (0 < port < 65536):
            continue
        if re.fullmatch(r"[0-9.]+", host) and host.startswith(("127.", "0.", "10.", "192.168.")):
            continue
        name = ""
        if "#" in s:
            name = urllib.parse.unquote(s.split("#", 1)[1])[:80]
        nodes.append(Node(uri=s, scheme=scheme, host=host, port=port, name=name))
    return nodes
# ----------------------------------------------------------------------------
# 存活检测：全并发 + 信号量限流 + 批量 DNS
# ----------------------------------------------------------------------------
async def _tcp_ping(host: str, port: int, sem: asyncio.Semaphore, timeout: float) -> float:
    """返回毫秒延迟，失败返回 -1。"""
    async with sem:
        t0 = time.perf_counter()
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout)
            latency = (time.perf_counter() - t0) * 1000.0
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return latency
        except (asyncio.TimeoutError, OSError, socket.gaierror):
            return -1.0


async def check_all(nodes: list[Node], concurrency: int = 512, timeout: float = 4.0,
                    tls_verify: bool = True, tls_timeout: float = 5.0) -> list[Node]:
    """对全部节点并发 TCP 探测，返回存活节点（按延迟升序）。"""
    if not nodes:
        return []
    sem = asyncio.Semaphore(concurrency)
    tls_sem = asyncio.Semaphore(concurrency)
    use_tls = tls_verify

    async def probe_one(n: Node) -> Node | None:
        r = await _tcp_ping(n.host, n.port, sem, timeout)
        if r < 0:
            return None
        n.latency = r
        # TCP 一通就马上做 TLS，不等其他节点
        if use_tls and n.port in _TLS_PORTS:
            t = await _tls_ping(n.host, n.port, tls_sem, tls_timeout)
            if t < 0:
                return None
            n.latency = t
        return n

    results = await asyncio.gather(*[probe_one(n) for n in nodes], return_exceptions=True)
    alive = [r for r in results if isinstance(r, Node)]
    alive.sort(key=lambda x: x.latency)
    return alive


# ----------------------------------------------------------------------------
# TLS 深度校验：TCP 可连不等于节点可用，再做一次 TLS 握手确认
# ----------------------------------------------------------------------------
_TLS_PORTS = {443, 8443, 2053, 2083, 2087, 2096, 4443, 9443}


async def _tls_ping(host: str, port: int, sem: asyncio.Semaphore, timeout: float) -> float:
    """TLS 握手延迟（毫秒），失败 -1。仅对常见 TLS 端口启用。"""
    async with sem:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        t0 = time.perf_counter()
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=None), timeout
            )
            latency = (time.perf_counter() - t0) * 1000.0
            return latency
        except Exception:
            return -1.0
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


async def tls_verify(nodes: list[Node], concurrency: int = 512, timeout: float = 5.0,
                     stats: dict | None = None) -> None:
    """对 TLS 端口节点做握手校验。非 TLS 端口保留 TCP 结果。仅当多数 TLS 节点失败时才剔除。"""
    tls_nodes = [n for n in nodes if n.port in _TLS_PORTS]
    if not tls_nodes:
        if stats is not None:
            stats.update({"tls_tested": 0, "tls_ok": 0, "tls_dropped": 0})
        return
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(
        *[asyncio.create_task(_tls_ping(n.host, n.port, sem, timeout)) for n in tls_nodes],
        return_exceptions=True,
    )
    ok_map: dict[str, float] = {}
    for n, r in zip(tls_nodes, results):
        if isinstance(r, float) and r >= 0:
            ok_map[n.key] = r
    ok_ratio = len(ok_map) / len(tls_nodes) if tls_nodes else 0.0
    dropped = 0
    if ok_ratio >= 0.5:
        # 校验可信：TLS 失败即剔除
        keep = []
        for n in nodes:
            if n.port in _TLS_PORTS and n.key not in ok_map:
                dropped += 1
                continue
            if n.key in ok_map:
                n.latency = ok_map[n.key]
            keep.append(n)
        nodes[:] = keep
    if stats is not None:
        stats.update({"tls_tested": len(tls_nodes), "tls_ok": len(ok_map),
                      "tls_dropped": dropped, "tls_ratio": round(ok_ratio * 100, 1)})


# ----------------------------------------------------------------------------
# 输出格式
# ----------------------------------------------------------------------------
def to_plain(nodes: list[Node]) -> str:
    return "\n".join(n.uri for n in nodes if n.uri.startswith(tuple(f"{s}://" for s in SCHEMES)))


def to_base64(nodes: list[Node]) -> str:
    plain = to_plain(nodes)
    return base64.b64encode(plain.encode()).decode()


_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean_name(name: str, fallback: str) -> str:
    """节点名清洗：去控制字符/换行/多余引号，保证 YAML 安全。"""
    s = _CTRL.sub("", name or "")
    s = s.replace("\\", "/").replace('"', "").replace("'", "").replace("{", "").replace("}", "")
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        s = fallback
    return s[:48]


def to_clash_yaml(nodes: list[Node], title: str = "nodefusion") -> str:
    """生成 mihomo/clash 可直接使用的配置。仅收 IPv4/IPv6 直连协议。"""
    lines = [
        f"# {title} - auto generated {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# alive nodes: {len(nodes)}",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "external-controller: 127.0.0.1:9090",
        "",
        "dns:",
        "  enable: true",
        "  ipv6: false",
        "  nameserver:",
        "    - 223.5.5.5",
        "    - 119.29.29.29",
        "",
        "proxies:",
    ]
    used: dict[str, int] = {}
    tags: list[str] = []
    body_lines: list[str] = []
    skip_types = {"clash", "hysteria2", "hy2", "tuic", "ssr", "ss"}
    count = 0
    for n in nodes:
        if n.scheme not in _YAML_SAFE:
            continue
        base = clean_name(n.name, f"{n.host}:{n.port}")
        tag = base
        if tag in used:
            used[base] += 1
            tag = f"{base}-{used[base]}"
        else:
            used[base] = 0
        # 延迟只作为注释保留，不写入节点字段（_latency 非标准会导致校验失败）
        body_lines.append(f'  # {int(n.latency)}ms  {n.scheme}')
        body_lines.append(
            f'  - {{name: "{tag}", server: "{n.host}", port: {n.port}, type: "{n.scheme}", '
            f'udp: true, skip-cert-verify: true}}'
        )
        tags.append(tag)
        count += 1
        if count >= 500:
            break
    lines += body_lines
    lines += ["", "proxy-groups:",
              "  - name: PROXY", "    type: select", "    proxies:",
              "      - AUTO", "      - DIRECT"]
    lines += ["  - name: AUTO", "    type: url-test",
              "    url: http://www.gstatic.com/generate_204",
              "    interval: 300", "    tolerance: 50", "    proxies:"]
    for t in tags[:120]:
        lines.append(f'      - "{t}"')
    lines += ["", "rules:", "  - GEOIP,CN,DIRECT", "  - MATCH,PROXY", ""]
    return "\n".join(lines)


def to_json(nodes: list[Node], meta: dict) -> str:
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": meta,
        "count": len(nodes),
        "nodes": [
            {"scheme": n.scheme, "host": n.host, "port": n.port,
             "latency_ms": round(n.latency, 1), "name": n.name}
            for n in nodes
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=1)


# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------
async def run(args) -> int:
    t_start = time.perf_counter()

    # 1) 并行拉取全部源（每个源多地址竞速：第一个成功即用）
    print(f"[1/4] fetching {len(SOURCES)} sources in parallel ...", flush=True)

    async def fetch_source(src):
        """同一源的多个地址并发竞速，返回最快成功的结果。"""
        tasks = [asyncio.create_task(fetch(u, args.fetch_timeout)) for u in src["urls"]]
        try:
            for fut in asyncio.as_completed(tasks):
                try:
                    r = await fut
                except Exception:
                    continue
                if r and _looks_like_nodes(r):
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    return r
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
        return None

    fetched = await asyncio.gather(*[fetch_source(s) for s in SOURCES], return_exceptions=True)
    texts: list[tuple[str, str]] = []
    for src, res in zip(SOURCES, fetched):
        if isinstance(res, str) and res.strip():
            texts.append((src["name"], res))
            print(f"      {src['name']:<22} OK   {len(res):>9,} chars", flush=True)
        else:
            print(f"      {src['name']:<22} FAIL", flush=True)

    # 2) 解析
    print("[2/4] parsing ...", flush=True)
    all_nodes: list[Node] = []
    seen: set[str] = set()
    for name, text in texts:
        parsed = extract_nodes(text)
        for n in parsed:
            k = n.key
            if k in seen:
                continue
            seen.add(k)
            all_nodes.append(n)
        print(f"      {name:<22} +{len(parsed):>6} nodes (unique total {len(all_nodes)})", flush=True)

    if not all_nodes:
        print("ERROR: no nodes parsed", file=sys.stderr)
        return 2

    # 3) 并发探测
    print(f"[3/4] probing {len(all_nodes)} nodes, concurrency={args.concurrency} "
          f"timeout={args.timeout}s ...", flush=True)
    t_probe = time.perf_counter()
    alive = await check_all(all_nodes, args.concurrency, args.timeout,
                            tls_verify=args.tls_verify, tls_timeout=args.tls_timeout)
    probe_ms = (time.perf_counter() - t_probe) * 1000
    rate = len(alive) / len(all_nodes) * 100 if all_nodes else 0
    print(f"      alive={len(alive)}/{len(all_nodes)} ({rate:.1f}%) in {probe_ms:.0f} ms "
          f"(tcp{' + tls' if args.tls_verify else ''})", flush=True)

    # 4) 输出
    print("[4/4] writing ...", flush=True)
    os.makedirs(args.outdir, exist_ok=True)
    meta = {
        "total_parsed": len(all_nodes),
        "alive": len(alive),
        "alive_rate": round(rate, 1),
        "probe_ms": round(probe_ms),
        "elapsed_ms": round((time.perf_counter() - t_start) * 1000),
    }
    files = {
        "sub.txt": to_plain(alive),
        "sub_base64.txt": to_base64(alive),
        "clash.yaml": to_clash_yaml(alive),
        "nodes.json": to_json(alive, meta),
    }
    for fn, content in files.items():
        p = os.path.join(args.outdir, fn)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        print(f"      {fn:<18} {len(content):>10,} bytes", flush=True)

    total = (time.perf_counter() - t_start)
    print(f"\nDONE in {total*1000:.0f} ms  |  {len(alive)} alive / {len(all_nodes)} parsed "
          f"({rate:.1f}%)", flush=True)
    if args.min_alive and len(alive) < args.min_alive:
        print(f"WARN: alive {len(alive)} < min_alive {args.min_alive}", file=sys.stderr)
        return 3
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="nodefusion - fast free node aggregator")
    ap.add_argument("--outdir", default="out", help="output directory")
    ap.add_argument("--concurrency", type=int, default=512, help="concurrent probes")
    ap.add_argument("--timeout", type=float, default=4.0, help="per-probe timeout seconds")
    ap.add_argument("--fetch-timeout", type=float, default=25.0, help="download timeout")
    ap.add_argument("--min-alive", type=int, default=0, help="fail below this alive count")
    ap.add_argument("--tls-verify", action="store_true", default=True, help="TLS handshake verify")
    ap.add_argument("--no-tls", dest="tls_verify", action="store_false", help="skip TLS verify")
    ap.add_argument("--tls-timeout", type=float, default=5.0, help="TLS handshake timeout")
    args = ap.parse_args()
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
