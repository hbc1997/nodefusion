#!/usr/bin/env python3
"""
nodefusion - 高速免费节点聚合 / 存活性检测 / 真实网速测试
全异步并发，零第三方依赖（纯标准库）
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

# ----------------------------------------------------------------------------
# 节点源（实测存活率 > 40%）
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

# 支持的协议
SCHEMES = ("vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "hy2", "tuic")

# mihomo 严格支持的输出类型
_YAML_SAFE = {"vmess", "vless", "trojan", "ss", "hysteria2", "tuic"}

_TLS_PORTS = {443, 8443, 2053, 2083, 2087, 2096, 4443, 9443, 2086, 2095}
UA = "clash-verge/v2.0"
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class Node:
    scheme: str
    host: str
    port: int
    name: str = ""
    params: dict = field(default_factory=dict)   # uuid/password/cipher/sni/...
    uri: str = ""
    latency: float = -1.0
    speed: float = -1.0                          # MB/s，由 speedtest 填充

    @property
    def key(self) -> str:
        return f"{self.host.lower()}:{self.port}"

    def essential_ok(self) -> bool:
        """检查该类型的必填字段是否齐全（否则在客户端不可用）。"""
        p = self.params
        if self.scheme == "vmess":
            return bool(p.get("uuid"))
        if self.scheme == "vless":
            return bool(p.get("uuid"))
        if self.scheme == "trojan":
            return bool(p.get("password"))
        if self.scheme == "ss":
            return bool(p.get("password") and p.get("cipher"))
        if self.scheme == "hysteria2":
            return bool(p.get("password"))
        if self.scheme == "tuic":
            return bool(p.get("uuid") or p.get("password"))
        return False


# ----------------------------------------------------------------------------
# 时间
# ----------------------------------------------------------------------------
def now_ms() -> float:
    return time.perf_counter() * 1000.0


# ----------------------------------------------------------------------------
# base64
# ----------------------------------------------------------------------------
def _b64v(c: int) -> int:
    if 65 <= c <= 90:
        return c - 65
    if 97 <= c <= 122:
        return c - 97 + 26
    if 48 <= c <= 57:
        return c - 48 + 52
    if c in (43, 45):
        return 62
    if c in (47, 95):
        return 63
    return -1


def b64dec(s: str) -> str:
    """宽松 base64 解码，失败返回空串。"""
    compact = re.sub(r"\s+", "", s)
    compact = compact.rstrip("=")
    pad = "=" * (-len(compact) % 4)
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return dec(compact + pad).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
    # 手动解码兜底
    vals, out = [], bytearray()
    for ch in compact:
        v = _b64v(ord(ch))
        if v < 0:
            continue
        vals.append(v)
        if len(vals) == 4:
            x = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]
            out += bytes([(x >> 16) & 255, (x >> 8) & 255, x & 255])
            vals = []
    if len(vals) == 2:
        x = (vals[0] << 18) | (vals[1] << 12)
        out.append((x >> 16) & 255)
    elif len(vals) == 3:
        x = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6)
        out += bytes([(x >> 16) & 255, (x >> 8) & 255])
    return out.decode("utf-8", "replace")


def _looks_like_nodes(text: str) -> bool:
    """判断是否为有效节点内容，过滤 HTML 错误页。"""
    if not text or len(text) < 64:
        return False
    head = text[:400].lstrip().lower()
    if head.startswith(("<!doctype", "<html", "<?xml")):
        return False
    if "proxies:" in text[:5000]:
        return True
    if any(f"{s}://" in text for s in SCHEMES):
        return True
    compact = "".join(text.split())[:4096]
    if len(compact) > 64 and all(c.isalnum() or c in "+/=_-" for c in compact):
        d = b64dec(compact)
        return any(f"{s}://" in d for s in SCHEMES)
    return False


def _maybe_b64(text: str) -> str:
    s = text.strip()
    if "\n" in s[:600] and any(k in s[:4000] for k in
                               ("proxies:", "proxy-groups:", "mixed-port:", "rules:", "dns:")):
        return s
    if "://" in s[:400]:
        return s
    compact = re.sub(r"\s+", "", s)
    if len(compact) < 32 or not re.fullmatch(r"[A-Za-z0-9+/=_\-]+", compact):
        return s
    d = b64dec(compact)
    return d if "://" in d else s
# ----------------------------------------------------------------------------
# HTTP 下载
# ----------------------------------------------------------------------------
async def fetch(url: str, timeout: float = 25.0) -> str | None:
    import gzip
    p = urllib.parse.urlsplit(url)
    host = p.hostname
    if not host:
        return None
    port = p.port or (443 if p.scheme == "https" else 80)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    try:
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout)
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except Exception:
        return None

    try:
        writer.write((
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
            f"Accept: */*\r\nAccept-Encoding: gzip, identity\r\n"
            f"Connection: close\r\n\r\n").encode())
        await asyncio.wait_for(writer.drain(), timeout)
        buf = bytearray()
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 64 * 1024 * 1024:
                break
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    raw = bytes(buf)
    if not raw:
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    if not re.search(r"\s200\s*$", status) and " 200 " not in status:
        return None
    hl = head.lower()
    if b"content-encoding: gzip" in hl:
        try:
            body = gzip.decompress(body)
        except Exception:
            pass
    if b"transfer-encoding: chunked" in hl:
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
# 节点解析（保留完整参数）
# ----------------------------------------------------------------------------
def _split_uri(uri: str) -> tuple[str, dict, str]:
    """返回 (scheme, {host,port,...}, fragment_name)。"""
    scheme, _, rest = uri.partition("://")
    scheme = scheme.lower()
    frag = ""
    if "#" in rest:
        rest, _, frag = rest.partition("#")
        frag = urllib.parse.unquote(frag)
    query = ""
    if "?" in rest:
        rest, _, query = rest.partition("?")
    return scheme.lower(), {"_rest": rest, "_query": query, "_frag": frag}, frag


def _qparse(qs: str) -> dict:
    out = {}
    for kv in qs.split("&"):
        if not kv:
            continue
        k, _, v = kv.partition("=")
        out[k.lower()] = urllib.parse.unquote(v)
    return out


def parse_uri(uri: str) -> Node | None:
    """解析一条节点 URI，完整提取参数。"""
    s = uri.strip()
    if "://" not in s:
        return None
    scheme = s.split("://", 1)[0].lower()
    if scheme == "hy2":
        scheme = "hysteria2"
    if scheme not in SCHEMES:
        return None

    frag = ""
    if "#" in s:
        frag = urllib.parse.unquote(s.split("#", 1)[1])
    body = s.split("#", 1)[0]

    params: dict = {}
    host = port = None

    if scheme == "vmess":
        payload = body[len("vmess://"):].strip()
        d = b64dec(payload)
        if not d:
            return None
        try:
            o = json.loads(d)
        except Exception:
            return None
        host = str(o.get("add") or "").strip()
        try:
            port = int(o.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        params = {
            "uuid": str(o.get("id") or "").strip(),
            "alterId": int(o.get("aid") or 0),
            "cipher": str(o.get("scy") or "auto"),
            "network": (str(o.get("net") or "tcp")).lower(),
            "tls": bool(o.get("tls")),
            "sni": str(o.get("sni") or o.get("host") or ""),
            "ws-path": str(o.get("path") or ""),
            "ws-host": str(o.get("host") or ""),
        }
    elif scheme == "ss":
        rest = body[len("ss://"):]
        qs = ""
        if "?" in rest:
            rest, _, qs = rest.partition("?")
        if "@" in rest:
            userinfo, _, hostpart = rest.rpartition("@")
            dec = b64dec(userinfo)
            if ":" in dec:
                cipher, _, pwd = dec.partition(":")
            else:
                cipher, pwd = "aes-256-gcm", dec
            host, port = _hostport(hostpart)
            params = {"cipher": cipher, "password": pwd}
        else:
            dec = b64dec(rest)
            if "@" not in dec:
                return None
            userinfo, _, hostpart = dec.rpartition("@")
            cipher, _, pwd = userinfo.partition(":")
            host, port = _hostport(hostpart)
            params = {"cipher": cipher, "password": pwd}
        q = _qparse(qs)
        if q.get("plugin"):
            params["plugin"] = q["plugin"]
    else:
        # vless / trojan / hysteria2 / tuic / ssr
        rest = body.split("://", 1)[1]
        qs = ""
        if "?" in rest:
            rest, _, qs = rest.partition("?")
        if "@" not in rest:
            return None
        userinfo, _, hostpart = rest.rpartition("@")
        host, port = _hostport(hostpart)
        q = _qparse(qs)
        if scheme == "vless":
            params = {"uuid": urllib.parse.unquote(userinfo)}
        elif scheme == "trojan":
            params = {"password": urllib.parse.unquote(userinfo)}
        elif scheme == "hysteria2":
            params = {"password": urllib.parse.unquote(userinfo)}
        elif scheme == "tuic":
            if ":" in userinfo:
                u, _, pw = userinfo.partition(":")
                params = {"uuid": urllib.parse.unquote(u), "password": urllib.parse.unquote(pw)}
            else:
                params = {"password": urllib.parse.unquote(userinfo)}
        # 通用传输参数
        for k in ("sni", "peer", "host", "path", "type", "network", "flow",
                  "security", "alpn", "obfs", "obfs-password", "serviceName"):
            if k in q:
                params[k] = q[k]
        if q.get("sni") or q.get("peer"):
            params["sni"] = q.get("sni") or q.get("peer")
        if q.get("security", "").lower() in ("tls", "reality"):
            params["tls"] = True
        if q.get("allowinsecure") in ("1", "true"):
            params["skip-cert-verify"] = True
        if q.get("insecure") in ("1", "true"):
            params["skip-cert-verify"] = True

    if not host or not port or not (0 < int(port) < 65536):
        return None
    if host.startswith(("127.", "0.", "10.", "192.168.")) or host in ("localhost",):
        return None
    return Node(scheme=scheme, host=host, port=int(port),
                name=(frag or "")[:60], params=params, uri=s)


def _hostport(s: str) -> tuple[str | None, int]:
    s = s.strip().strip("/")
    m = re.match(r"^\[([0-9a-fA-F:]+)\]:(\d{1,5})$", s)
    if m:
        return m.group(1), int(m.group(2))
    m = re.match(r"^([^:\[\]]+):(\d{1,5})$", s)
    if m:
        try:
            return m.group(1), int(m.group(2))
        except ValueError:
            return None, 0
    return None, 0

def _yaml_field(block: str, key: str) -> str | None:
    m = re.search(rf"^\s*{re.escape(key)}:\s*\"?([^\"\n]+?)\"?\s*$", block, re.M)
    if not m:
        return None
    v = m.group(1).strip()
    return v if v and v.lower() not in ("true", "false", "null", "~") else None


def _yaml_bool(block: str, key: str) -> bool:
    m = re.search(rf"^\s*{re.escape(key)}:\s*(true|false)", block, re.M | re.I)
    return bool(m and m.group(1).lower() == "true")


def parse_clash_yaml(text: str) -> list[Node]:
    """解析 clash/mihomo YAML，完整保留节点参数。"""
    out: list[Node] = []
    if "proxies:" not in text:
        return out
    body = text.split("proxies:", 1)[1]
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
        if t == "hy2":
            t = "hysteria2"
        if t not in _YAML_SAFE:
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        if not (0 < port < 65536):
            continue
        p: dict = {}
        for k in ("uuid", "password", "cipher", "sni", "servername", "network",
                  "flow", "obfs", "obfs-password", "plugin"):
            v = _yaml_field(block, k)
            if v:
                p[k] = v
        if not p.get("sni") and p.get("servername"):
            p["sni"] = p["servername"]
        path = _yaml_field(block, "path")
        host = _yaml_field(block, "host")
        if path:
            p["ws-path"] = path
        if host:
            p["ws-host"] = host
        if _yaml_bool(block, "tls"):
            p["tls"] = True
        if _yaml_bool(block, "skip-cert-verify"):
            p["skip-cert-verify"] = True
        out.append(Node(scheme=t, host=server, port=port,
                        name=(_yaml_field(block, "name") or "")[:60], params=p))
    return out


def extract_nodes(text: str) -> list[Node]:
    text = _maybe_b64(text)
    nodes: list[Node] = []
    if "proxies:" in text:
        nodes.extend(parse_clash_yaml(text))
    for line in text.splitlines():
        s = line.strip()
        if "://" not in s:
            continue
        sc = s.split("://", 1)[0].lower()
        if sc not in SCHEMES and sc != "hy2":
            continue
        n = parse_uri(s)
        if n:
            nodes.append(n)
    return nodes


# ----------------------------------------------------------------------------
# 输出：Clash YAML（含完整参数）
# ----------------------------------------------------------------------------
def _q(v) -> str:
    s = str(v).replace('"', '\\"').replace("\n", " ")
    return f'"{s}"'



def _ys(s) -> str:
    """YAML 字符串安全引用。"""
    s = _CTRL.sub("", str(s)).replace("\\", "/")
    s = s.replace('"', "'")
    return '"' + s + '"'


def node_to_yaml_lines(n: Node, tag: str) -> list[str] | None:
    """把 Node 渲染成 clash 块式 YAML 行。缺必填字段返回 None。"""
    if not n.essential_ok():
        return None
    p = n.params
    L: list[str] = [f"  - name: {_ys(tag)}",
                    f"    type: {n.scheme}",
                    f"    server: {_ys(n.host)}",
                    f"    port: {n.port}"]

    if n.scheme == "vmess":
        L += [f"    uuid: {_ys(p['uuid'])}",
              f"    alterId: {int(p.get('alterId') or 0)}",
              f"    cipher: {_ys(p.get('cipher') or 'auto')}"]
        net = (p.get("network") or "tcp").lower()
        L.append(f"    network: {net}")
        if p.get("tls"):
            L.append("    tls: true")
            if p.get("sni"):
                L.append(f"    servername: {_ys(p['sni'])}")
        if net == "ws":
            L.append(f"    ws-opts:")
            L.append(f"      path: {_ys(p.get('ws-path') or '/')}")
            if p.get("ws-host"):
                L.append("      headers:")
                L.append(f"        Host: {_ys(p['ws-host'])}")

    elif n.scheme == "vless":
        L.append(f"    uuid: {_ys(p['uuid'])}")
        net = (p.get("network") or p.get("type") or "tcp").lower()
        if net in ("", "none"):
            net = "tcp"
        L.append(f"    network: {net}")
        if p.get("tls"):
            L.append("    tls: true")
            if p.get("sni"):
                L.append(f"    servername: {_ys(p['sni'])}")
        if p.get("flow"):
            L.append(f"    flow: {_ys(p['flow'])}")
        if net == "ws":
            L.append("    ws-opts:")
            L.append(f"      path: {_ys(p.get('ws-path') or '/')}")
            if p.get("ws-host"):
                L.append("      headers:")
                L.append(f"        Host: {_ys(p['ws-host'])}")

    elif n.scheme == "trojan":
        L.append(f"    password: {_ys(p['password'])}")
        if p.get("sni"):
            L.append(f"    sni: {_ys(p['sni'])}")
        net = (p.get("network") or p.get("type") or "").lower()
        if net == "ws":
            L.append("    network: ws")
            L.append("    ws-opts:")
            L.append(f"      path: {_ys(p.get('ws-path') or '/')}")
            if p.get("ws-host"):
                L.append("      headers:")
                L.append(f"        Host: {_ys(p['ws-host'])}")

    elif n.scheme == "ss":
        L.append(f"    cipher: {_ys(p['cipher'])}")
        L.append(f"    password: {_ys(p['password'])}")
        if p.get("plugin"):
            plug = p["plugin"]
            name, _, opts = plug.partition(";")
            L.append(f"    plugin: {_ys(name)}")
            if opts:
                L.append("    plugin-opts:")
                L.append("      mode: " + _ys(opts.split("=", 1)[-1]))

    elif n.scheme == "hysteria2":
        L.append(f"    password: {_ys(p.get('password') or '')}")
        if p.get("sni"):
            L.append(f"    sni: {_ys(p['sni'])}")
        obfs = p.get("obfs") or p.get("obfs-password")
        if p.get("obfs"):
            L.append(f"    obfs: {_ys(p['obfs'])}")
        if p.get("obfs-password"):
            L.append(f"    obfs-password: {_ys(p['obfs-password'])}")

    elif n.scheme == "tuic":
        if p.get("uuid"):
            L.append(f"    uuid: {_ys(p['uuid'])}")
        if p.get("password"):
            L.append(f"    password: {_ys(p['password'])}")
        if p.get("sni"):
            L.append(f"    sni: {_ys(p['sni'])}")

    else:
        return None

    if p.get("skip-cert-verify"):
        L.append("    skip-cert-verify: true")
    L.append("    udp: true")
    return L


def to_clash_yaml(nodes: list[Node], limit: int = 600) -> str:
    """生成 mihomo/clash 完整配置。"""
    head = [
        f"# nodefusion  generated {time.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"# alive: {len(nodes)}   speed-tested: {sum(1 for n in nodes if n.speed > 0)}",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "external-controller: 127.0.0.1:9090",
        "unified-delay: true",
        "tcp-concurrent: true",
        "",
        "dns:",
        "  enable: true",
        "  ipv6: false",
        "  enhanced-mode: normal",
        "  nameserver:",
        "    - 223.5.5.5",
        "    - 119.29.29.29",
        "",
        "proxies:",
    ]
    body: list[str] = []
    tags: list[str] = []
    used: dict[str, int] = {}
    count = 0
    for n in nodes:
        raw = (n.name or f"{n.host}:{n.port}").strip()
        tag = _CTRL.sub("", raw)[:40].replace('"', "'") or f"{n.host}:{n.port}"
        if tag in used:
            used[tag] += 1
            tag = f"{tag}-{used[tag]}"
        else:
            used[tag] = 0
        lines = node_to_yaml_lines(n, tag)
        if not lines:
            continue
        body.extend(lines)
        tags.append(tag)
        count += 1
        if count >= limit:
            break

    if not tags:
        body = ["  # no compatible nodes"]
        tags = ["DIRECT"]

    tail = ["", "proxy-groups:",
            "  - name: PROXY",
            "    type: select",
            "    proxies:",
            "      - AUTO"] + [f"      - {_ys(t)}" for t in tags[:80]] + [
            "      - DIRECT",
            "",
            "  - name: AUTO",
            "    type: url-test",
            "    url: http://www.gstatic.com/generate_204",
            "    interval: 300",
            "    tolerance: 50",
            "    lazy: false",
            "    proxies:"] + [f"      - {_ys(t)}" for t in tags[:120]] + [
            "",
            "rules:",
            "  - GEOIP,CN,DIRECT",
            "  - MATCH,PROXY",
            ""]
    return "\n".join(head + body + tail)

# ----------------------------------------------------------------------------
# 真实网速测试（通过 mihomo 内核）

# 原理：起一个 mihomo 实例加载全部候选节点，用它的 /proxies/{name}/delay
# 接口并发测真实 HTTP 延迟，再用长连接下载测速端点算带宽。
# ----------------------------------------------------------------------------
MIHOMO_VERSION = "v1.19.34"


def _mihomo_urls() -> list[str]:
    """mihomo release 文件名带 v1-v 前缀，构造多个候选 + 镜像。"""
    v = MIHOMO_VERSION.lstrip("v")
    names = [
        f"mihomo-linux-amd64-v1-v{v}.gz",
        f"mihomo-linux-amd64-v{v}.gz",
        f"mihomo-linux-amd64-compatible-v{v}.gz",
    ]
    bases = [
        f"https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_VERSION}/",
        f"https://ghproxy.net/https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_VERSION}/",
        f"https://cdn.jsdelivr.net/gh/MetaCubeX/mihomo@master/",
    ]
    out = []
    for b in bases[:2]:
        for n in names:
            out.append(b + n)
    return out


MIHOMO_URLS: list[str] = []  # 运行时由 _mihomo_urls() 填充

SPEEDTEST_URL = "http://cachefly.cachefly.net/10mb.test"
DELAYTEST_URL = "http://www.gstatic.com/generate_204"

CTRL_PORT = 19090
PROXY_PORT = 17890


def _find_mihomo() -> str | None:
    for c in ("mihomo", "clash-meta", "clash"):
        p = os.popen(f"command -v {c} 2>/dev/null").read().strip()
        if p:
            return p
    for p in ("./mihomo", "./bin/mihomo", "/usr/local/bin/mihomo"):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _download_mihomo(dest: str = "./mihomo") -> str | None:
    """下载并解压 mihomo 内核。"""
    import gzip
    import urllib.request
    for u in (_mihomo_urls() if not MIHOMO_URLS else MIHOMO_URLS):
        try:
            print(f"      downloading mihomo: {u.split('/')[-1]}", flush=True)
            with urllib.request.urlopen(u, timeout=60) as r:
                data = r.read()
            if data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            with open(dest, "wb") as f:
                f.write(data)
            os.chmod(dest, 0o755)
            if os.path.getsize(dest) > 5_000_000:
                return dest
        except Exception as e:
            print(f"      mirror failed: {type(e).__name__}", flush=True)
    return None


def _write_speedtest_cfg(nodes: list[Node], path: str) -> int:
    """写测速用 mihomo 配置，返回写入节点数。"""
    body: list[str] = []
    tags: list[str] = []
    used: dict[str, int] = {}
    for i, n in enumerate(nodes):
        tag = f"n{i:04d}"
        lines = node_to_yaml_lines(n, tag)
        if not lines:
            continue
        body.extend(lines)
        tags.append(tag)
    if not tags:
        return 0
    cfg = [
        f"mixed-port: {PROXY_PORT}",
        "allow-lan: false",
        "mode: global",
        "log-level: silent",
        "ipv6: false",
        "unified-delay: true",
        f"external-controller: 127.0.0.1:{CTRL_PORT}",
        "profile:",
        "  store-selected: false",
        "dns:",
        "  enable: false",
        "",
        "proxies:",
    ] + body + [
        "",
        "proxy-groups:",
        "  - name: GLOBAL",
        "    type: select",
        "    proxies:",
    ] + [f"      - {_ys(t)}" for t in tags] + [""]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(cfg))
    return len(tags)


async def _http_get(url: str, timeout: float, proxy: str | None = None,
                    read_bytes: int = 0) -> tuple[int, float]:
    """简易 HTTP GET，返回 (字节数, 毫秒)。proxy 形如 host:port。"""
    p = urllib.parse.urlsplit(url)
    host = p.hostname
    port = p.port or 80
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    t0 = time.perf_counter()
    try:
        if proxy:
            ph, _, pp = proxy.partition(":")
            conn = asyncio.open_connection(ph, int(pp))
        else:
            conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout)
    except Exception:
        return 0, -1.0
    got = 0
    try:
        req = (f"GET {url} HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        writer.write(req.encode())
        await asyncio.wait_for(writer.drain(), timeout)
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout)
            if not chunk:
                break
            got += len(chunk)
            if read_bytes and got >= read_bytes:
                break
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    el = (time.perf_counter() - t0) * 1000.0
    return got, el


async def _ctrl_get(path: str, timeout: float = 6.0) -> dict | None:
    got, _ = await _http_get(f"http://127.0.0.1:{CTRL_PORT}{path}", timeout, read_bytes=0)
    # 需要拿 body，改用带 body 的实现
    return None


async def ctrl_request(method: str, path: str, timeout: float = 8.0) -> dict | None:
    """访问 mihomo external-controller。"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", CTRL_PORT), timeout)
    except Exception:
        return None
    try:
        req = (f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               f"Connection: close\r\n\r\n")
        writer.write(req.encode())
        await asyncio.wait_for(writer.drain(), timeout)
        raw = await asyncio.wait_for(reader.read(1 << 20), timeout)
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    head, _, body = raw.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        out, pos = [], 0
        while pos < len(body):
            nl = body.find(b"\r\n", pos)
            if nl < 0:
                break
            try:
                size = int(body[pos:nl], 16)
            except ValueError:
                break
            if size == 0:
                break
            out.append(body[nl + 2:nl + 2 + size])
            pos = nl + 2 + size + 2
        if out:
            body = b"".join(out)
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None

async def speedtest_via_mihomo(candidates: list[Node], min_speed: float,
                               max_test: int, concurrency: int) -> list[Node]:
    """用 mihomo 实测节点下载速度，返回 speed >= min_speed(MB/s) 的节点。"""
    if not candidates:
        return []

    core = _find_mihomo()
    if not core:
        core = _download_mihomo()
    if not core:
        print("      !! mihomo unavailable, falling back to delay-only ranking", flush=True)
        return []

    cfg_path = "./speedtest.yaml"
    n_written = _write_speedtest_cfg(candidates, cfg_path)
    if n_written == 0:
        print("      !! no node has complete params, skip speedtest", flush=True)
        return []
    print(f"      mihomo config: {n_written} usable nodes", flush=True)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            core, "-d", "./mihomo-data", "-f", cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        # 等控制器就绪
        ready = False
        for _ in range(60):
            await asyncio.sleep(0.5)
            v = await ctrl_request("GET", "/version", timeout=1.5)
            if v and "version" in v:
                ready = True
                break
        if not ready:
            print("      !! mihomo controller not ready", flush=True)
            return []
        print(f"      mihomo ready: {v.get('version')}", flush=True)

        # 并发测速
        sem = asyncio.Semaphore(concurrency)

        async def test_one(idx: int, n: Node) -> Node | None:
            async with sem:
                tag = f"n{idx:04d}"
                await ctrl_request("PUT", f"/proxies/GLOBAL", timeout=5)  # 触发初始化
                # 用 delay 接口测真实 HTTP 延迟
                d = await ctrl_request(
                    "GET",
                    f"/proxies/{urllib.parse.quote(tag)}/delay"
                    f"?url={urllib.parse.quote(DELAYTEST_URL, safe='')}&timeout=4000",
                    timeout=8.0)
                if not d or not isinstance(d.get("delay"), int) or d["delay"] <= 0:
                    return None
                n.latency = float(d["delay"])
                # 下载测速：跑到 10MB 或 6 秒上限
                got, el = await asyncio.wait_for(
                    _http_get(SPEEDTEST_URL, 8.0,
                              proxy=f"127.0.0.1:{PROXY_PORT}",
                              read_bytes=10 * 1024 * 1024),
                    12.0)
                if got <= 0 or el <= 0:
                    n.speed = 0.0
                    return n
                mb = got / (1024.0 * 1024.0)
                n.speed = round(mb / (el / 1000.0), 3)
                return n

        order = [(i, n) for i, n in enumerate(candidates)
                 if node_to_yaml_lines(n, f"n{i:04d}")]
        order = order[:max_test]
        print(f"      speed testing {len(order)} nodes "
              f"(concurrency={concurrency}) ...", flush=True)
        t0 = time.perf_counter()
        results = await asyncio.gather(
            *[test_one(i, n) for i, n in order], return_exceptions=True)
        el = time.perf_counter() - t0

        passed: list[Node] = []
        for r in results:
            if isinstance(r, Node) and r.speed >= min_speed:
                passed.append(r)
        passed.sort(key=lambda n: n.speed, reverse=True)
        print(f"      speedtest done in {el:.1f}s: "
              f"{len(passed)}/{len(order)} >= {min_speed} MB/s", flush=True)
        return passed
    finally:
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), 8)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

# ----------------------------------------------------------------------------
# 存活性探测
# ----------------------------------------------------------------------------
async def _tcp_ping(host: str, port: int, sem: asyncio.Semaphore, timeout: float) -> float:
    async with sem:
        t0 = time.perf_counter()
        w = None
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            return (time.perf_counter() - t0) * 1000.0
        except Exception:
            return -1.0
        finally:
            if w is not None:
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass


async def check_all(nodes: list[Node], concurrency: int, timeout: float) -> list[Node]:
    sem = asyncio.Semaphore(concurrency)
    res = await asyncio.gather(
        *[asyncio.create_task(_tcp_ping(n.host, n.port, sem, timeout)) for n in nodes],
        return_exceptions=True)
    alive = []
    for n, r in zip(nodes, res):
        if isinstance(r, float) and r >= 0:
            n.latency = r
            alive.append(n)
    alive.sort(key=lambda x: x.latency)
    return alive


# ----------------------------------------------------------------------------
# 其它输出格式
# ----------------------------------------------------------------------------
def to_plain(nodes: list[Node]) -> str:
    out = []
    for n in nodes:
        if n.uri:
            out.append(n.uri)
        else:
            u = _rebuild_uri(n)
            if u:
                out.append(u)
    return "\n".join(out)


def _rebuild_uri(n: Node) -> str:
    p = n.params
    name = urllib.parse.quote(n.name or f"{n.host}:{n.port}", safe="")
    sni = p.get("sni") or ""
    if n.scheme == "vless" and p.get("uuid"):
        q = ["encryption=none", "security=tls" if p.get("tls") else "security=none"]
        if sni:
            q.append("sni=" + urllib.parse.quote(sni, safe=""))
        if p.get("flow"):
            q.append("flow=" + urllib.parse.quote(p["flow"], safe=""))
        net = (p.get("network") or "").lower()
        if net:
            q.append("type=" + net)
        if p.get("ws-path"):
            q.append("path=" + urllib.parse.quote(p["ws-path"], safe=""))
        if p.get("ws-host"):
            q.append("host=" + urllib.parse.quote(p["ws-host"], safe=""))
        if p.get("skip-cert-verify"):
            q.append("allowInsecure=1")
        return f"vless://{p['uuid']}@{n.host}:{n.port}?{'&'.join(q)}#{name}"
    if n.scheme == "vmess" and p.get("uuid"):
        o = {"v": "2", "ps": n.name or f"{n.host}:{n.port}", "add": n.host,
             "port": str(n.port), "id": p["uuid"],
             "aid": str(p.get("alterId") or 0),
             "scy": p.get("cipher") or "auto",
             "net": (p.get("network") or "tcp"),
             "type": "none", "host": p.get("ws-host") or "",
             "path": p.get("ws-path") or "",
             "tls": "tls" if p.get("tls") else "", "sni": sni}
        return "vmess://" + base64.b64encode(
            json.dumps(o, separators=(",", ":")).encode()).decode()
    if n.scheme == "trojan" and p.get("password"):
        q = []
        if sni:
            q.append("sni=" + urllib.parse.quote(sni, safe=""))
        if p.get("skip-cert-verify"):
            q.append("allowInsecure=1")
        tail = ("?" + "&".join(q)) if q else ""
        return f"trojan://{p['password']}@{n.host}:{n.port}{tail}#{name}"
    if n.scheme == "ss" and p.get("password") and p.get("cipher"):
        ui = base64.b64encode(f"{p['cipher']}:{p['password']}".encode()).decode().rstrip("=")
        q = []
        if p.get("plugin"):
            q.append("plugin=" + urllib.parse.quote(p["plugin"], safe=""))
        tail = ("?" + "&".join(q)) if q else ""
        return f"ss://{ui}@{n.host}:{n.port}{tail}#{name}"
    if n.scheme == "hysteria2" and p.get("password"):
        q = []
        if sni:
            q.append("sni=" + urllib.parse.quote(sni, safe=""))
        tail = ("?" + "&".join(q)) if q else ""
        return f"hysteria2://{p['password']}@{n.host}:{n.port}{tail}#{name}"
    return ""


def to_base64(nodes: list[Node]) -> str:
    return base64.b64encode(to_plain(nodes).encode()).decode()


def to_json(nodes: list[Node], meta: dict) -> str:
    return json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": meta,
        "count": len(nodes),
        "nodes": [{
            "scheme": n.scheme, "host": n.host, "port": n.port,
            "name": n.name, "latency_ms": round(n.latency, 1),
            "speed_mbps": round(n.speed, 3) if n.speed >= 0 else None,
        } for n in nodes],
    }, ensure_ascii=False, indent=1)

# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------
async def run(args) -> int:
    t_start = time.perf_counter()

    print(f"[1/5] fetching {len(SOURCES)} sources ...", flush=True)

    async def fetch_source(src):
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

    fetched = await asyncio.gather(*[fetch_source(s) for s in SOURCES],
                                   return_exceptions=True)
    texts: list[tuple[str, str]] = []
    for src, res in zip(SOURCES, fetched):
        if isinstance(res, str) and res.strip():
            texts.append((src["name"], res))
            print(f"      {src['name']:<20} OK {len(res):>9,} chars", flush=True)
        else:
            print(f"      {src['name']:<20} FAIL", flush=True)

    print("[2/5] parsing ...", flush=True)
    all_nodes: list[Node] = []
    seen: set[str] = set()
    for name, text in texts:
        parsed = extract_nodes(text)
        usable = [n for n in parsed if n.essential_ok()]
        for n in usable:
            k = n.key
            if k in seen:
                continue
            seen.add(k)
            all_nodes.append(n)
        print(f"      {name:<20} +{len(parsed):>5} parsed "
              f"({len(usable)} complete) total={len(all_nodes)}", flush=True)

    if not all_nodes:
        print("ERROR: no usable nodes", file=sys.stderr)
        return 2

    print(f"[3/5] tcp probing {len(all_nodes)} nodes "
          f"(c={args.concurrency}, t={args.timeout}s) ...", flush=True)
    t_probe = time.perf_counter()
    alive = await check_all(all_nodes, args.concurrency, args.timeout)
    probe_ms = (time.perf_counter() - t_probe) * 1000
    print(f"      alive={len(alive)}/{len(all_nodes)} "
          f"({len(alive)/len(all_nodes)*100:.1f}%) in {probe_ms:.0f} ms", flush=True)

    tls_stats: dict = {}
    if args.tls_verify and alive:
        t0 = time.perf_counter()
        await tls_verify(alive, args.concurrency, args.tls_timeout, tls_stats)
        print(f"      tls: tested={tls_stats.get('tls_tested',0)} "
              f"ok={tls_stats.get('tls_ok',0)} drop={tls_stats.get('tls_dropped',0)} "
              f"in {(time.perf_counter()-t0)*1000:.0f} ms", flush=True)
        alive.sort(key=lambda x: x.latency)

    # 4) 真实网速测试
    speed_passed: list[Node] = []
    if not args.no_speedtest and alive:
        print(f"[4/5] speed test (min {args.min_speed} MB/s) ...", flush=True)
        speed_passed = await speedtest_via_mihomo(
            alive, args.min_speed, args.max_speedtest, args.speed_concurrency)
        if speed_passed:
            alive = speed_passed
    else:
        print("[4/5] speed test skipped", flush=True)

    print(f"[5/5] writing {len(alive)} nodes ...", flush=True)
    os.makedirs(args.outdir, exist_ok=True)
    meta = {
        "total_parsed": len(all_nodes),
        "alive": len(alive),
        "alive_rate": round(len(alive) / len(all_nodes) * 100, 1),
        "probe_ms": round(probe_ms),
        "min_speed_mbps": args.min_speed if not args.no_speedtest else None,
        "speed_tested": len(speed_passed),
        "elapsed_ms": round((time.perf_counter() - t_start) * 1000),
        "tls": tls_stats,
    }
    files = {
        "sub.txt": to_plain(alive),
        "sub_base64.txt": to_base64(alive),
        "clash.yaml": to_clash_yaml(alive),
        "nodes.json": to_json(alive, meta),
    }
    for fn, content in files.items():
        with open(os.path.join(args.outdir, fn), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write(content)
        print(f"      {fn:<18} {len(content):>9,} chars", flush=True)

    total = (time.perf_counter() - t_start)
    print(f"\nDONE {total:.1f}s | {len(alive)} alive "
          f"({len(alive)/max(1,len(all_nodes))*100:.1f}%)", flush=True)
    if args.min_alive and len(alive) < args.min_alive:
        print(f"WARN: alive {len(alive)} < min_alive {args.min_alive}", file=sys.stderr)
        return 3
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="nodefusion - fast free node aggregator")
    ap.add_argument("--outdir", default="out")
    ap.add_argument("--concurrency", type=int, default=4096)
    ap.add_argument("--timeout", type=float, default=2.5)
    ap.add_argument("--fetch-timeout", type=float, default=25.0)
    ap.add_argument("--min-alive", type=int, default=0)
    ap.add_argument("--tls-verify", dest="tls_verify", action="store_true", default=False)
    ap.add_argument("--tls-timeout", type=float, default=4.0)
    ap.add_argument("--min-speed", type=float, default=0.1,
                    help="minimum download speed in MB/s (default 0.1)")
    ap.add_argument("--max-speedtest", type=int, default=150,
                    help="max nodes to speed test")
    ap.add_argument("--speed-concurrency", type=int, default=12)
    ap.add_argument("--no-speedtest", action="store_true",
                    help="skip mihomo speed test")
    args = ap.parse_args()
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())

# ----------------------------------------------------------------------------
# TLS 校验（可选）
# ----------------------------------------------------------------------------
async def _tls_ping(host: str, port: int, sem: asyncio.Semaphore, timeout: float) -> float:
    async with sem:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t0 = time.perf_counter()
        w = None
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx,
                                        server_hostname=None), timeout)
            return (time.perf_counter() - t0) * 1000.0
        except Exception:
            return -1.0
        finally:
            if w is not None:
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass


async def tls_verify(nodes: list[Node], concurrency: int, timeout: float,
                     stats: dict | None = None) -> None:
    """对 TLS 端口节点做握手校验；仅当多数成功时才采信并剔除失败者。"""
    cand = [n for n in nodes if n.port in _TLS_PORTS]
    if stats is not None:
        stats.update({"tls_tested": len(cand), "tls_ok": 0, "tls_dropped": 0})
    if not cand:
        return
    sem = asyncio.Semaphore(concurrency)
    res = await asyncio.gather(
        *[asyncio.create_task(_tls_ping(n.host, n.port, sem, timeout)) for n in cand],
        return_exceptions=True)
    ok = {n.key: r for n, r in zip(cand, res) if isinstance(r, float) and r >= 0}
    ratio = len(ok) / len(cand)
    dropped = 0
    if ratio >= 0.5:
        keep = []
        for n in nodes:
            if n.port in _TLS_PORTS and n.key not in ok:
                dropped += 1
                continue
            if n.key in ok:
                n.latency = ok[n.key]
            keep.append(n)
        nodes[:] = keep
    if stats is not None:
        stats.update({"tls_ok": len(ok), "tls_dropped": dropped,
                      "tls_ratio": round(ratio * 100, 1)})
