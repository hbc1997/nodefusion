<div align="center">

# nodefusion

**高速免费节点聚合与存活性检测 · 每 6 小时自动更新**

零依赖 Python · 全异步并发探测 · 4 秒完成 400+ 节点检测

[![Update Nodes](https://github.com/USER/REPO/actions/workflows/update.yml/badge.svg)](https://github.com/USER/REPO/actions/workflows/update.yml)

</div>

## 订阅地址

部署后把 `USER/REPO` 换成你的仓库，直接导入客户端：

| 格式 | 地址 | 适用 |
|---|---|---|
| **Clash / Mihomo** | `https://raw.githubusercontent.com/USER/REPO/main/out/clash.yaml` | Clash Verge、Clash Party、FlClash、OpenClash |
| **Base64 订阅** | `https://raw.githubusercontent.com/USER/REPO/main/out/sub_base64.txt` | v2rayN、NekoBox、Sing-box、Shadowrocket |
| **纯文本** | `https://raw.githubusercontent.com/USER/REPO/main/out/sub.txt` | 手工导入、二次处理 |
| **JSON** | `https://raw.githubusercontent.com/USER/REPO/main/out/nodes.json` | 自建面板、统计 |

> `raw.githubusercontent.com` 在国内经常超时。把域名换成任一镜像前缀即可：
> `https://cdn.jsdelivr.net/gh/USER/REPO@main/out/clash.yaml`
> `https://ghproxy.net/https://raw.githubusercontent.com/USER/REPO/main/out/clash.yaml`

## 特性

- **全并发**：多源并行下载（同源多镜像竞速）、DNS 批量解析、`asyncio` 4096 并发探测
- **快**：384 个节点 4.9 秒完成抓取+解析+探测+输出
- **准**：TCP 探测 + 可选 TLS 握手双重校验，剔除"端口开着但节点已死"的假节点
- **零依赖**：只用 Python 标准库，不需要 `pip install` 任何东西
- **自动排序**：按实际延迟升序，最快的排前面
- **多格式输出**：Clash YAML / Base64 / 纯文本 / JSON 一次生成

## 工作原理

```
每 6 小时 (GitHub Actions 定时)
      │
      ├─ 并行拉取 4 个高质量源（每个源配 2-3 个镜像竞速）
      │     mfuu · ermao · SubCrawler · NoMoreWalls
      │
      ├─ 解析 vmess / vless / trojan / ss / ssr / hysteria2 / tuic
      │     自动识别 base64 包裹与 Clash YAML
      │
      ├─ 4096 并发 TCP 探测，按延迟排序
      │     （可选 TLS 握手深度校验）
      │
      └─ 输出 4 种格式 → 自动提交到仓库 → 客户端订阅即用
```

## 本地运行

需要 Python 3.9+（不需要任何第三方库）：

```bash
python aggregator.py --outdir out --concurrency 4096 --timeout 2.5 --no-tls
```

常用参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--outdir` | `out` | 输出目录 |
| `--concurrency` | `512` | 并发探测数，4096 适合 500 节点以内 |
| `--timeout` | `4.0` | 单个节点 TCP 超时（秒） |
| `--fetch-timeout` | `25.0` | 下载超时（秒） |
| `--no-tls` | 开启校验 | 跳过 TLS 握手，速度更快但会混入少量假节点 |
| `--tls-timeout` | `5.0` | TLS 握手超时 |
| `--min-alive` | `0` | 存活数低于此值则退出码非 0（用于告警） |

## 数据源

只收录**实测存活率 > 40%** 的源：

| 源 | 实测存活率 | 说明 |
|---|---|---|
| [mfuu/FreeProxies](https://github.com/mfuu/FreeProxies) | 81% | 质量最高 |
| [Leon406/SubCrawler](https://github.com/Leon406/SubCrawler) | 50% | hysteria2 专用 |
| [ermao/get_subscribe](https://github.com/ermaozi/get_subscribe) | 48% | 服务端已测活 |
| [peasoft/NoMoreWalls](https://github.com/peasoft/NoMoreWalls) | 23% | 量大，作补充池 |

想加减源，编辑 `aggregator.py` 顶部的 `SOURCES` 列表即可。

## 注意事项

- 免费公开节点**寿命短**（几小时到几天），漏电、限速、突然失效都正常，多留备用节点
- 不要用这些节点登录网银、公司邮箱等敏感账号
- 全部节点来自公开渠道，本项目只做聚合与测活，不提供任何节点

## License

MIT