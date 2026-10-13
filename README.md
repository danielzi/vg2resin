# vg2resin

将 **VPN Gate** (`vpngate.net`) 公共 OpenVPN 节点池自动转换为 **[Resin](https://github.com/Resinat/Resin)** 可直接导入的 `socks5://` 代理订阅网关。

## 核心特性

- **双通道自适应采集**：
  - 优先通过已连通的本地 VPNGate SOCKS5 节点请求官方 `http://www.vpngate.net/api/iphone/` CSV 接口，绕过机房/云厂商 IP 静默风控。
  - 冷启动或无存活节点时自动回退至 `https://www.vpngate.net/en/` 网页端提取 `.ovpn` 配置。
- **零路由污染多隧道并发**：
  - 基于 `openvpn --route-noexec` 与 Linux 策略路由（`ip rule` + 独立路由表 `101..100+N`），所有 OpenVPN 隧道互不干扰且绝不篡改宿主机默认路由。
  - 每个隧道由 `up_hook.sh` 自动拉起绑定对应 `tunX` 源 IP 的 `microsocks` 实例，暴露独立 SOCKS5 端口（`10801..10800+N`）。
- **OpenVPN 2.6 协议兼容与自动容灾**：
  - 自动修补 `data-ciphers`、`data-ciphers-fallback AES-128-CBC` 与 `tls-cipher "DEFAULT:@SECLEVEL=0"`，兼容 VPNGate 节点的传统 SoftEther 加密套件。
  - 后台守护线程定时对所有 SOCKS5 端口执行端到端公网出口探测（`checkip.amazonaws.com`），自动剔除断流节点并补充新节点。
- **Resin 原生订阅对接**：
  - 提供 `/sub`（明文 URI 列表）、`/sub/base64`（Base64 订阅）与 `/status`（JSON 状态监控）接口，自动根據请求 `Host` 头或 `?host=` 参数生成适配 Resin 的 `socks5://HOST:PORT#VG-COUNTRY-IP` 订阅。

## 目录结构

```text
.
├── Dockerfile           # 基于 Alpine 3.20 的轻量运行镜像
├── docker-compose.yml   # Docker Compose 编排文件
├── entrypoint.sh        # 容器启动脚本（自动初始化 /dev/net/tun）
├── up_hook.sh           # OpenVPN --up 策略路由与 microsocks 挂载钩子
└── app.py               # 节点采集、隧道生命周期守护与 HTTP 订阅服务
```

## 快速开始（Docker Compose）

```bash
git clone https://github.com/danielzi/vg2resin.git
cd vg2resin
docker compose up -d --build
```

## 环境变量说明

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `POOL_SIZE` | `10` | 并发维持的 VPNGate 出口隧道数量 |
| `BASE_PORT` | `10800` | SOCKS5 起始端口（实际分配 `BASE_PORT+1` ~ `BASE_PORT+POOL_SIZE`） |
| `HTTP_PORT` | `28080` | 订阅与状态 HTTP 服务监听端口 |
| `REFRESH_INTERVAL` | `120` | 节点池健康巡检与坏节点轮换周期（秒） |
| `SERVER_IP` | 自动探测 | 订阅输出的默认主机 IP（也可在请求 `/sub?host=x.x.x.x` 时动态指定） |

## 对接 Resin

在 Resin WebUI 的 **「订阅管理」 -> 「添加订阅」** 中填入远程订阅地址：

- 同机部署：`http://127.0.0.1:28080/sub`
- 跨机部署：`http://<vg2resin服务器IP>:28080/sub`

接口汇总：
- `GET /sub`：返回明文 `socks5://` 节点列表
- `GET /sub/base64`：返回 Base64 编码的订阅内容
- `GET /status`：查看当前活跃隧道、出口公网 IP、国家代码与运行时长
