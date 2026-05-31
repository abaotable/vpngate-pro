# VPNGate Pro

基于 [aimili-vpngate](https://github.com/baoweise-bot/aimili-vpngate) 重构，针对 argosbx 多协议 VPS 优化的双节点智能代理网关。

## 架构

```
[ argosbx 各协议端口 ] 
         ↓ iptables REDIRECT（可按协议配置）
[ 本地代理层 ]
   Slot 1: 127.0.0.1:7920 ──绑定──▶ tun10 ──▶ VPNGate 节点 A
   Slot 2: 127.0.0.1:7921 ──绑定──▶ tun11 ──▶ VPNGate 节点 B
         ↑ SO_BINDTODEVICE 内核级强制绑定，VPN断开时返回502，不泄露真实IP
```

## 功能

- **双节点并发**：两个独立 tun 网卡，各自对应一个本地代理端口
- **节点过滤**：在 Web UI 中选择国家、IP 类型（住宅/机房）、延迟上限
- **自动切换**：节点失效时按过滤规则自动切换，不满足条件时降级到任意可用节点
- **协议路由**：5 个协议端口（VLESS-Reality/SS/VMess-WS/Hy2/SOCKS5）可单独配置走槽1/槽2/直连
- **IP 防泄漏**：tun 断开时代理返回 502，绝不回落物理网卡
- **Web 管理界面**：暗色主题，随机生成用户名密码，session 认证

## 快速安装

> 先把 `install.sh` 里的 `YOUR_GITHUB` 替换成你自己的 GitHub 用户名

```bash
bash <(curl -Ls https://raw.githubusercontent.com/YOUR_GITHUB/vpngate-pro/main/install.sh)
```

**要求**：Debian 11/12 或 Ubuntu 20/22/24，root 权限，1GB+ 内存

## 安装后使用

```bash
vg status    # 查看状态、Web UI 地址和密码
vg logs      # 实时日志
vg restart   # 重启服务
vg password  # 重置管理密码
vg stop      # 停止服务
vg uninstall # 卸载
```

## Web UI 操作流程

1. **控制台**：查看两个节点槽状态，快速连接节点
2. **节点列表**：拉取 VPNGate 节点 → 测试 → 手动连接到指定槽
3. **过滤设置**：选择国家、IP类型、延迟上限（影响自动切换时的节点选择）
4. **协议路由**：勾选各协议是否走代理，选择走槽1还是槽2
5. **日志**：查看运行日志，排查问题

## Xray 出站配置示例

在 argosbx 的 Xray config 中添加出站：

```json
{
  "outbounds": [
    {
      "tag": "vpngate-slot1",
      "protocol": "http",
      "settings": {
        "servers": [{"address": "127.0.0.1", "port": 7920}]
      }
    },
    {
      "tag": "vpngate-slot2",
      "protocol": "http",
      "settings": {
        "servers": [{"address": "127.0.0.1", "port": 7921}]
      }
    }
  ]
}
```

## 协议端口对照

| 协议 | 端口 |
|------|------|
| VLESS-Reality | 25476 |
| Shadowsocks | 62026 |
| VMess-WS | 6123 |
| Hysteria2 | 53145 |
| SOCKS5 | 42447 |

## 文件结构

```
/opt/vpngate-pro/          # 程序目录
├── vpngate_manager.py     # 主程序（Web UI + 调度）
├── proxy_server.py        # 双节点代理服务器
└── vpn_utils.py           # 工具函数

/var/lib/vpngate-pro/      # 数据目录
├── nodes.json             # 节点列表缓存
├── state.json             # 运行状态
├── filter.json            # 过滤规则
├── routing.json           # 协议路由规则
├── ui_auth.json           # Web UI 认证配置
├── vpngate_auth.txt       # OpenVPN 认证（vpn/vpn）
├── configs/               # 临时 ovpn 配置文件
└── logs/                  # 运行日志（按日期）
```

## 注意事项

- 协议路由功能使用 `iptables REDIRECT`，需要 root 权限和 `iptable_nat` 模块
- 测试节点时会临时占用 `tun2~tun9`，不影响正在使用的 `tun10/tun11`
- 1GB 内存环境下并发测试限制为 6 个节点
- VPNGate 数据来源：[vpngate.net](https://www.vpngate.net)（日本筑波大学公开服务）

## 与原项目的主要差异

| 对比项 | aimili-vpngate | VPNGate Pro |
|--------|---------------|-------------|
| 节点数量 | 单节点 | 双节点并发 |
| 过滤规则 | 无 Web UI 配置 | Web UI 实时配置 |
| 协议路由 | 无 | 5个协议可独立配置 |
| IP类型识别 | 有 | 有（住宅/机房） |
| 认证方式 | 固定路径 | 随机用户名密码 |
| 依赖 | 零外部依赖 | 零外部依赖 |
