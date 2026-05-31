#!/usr/bin/env python3
"""工具函数：IP信息查询、延迟测试、DNS修复、OpenVPN配置解析"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import urllib.request
from typing import Any

# ── 国家名中文映射（常见国家）──────────────────────────────────────
COUNTRY_TRANSLATIONS: dict[str, str] = {
    "Japan": "日本", "United States": "美国", "Korea": "韩国",
    "South Korea": "韩国", "China": "中国", "Taiwan": "台湾",
    "Hong Kong": "香港", "Singapore": "新加坡", "Thailand": "泰国",
    "Vietnam": "越南", "India": "印度", "Russia": "俄罗斯",
    "Germany": "德国", "France": "法国", "United Kingdom": "英国",
    "Canada": "加拿大", "Australia": "澳大利亚", "Brazil": "巴西",
    "Netherlands": "荷兰", "Sweden": "瑞典", "Switzerland": "瑞士",
    "Italy": "意大利", "Spain": "西班牙", "Poland": "波兰",
    "Turkey": "土耳其", "Indonesia": "印度尼西亚", "Malaysia": "马来西亚",
    "Philippines": "菲律宾", "Mexico": "墨西哥", "Argentina": "阿根廷",
    "Ukraine": "乌克兰", "Romania": "罗马尼亚", "Czech Republic": "捷克",
    "Hungary": "匈牙利", "Finland": "芬兰", "Norway": "挪威",
    "Denmark": "丹麦", "Belgium": "比利时", "Austria": "奥地利",
    "Portugal": "葡萄牙", "Greece": "希腊", "Israel": "以色列",
    "United Arab Emirates": "阿联酋", "Saudi Arabia": "沙特阿拉伯",
    "South Africa": "南非", "Egypt": "埃及", "Nigeria": "尼日利亚",
    "New Zealand": "新西兰", "Mongolia": "蒙古", "Kazakhstan": "哈萨克斯坦",
    "Unknown": "未知",
}

# ── OpenVPN 配置解析 ────────────────────────────────────────────────

def parse_remote(config_text: str, fallback_ip: str = "") -> tuple[str, int, str]:
    """从 ovpn 配置中解析 remote host, port, proto"""
    host, port, proto = fallback_ip, 1194, "udp"
    for line in config_text.splitlines():
        line = line.strip()
        if line.startswith("remote "):
            parts = line.split()
            if len(parts) >= 2:
                host = parts[1]
            if len(parts) >= 3:
                try:
                    port = int(parts[2])
                except ValueError:
                    pass
        elif line.startswith("proto "):
            parts = line.split()
            if len(parts) >= 2:
                proto = parts[1].lower().replace("6", "")
    return host, port, proto


def is_config_tcp(config_text: str) -> bool:
    for line in config_text.splitlines():
        line = line.strip().lower()
        if line.startswith("proto ") and "tcp" in line:
            return True
    return False


def get_upstream_proxy() -> tuple[str, str, int]:
    """读取环境变量中的上游代理配置，返回 (type, host, port)"""
    for var in ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "HTTP_PROXY"):
        val = os.environ.get(var, "")
        if val:
            m = re.match(r"(socks5?|http)://([^:]+):(\d+)", val)
            if m:
                return m.group(1).rstrip("5"), m.group(2), int(m.group(3))
    return "", "", 0

# ── 延迟测试 ────────────────────────────────────────────────────────

def ping_latency_ms(host: str, port: int, fallback: int = 0, timeout: float = 4.0) -> int:
    """TCP 连接延迟测试，失败返回 fallback"""
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, port), timeout=timeout)
        latency = int((time.monotonic() - t0) * 1000)
        sock.close()
        return latency
    except Exception:
        return fallback

# ── IP 信息查询 ─────────────────────────────────────────────────────

def enrich_ip_info(nodes: list[dict[str, Any]], timeout: float = 6.0) -> None:
    """批量查询节点 IP 信息（ASN、归属地、住宅/机房类型）"""
    for node in nodes:
        ip = node.get("ip") or node.get("remote_host") or ""
        if not ip:
            continue
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,org,as,hosting"
            req = urllib.request.Request(url, headers={"User-Agent": "vpngate-pro/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                org = data.get("org", "")
                asn = data.get("as", "")
                is_hosting = data.get("hosting", False)
                node["owner"] = org
                node["asn"] = asn
                node["as_name"] = org
                node["location"] = f"{data.get('city', '')} {data.get('regionName', '')}".strip()
                node["ip_type"] = "datacenter" if is_hosting else "residential"
                node["quality"] = "机房IP" if is_hosting else "住宅IP"
        except Exception:
            node.setdefault("owner", "")
            node.setdefault("asn", "")
            node.setdefault("as_name", "")
            node.setdefault("location", "")
            node.setdefault("ip_type", "unknown")
            node.setdefault("quality", "未知")

# ── DNS 修复 ────────────────────────────────────────────────────────

def check_and_fix_dns() -> None:
    """检测 DNS 是否可用，不可用时写入备用 DNS"""
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo("www.vpngate.net", 443)
        return
    except Exception:
        pass
    resolv = "/etc/resolv.conf"
    try:
        content = open(resolv).read()
        if "8.8.8.8" not in content:
            with open(resolv, "a") as f:
                f.write("\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n")
            print("[DNS修复] 已添加备用 DNS 8.8.8.8 / 1.1.1.1", flush=True)
    except Exception as e:
        print(f"[DNS修复] 失败: {e}", flush=True)
