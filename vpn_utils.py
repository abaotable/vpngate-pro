#!/usr/bin/env python3
"""工具函数：IP信息查询、延迟测试、DNS修复、OpenVPN配置解析"""
from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.request
from typing import Any

# ── 国家名中文映射 ──────────────────────────────────────────────────
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
        if line.strip().lower().startswith("proto ") and "tcp" in line:
            return True
    return False

# ── 延迟测试 ────────────────────────────────────────────────────────

def ping_latency_ms(host: str, port: int, fallback: int = 0, timeout: float = 4.0) -> int:
    """TCP 连接延迟测试，失败返回 fallback（0 表示不可达）"""
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, port), timeout=timeout)
        latency = max(1, int((time.monotonic() - t0) * 1000))
        sock.close()
        return latency
    except Exception:
        return fallback

# ── IP 信息查询（带重试） ───────────────────────────────────────────

def enrich_ip_info(nodes: list[dict[str, Any]], timeout: float = 8.0) -> None:
    """
    批量查询节点 IP 的详细地理位置和类型信息。
    使用 ip-api.com，免费额度 45次/分钟。
    IP类型采用多维度综合判断（hosting字段 + org/isp关键词 + isp与org一致性）
    """
    for node in nodes:
        ip = node.get("ip") or node.get("remote_host") or ""
        if not ip:
            _set_unknown(node)
            continue
        success = False
        for attempt in range(2):
            try:
                # 请求 isp 字段用于和 org 对比
                url = (
                    f"http://ip-api.com/json/{ip}"
                    f"?fields=status,message,country,countryCode,"
                    f"regionName,city,org,as,isp,hosting,lat,lon&lang=zh-CN"
                )
                req = urllib.request.Request(
                    url, headers={"User-Agent": "vpngate-pro/1.0"}
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode())

                if data.get("status") != "success":
                    break

                is_hosting = bool(data.get("hosting", False))
                org        = data.get("org", "")
                isp        = data.get("isp", "")
                asn        = data.get("as", "")
                city       = data.get("city", "")
                region     = data.get("regionName", "")
                country_en = data.get("country", "")

                location_parts = [p for p in [city, region] if p]
                location   = " ".join(location_parts)
                country_zh = COUNTRY_TRANSLATIONS.get(country_en, country_en)

                # ── 多维度综合判断 IP 类型 ──────────────────────────
                ip_type = _classify_ip_type(is_hosting, org, isp, asn)

                node["owner"]      = org or isp
                node["asn"]        = asn
                node["as_name"]    = org or isp
                node["isp"]        = isp
                node["location"]   = location
                node["country_zh"] = country_zh
                node["ip_type"]    = ip_type
                node["quality"]    = "机房IP" if ip_type == "datacenter" else "住宅IP"
                node["lat"]        = data.get("lat", 0)
                node["lon"]        = data.get("lon", 0)
                success = True
                break
            except Exception:
                if attempt == 0:
                    time.sleep(1)
        if not success:
            _set_unknown(node)


# 机房/云/VPS 关键词（小写匹配）
_DATACENTER_KEYWORDS = [
    "cloud", "hosting", "host", "server", "datacenter", "data center",
    "vps", "virtual", "dedicated", "coloc", "colo", "cdn", "network",
    "internet", "idc", "telecom", "backbone", "ix", "exchange",
    "amazon", "google", "microsoft", "azure", "alibaba", "tencent",
    "huawei", "oracle", "ibm", "linode", "digitalocean", "vultr",
    "ovh", "hetzner", "leaseweb", "choopa", "quadranet", "psychz",
    "cogent", "hurricane", "he.net", "zayo", "level3", "lumen",
    "ntt", "softbank", "kddi", "iij", "sakura", "conoha",
    "kagoya", "xserver", "wadax", "ablenet", "gmo", "nuro",
    "limited", "ltd", "inc", "corp", "llc", "co.", "gmbh", "s.a.",
    "enterprise", "solution", "system", "technology", "tech",
    "communication", "telecom", "broadband", "fiber",
]

# 住宅宽带 ISP 关键词（匹配到则倾向住宅）
_RESIDENTIAL_KEYWORDS = [
    "home", "residential", "consumer", "dsl", "adsl", "cable",
    "fttx", "ftth", "fios", "xfinity", "comcast", "at&t", "verizon",
    "charter", "spectrum", "t-mobile", "docomo", "au ", "biglobe",
    "plala", "ocn", "so-net", "nifty", "asahi", "willcom",
]


def _classify_ip_type(is_hosting: bool, org: str, isp: str, asn: str) -> str:
    """
    综合多个维度判断 IP 类型：
    1. ip-api 直接标记 hosting=True → 机房
    2. org/isp/asn 包含明确机房关键词 → 机房
    3. org 与 isp 高度一致（住宅 IP 特征） → 住宅
    4. isp 包含住宅关键词 → 住宅
    5. 默认 → 机房（VPNGate 节点大多是服务器/机构网络）
    """
    org_l = (org or "").lower()
    isp_l = (isp or "").lower()
    asn_l = (asn or "").lower()
    combined = org_l + " " + isp_l + " " + asn_l

    # 规则1：ip-api 直接标记
    if is_hosting:
        return "datacenter"

    # 规则2：明确住宅关键词
    for kw in _RESIDENTIAL_KEYWORDS:
        if kw in combined:
            return "residential"

    # 规则3：org 与 isp 高度一致 → 住宅宽带 ISP 特征
    # 住宅 IP 的 org 和 isp 通常是同一家运营商
    if org and isp and org_l == isp_l:
        # 还要排除 org 本身是机房关键词的情况
        is_dc_org = any(kw in org_l for kw in _DATACENTER_KEYWORDS)
        if not is_dc_org:
            return "residential"

    # 规则4：明确机房关键词
    for kw in _DATACENTER_KEYWORDS:
        if kw in combined:
            return "datacenter"

    # 规则5：org 和 isp 都为空或都不匹配 → 默认机房
    # （VPNGate 志愿者节点多为大学/企业/机构网络）
    return "datacenter"


def _set_unknown(node: dict[str, Any]) -> None:
    node.setdefault("owner",      "")
    node.setdefault("asn",        "")
    node.setdefault("as_name",    "")
    node.setdefault("location",   "")
    node.setdefault("country_zh", "")
    node.setdefault("ip_type",    "unknown")
    node.setdefault("quality",    "未知")
    node.setdefault("lat",        0)
    node.setdefault("lon",        0)

# ── DNS 修复 ────────────────────────────────────────────────────────

def check_and_fix_dns() -> None:
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
