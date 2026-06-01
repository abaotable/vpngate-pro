#!/usr/bin/env python3
"""
VPNGate Pro - 双节点智能代理网关
修复：节点类型显示、测试结果实时返回、自动切换（每槽独立规则）、
      修改用户名密码、详细地理位置显示
"""
from __future__ import annotations

import base64
import concurrent.futures
import csv
import hashlib
import json
import os
import queue
import random
import re
import socket
import string
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid as _uuid_mod
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# 强制 IPv4
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        family = socket.AF_INET
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_only

import vpn_utils
import proxy_server as proxy_mod

# ── 常量 ────────────────────────────────────────────────────────────
API_URL     = "https://www.vpngate.net/api/iphone/"
ROOT_DIR    = Path(__file__).resolve().parent
DATA_DIR    = Path(os.environ.get("VPNGATE_DATA_DIR", str(ROOT_DIR / "vpngate_data")))
CONFIG_DIR  = DATA_DIR / "configs"
NODES_FILE        = DATA_DIR / "nodes.json"
CUSTOM_NODES_FILE = DATA_DIR / "custom_nodes.json"
STATE_FILE        = DATA_DIR / "state.json"
UI_AUTH_FILE      = DATA_DIR / "ui_auth.json"
ROUTING_FILE      = DATA_DIR / "routing.json"
FILTER_FILE       = DATA_DIR / "filter.json"
SLOT_CONFIG_FILE  = DATA_DIR / "slot_config.json"
AUTH_FILE         = DATA_DIR / "vpngate_auth.txt"
LOGS_DIR          = DATA_DIR / "logs"

OPENVPN_CMD        = os.environ.get("OPENVPN_CMD", "openvpn")
MAX_SCAN_ROWS      = 300
MAX_CONCURRENT_TESTS = 6
OPENVPN_TIMEOUT    = 35

SLOTS = [
    {"id": 0, "tun": "tun10", "table": 110, "proxy_port": 7920},
    {"id": 1, "tun": "tun11", "table": 111, "proxy_port": 7921},
]

PROTOCOL_PORTS = {
    "VLESS-Reality": 25476,
    "Shadowsocks":   62026,
    "VMess-WS":      6123,
    "Hysteria2":     53145,
    "SOCKS5":        42447,
}

lock = threading.RLock()

# ── Slot 运行状态 ────────────────────────────────────────────────────
class SlotState:
    def __init__(self, slot_id: int):
        self.slot_id     = slot_id
        self.process: subprocess.Popen | None = None
        self.node_id     = ""
        self.node_type   = ""   # "vpngate" | "custom"
        self.is_connecting = False
        self.status_msg  = "未启动"
        self.proxy_ok    = False
        self.proxy_ip    = ""
        self.latency_ms  = 0

slot_states = {s["id"]: SlotState(s["id"]) for s in SLOTS}

# ── 每槽自动切换配置 ─────────────────────────────────────────────────
# node_sources: 列表，按优先级，值可以是 "vpngate_residential" /
#               "vpngate_datacenter" / "vpngate_any" / "custom"
DEFAULT_SLOT_CFG = {
    "auto_switch": True,
    "node_sources": ["vpngate_residential", "vpngate_any"],
    "countries": [],
    "max_latency_ms": 0,
}

def load_slot_configs() -> dict[str, Any]:
    data = read_json(SLOT_CONFIG_FILE, {})
    result = {}
    for s in SLOTS:
        sid = str(s["id"])
        cfg = dict(DEFAULT_SLOT_CFG)
        cfg.update(data.get(sid, {}))
        result[sid] = cfg
    return result

def save_slot_configs(configs: dict[str, Any]) -> None:
    write_json(SLOT_CONFIG_FILE, configs)

# ── 辅助 ────────────────────────────────────────────────────────────
def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    LOGS_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\nvpn\n")
        AUTH_FILE.chmod(0o600)

def write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def safe_name(v: str) -> str:
    v = re.sub(r"[^A-Za-z0-9_.-]+", "_", v.strip())
    return v.strip("._") or "node"

def parse_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0

def log(level: str, module: str, msg: str) -> None:
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "level": level, "module": module, "message": msg,
    }
    try:
        log_file = LOGS_DIR / f"{time.strftime('%Y-%m-%d')}.json"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
    print(f"[{level}][{module}] {msg}", flush=True)

# ── UI 认证 ──────────────────────────────────────────────────────────
def _rand_str(n: int, alpha_start: bool = False) -> str:
    chars = string.ascii_letters + string.digits
    while True:
        s = "".join(random.choices(chars, k=n))
        if any(c.islower() for c in s) and any(c.isupper() for c in s) and any(c.isdigit() for c in s):
            if not alpha_start or s[0].isalpha():
                return s

def load_ui_config() -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "username": "", "password": "",
        "host": "0.0.0.0", "port": 8787,
    }
    if UI_AUTH_FILE.exists():
        try:
            cfg.update(json.loads(UI_AUTH_FILE.read_text()))
        except Exception:
            pass
    changed = False
    if not cfg.get("username"):
        cfg["username"] = _rand_str(12, alpha_start=True)
        changed = True
    if not cfg.get("password"):
        cfg["password"] = _rand_str(12)
        changed = True
    if changed:
        UI_AUTH_FILE.write_text(json.dumps(cfg, indent=2))
    return cfg

def save_ui_config(cfg: dict[str, Any]) -> None:
    UI_AUTH_FILE.write_text(json.dumps(cfg, indent=2))

def session_token(username: str, password: str) -> str:
    return hashlib.sha256(f"{username}:{password}:vpngate-pro-2026".encode()).hexdigest()

WEB_SESSIONS: dict[str, float] = {}
SESSION_TTL = 7200

# ── 路由规则 ─────────────────────────────────────────────────────────
DEFAULT_ROUTING = {p: {"slot": -1, "enabled": False} for p in PROTOCOL_PORTS}

def load_routing() -> dict[str, Any]:
    data = read_json(ROUTING_FILE, {})
    result = dict(DEFAULT_ROUTING)
    result.update(data)
    return result

def save_routing(routing: dict[str, Any]) -> None:
    write_json(ROUTING_FILE, routing)

def apply_routing_rules(routing: dict[str, Any]) -> None:
    for proto, port in PROTOCOL_PORTS.items():
        for slot in SLOTS:
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "OUTPUT",
                 "-p", "tcp", "--dport", str(port),
                 "-j", "REDIRECT", "--to-port", str(slot["proxy_port"])],
                capture_output=True,
            )
    for proto, cfg in routing.items():
        if not cfg.get("enabled"):
            continue
        slot_id = cfg.get("slot", -1)
        if slot_id < 0 or slot_id >= len(SLOTS):
            continue
        port = PROTOCOL_PORTS.get(proto)
        if not port:
            continue
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "OUTPUT",
             "-p", "tcp", "--dport", str(port),
             "-j", "REDIRECT", "--to-port", str(SLOTS[slot_id]["proxy_port"])],
            capture_output=True,
        )
        log("INFO", "Routing", f"{proto}:{port} → Slot{slot_id} :{SLOTS[slot_id]['proxy_port']}")

# ── 全局过滤（节点列表过滤用） ────────────────────────────────────────
DEFAULT_FILTER = {"countries": [], "ip_types": [], "max_latency_ms": 0}

def load_filter() -> dict[str, Any]:
    f = read_json(FILTER_FILE, {})
    result = dict(DEFAULT_FILTER)
    result.update(f)
    return result

def save_filter(f: dict[str, Any]) -> None:
    write_json(FILTER_FILE, f)

def node_matches_filter(node: dict[str, Any], flt: dict[str, Any]) -> bool:
    countries = flt.get("countries", [])
    if countries and node.get("country_short", "") not in countries:
        return False
    ip_types = flt.get("ip_types", [])
    if ip_types and node.get("ip_type", "") not in ip_types:
        return False
    max_lat = flt.get("max_latency_ms", 0)
    if max_lat > 0 and parse_int(node.get("latency_ms", 0)) > max_lat:
        return False
    return True

# ── VPNGate 节点拉取 ─────────────────────────────────────────────────
def fetch_candidates() -> list[dict[str, Any]]:
    log("INFO", "Fetch", "开始拉取 VPNGate 节点列表...")
    req = urllib.request.Request(
        API_URL,
        headers={"User-Agent": "Mozilla/5.0 vpngate-pro/1.0", "Accept": "text/plain,*/*"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        text = resp.read().decode("utf-8", errors="replace")

    lines = [l for l in text.splitlines() if l and not l.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]

    rows = list(csv.DictReader(lines))
    candidates: list[dict[str, Any]] = []
    seen_ips: set[str] = set()

    for row in rows[:MAX_SCAN_ROWS]:
        ip = row.get("IP", "").strip()
        if not ip or ip in seen_ips:
            continue
        encoded = row.get("OpenVPN_ConfigData_Base64", "").strip()
        if not encoded:
            continue
        try:
            config_text = base64.b64decode(encoded.encode(), validate=False).decode("utf-8", errors="replace")
        except Exception:
            continue

        country_long  = row.get("CountryLong", "")
        country_short = row.get("CountryShort", "")
        country_zh    = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, country_long)
        remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
        node_id = safe_name("_".join([country_short or "XX", ip, str(remote_port), proto]))
        config_path = CONFIG_DIR / f"{node_id}.ovpn"

        candidates.append({
            "id":           node_id,
            "node_type":    "vpngate",
            "country":      country_zh,
            "country_short": country_short,
            "country_zh":   country_zh,
            "host_name":    row.get("HostName", ""),
            "ip":           ip,
            "score":        parse_int(row.get("Score")),
            "ping":         parse_int(row.get("Ping")),
            "speed":        parse_int(row.get("Speed")),
            "config_file":  str(config_path),
            "config_text":  config_text,
            "proto":        proto,
            "remote_host":  remote_host,
            "remote_port":  remote_port,
            "fetched_at":   time.time(),
            "probe_status": "not_checked",
            "probe_message": "",
            "probed_at":    0,
            "latency_ms":   0,
            "owner":    "", "asn": "", "as_name": "",
            "location": "", "country_zh": country_zh,
            "ip_type":  "unknown", "quality": "未知",
            "lat": 0, "lon": 0,
            "active_slot": -1,
        })
        seen_ips.add(ip)

    log("INFO", "Fetch", f"获取到 {len(candidates)} 个候选节点")
    return candidates

def sort_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available = sorted(
        [n for n in nodes if n.get("probe_status") == "available"],
        key=lambda n: (parse_int(n.get("latency_ms")) or 999999, -parse_int(n.get("score")))
    )
    untested  = sorted(
        [n for n in nodes if n.get("probe_status") == "not_checked"],
        key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavail = [n for n in nodes if n.get("probe_status") == "unavailable"]
    return available + untested + unavail

# ── OpenVPN ──────────────────────────────────────────────────────────
_openvpn_ver: float | None = None

def get_openvpn_version() -> float:
    global _openvpn_ver
    if _openvpn_ver is not None:
        return _openvpn_ver
    try:
        res = subprocess.run([OPENVPN_CMD, "--version"], capture_output=True, text=True, timeout=3)
        m = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout + res.stderr)
        if m:
            _openvpn_ver = float(m.group(1))
            return _openvpn_ver
    except Exception:
        pass
    _openvpn_ver = 2.4
    return _openvpn_ver

def build_openvpn_cmd(config_file: str, tun_dev: str) -> list[str]:
    cmd = [
        OPENVPN_CMD,
        "--config", config_file,
        "--dev", tun_dev, "--dev-type", "tun",
        "--pull-filter", "ignore", "route-ipv6",
        "--pull-filter", "ignore", "ifconfig-ipv6",
        "--route-delay", "2",
        "--connect-retry-max", "1",
        "--connect-timeout", "15",
        "--auth-user-pass", str(AUTH_FILE),
        "--auth-nocache",
        "--route-nopull",
    ]
    ver = get_openvpn_version()
    if ver >= 2.5:
        cmd += ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"]
    else:
        cmd += ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"]
    cmd += ["--verb", "3"]
    return cmd

def run_openvpn(config_file: str, tun_dev: str, keep_alive: bool,
                timeout: int = OPENVPN_TIMEOUT) -> tuple[bool, str, subprocess.Popen | None]:
    try:
        proc = subprocess.Popen(
            build_openvpn_cmd(config_file, tun_dev),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "openvpn 命令未找到", None
    except OSError as e:
        return False, f"openvpn 启动失败: {e}", None

    lines: queue.Queue[str | None] = queue.Queue()
    done  = [False]

    def reader():
        assert proc.stdout
        for line in proc.stdout:
            if not done[0]:
                lines.put(line.rstrip())
        if not done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()

    started = time.time()
    tail: list[str] = []
    ok  = False
    msg = "OpenVPN 初始化超时"

    while time.time() - started < timeout:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if proc.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail = (tail + [line])[-8:]
            if keep_alive:
                print(f"[OpenVPN/{tun_dev}] {line}", flush=True)
            lower = line.lower()
            if "initialization sequence completed" in lower:
                ok  = True
                msg = f"连接成功，耗时 {int((time.time()-started)*1000)} ms"
                break
            if "auth_failed" in lower or "authentication failed" in lower:
                msg = "AUTH_FAILED"
                break
            if "fatal error" in lower:
                msg = line[-200:]
                break
    else:
        msg = f"连接超时 ({timeout}s)"

    done[0] = True
    if not ok or not keep_alive:
        _stop_proc(proc)
        proc = None
    return ok, msg, proc

def _stop_proc(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()

def setup_policy_routing(tun_dev: str, table_id: int) -> None:
    subprocess.run(["ip", "rule", "del", "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)
    for _ in range(3):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", tun_dev,
                            "table", str(table_id)], check=True, timeout=3)
            subprocess.run(["ip", "rule", "add", "oif", tun_dev,
                            "table", str(table_id)], check=True, timeout=3)
            log("INFO", "Routing", f"策略路由: {tun_dev} → 表{table_id}")
            return
        except Exception as e:
            log("WARNING", "Routing", f"策略路由失败: {e}")
            time.sleep(1)

def cleanup_policy_routing(table_id: int) -> None:
    subprocess.run(["ip", "rule", "del", "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)

def kill_slot_openvpn(tun_dev: str) -> None:
    subprocess.run(["pkill", "-f", f"openvpn.*{tun_dev}"], capture_output=True)

# ── 节点测试（同步，直接返回结果） ──────────────────────────────────
_test_tuns: set[int] = set()
_test_tuns_lock = threading.Lock()

def _alloc_test_tun() -> int:
    with _test_tuns_lock:
        for i in range(2, 10):
            if i not in _test_tuns:
                _test_tuns.add(i)
                return i
        return 9

def _free_test_tun(idx: int) -> None:
    with _test_tuns_lock:
        _test_tuns.discard(idx)

def test_node_sync(node: dict[str, Any]) -> dict[str, Any]:
    """
    同步测试单个节点，直接返回完整更新字段。
    调用方可拿到结果后立刻回包给前端。
    """
    config_path = Path(node["config_file"])
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    config_path.write_text(node.get("config_text", ""), encoding="utf-8")

    latency = vpn_utils.ping_latency_ms(
        node.get("remote_host") or node.get("ip"),
        parse_int(node.get("remote_port")),
        parse_int(node.get("ping")),
    )

    tun_idx = _alloc_test_tun()
    try:
        ok, msg, _ = run_openvpn(str(config_path), f"tun{tun_idx}",
                                  keep_alive=False, timeout=12)
    finally:
        _free_test_tun(tun_idx)

    try:
        config_path.unlink(missing_ok=True)
    except Exception:
        pass

    updates: dict[str, Any] = {
        "latency_ms":     latency,
        "probe_status":   "available" if ok else "unavailable",
        "probe_message":  msg,
        "probed_at":      time.time(),
    }
    if ok:
        tmp = {
            "ip": node.get("ip"), "remote_host": node.get("remote_host"),
            "owner": "", "asn": "", "as_name": "",
            "location": "", "country_zh": "", "ip_type": "unknown",
            "quality": "未知", "lat": 0, "lon": 0,
        }
        vpn_utils.enrich_ip_info([tmp])
        for k in ("owner","asn","as_name","location","country_zh","ip_type","quality","lat","lon"):
            updates[k] = tmp[k]
    return updates

def batch_test_nodes(node_ids: list[str]) -> None:
    with lock:
        nodes = read_json(NODES_FILE, [])
        to_test = [n for n in nodes if n["id"] in node_ids]

    def worker(node: dict[str, Any]) -> tuple[str, dict]:
        return node["id"], test_node_sync(node)

    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TESTS) as ex:
        futs = {ex.submit(worker, n): n["id"] for n in to_test}
        for fut in concurrent.futures.as_completed(futs):
            try:
                nid, updates = fut.result()
                results[nid] = updates
            except Exception as e:
                results[futs[fut]] = {"probe_status": "unavailable", "probe_message": str(e)}

    with lock:
        nodes = read_json(NODES_FILE, [])
        for n in nodes:
            if n["id"] in results:
                n.update(results[n["id"]])
        write_json(NODES_FILE, sort_nodes(nodes))

# ── Slot 连接/断开 ───────────────────────────────────────────────────
def stop_slot(slot_id: int) -> None:
    slot_cfg = SLOTS[slot_id]
    st = slot_states[slot_id]
    cleanup_policy_routing(slot_cfg["table"])
    _stop_proc(st.process)
    kill_slot_openvpn(slot_cfg["tun"])
    st.process   = None
    st.node_id   = ""
    st.node_type = ""
    st.proxy_ok  = False
    st.proxy_ip  = ""
    st.latency_ms = 0
    st.status_msg = "已断开"
    srv = proxy_mod._proxy_slots.get(slot_id)
    if srv:
        srv.set_upstream_socks5(None)
    with lock:
        nodes = read_json(NODES_FILE, [])
        for n in nodes:
            if n.get("active_slot") == slot_id:
                n["active_slot"] = -1
        write_json(NODES_FILE, nodes)
        cnodes = read_json(CUSTOM_NODES_FILE, [])
        for n in cnodes:
            if n.get("active_slot") == slot_id:
                n["active_slot"] = -1
        write_json(CUSTOM_NODES_FILE, cnodes)

def connect_slot(slot_id: int, node_id: str) -> str:
    slot_cfg = SLOTS[slot_id]
    st = slot_states[slot_id]
    if st.is_connecting:
        return "正在连接中，请稍候"
    st.is_connecting = True
    st.status_msg = "初始化..."
    try:
        with lock:
            nodes = read_json(NODES_FILE, [])
            node = next((n for n in nodes if n["id"] == node_id), None)
        if not node:
            raise ValueError(f"节点不存在: {node_id}")
        stop_slot(slot_id)
        config_path = Path(node["config_file"])
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        config_path.write_text(node.get("config_text", ""), encoding="utf-8")
        st.status_msg = "启动 OpenVPN..."
        ok, msg, proc = run_openvpn(str(config_path), slot_cfg["tun"], keep_alive=True)
        if not ok or proc is None:
            try:
                config_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise RuntimeError(f"OpenVPN 连接失败: {msg}")
        st.process   = proc
        st.node_id   = node_id
        st.node_type = "vpngate"
        st.status_msg = "配置路由..."
        setup_policy_routing(slot_cfg["tun"], slot_cfg["table"])
        try:
            lat = vpn_utils.ping_latency_ms(
                node.get("ip") or node.get("remote_host"),
                parse_int(node.get("remote_port")),
                parse_int(node.get("ping")),
            )
            st.latency_ms = lat
        except Exception:
            pass
        with lock:
            nodes = read_json(NODES_FILE, [])
            for n in nodes:
                if n["id"] == node_id:
                    n["active_slot"] = slot_id
                elif n.get("active_slot") == slot_id:
                    n["active_slot"] = -1
            write_json(NODES_FILE, nodes)
        st.status_msg = "检测出口..."
        res = check_slot_proxy(slot_id)
        st.proxy_ok = res["ok"]
        st.proxy_ip = res.get("ip", "")
        st.status_msg = f"已连接 | {st.proxy_ip}" if st.proxy_ok else "已连接 | 出口检测失败"
        log("INFO", f"Slot{slot_id}", f"节点 {node_id} 连接成功，出口: {st.proxy_ip}")
        return f"连接成功: {node_id}"
    except Exception as e:
        st.status_msg = f"连接失败: {e}"
        log("ERROR", f"Slot{slot_id}", str(e))
        stop_slot(slot_id)
        raise
    finally:
        st.is_connecting = False

def connect_custom_socks5(slot_id: int, node: dict) -> str:
    st = slot_states[slot_id]
    if st.is_connecting:
        return "正在连接中，请稍候"
    st.is_connecting = True
    st.status_msg = "连接自建节点..."
    try:
        stop_slot(slot_id)
        host     = node["host"]
        port     = int(node["port"])
        username = node.get("username", "")
        password = node.get("password", "")
        st.status_msg = "测试连通性..."
        lat = vpn_utils.ping_latency_ms(host, port)
        if lat == 0:
            raise RuntimeError(f"无法连接到 {host}:{port}")
        st.latency_ms = lat
        srv = proxy_mod._proxy_slots.get(slot_id)
        if srv:
            srv.set_upstream_socks5({
                "host": host, "port": port,
                "username": username, "password": password,
            })
        st.node_id   = node["id"]
        st.node_type = "custom"
        st.status_msg = "检测出口..."
        res = check_slot_proxy(slot_id)
        st.proxy_ok = res["ok"]
        st.proxy_ip = res.get("ip", "")
        st.status_msg = f"已连接 | {st.proxy_ip}" if st.proxy_ok else "已连接 | 出口检测失败"
        cnodes = read_json(CUSTOM_NODES_FILE, [])
        for n in cnodes:
            if n["id"] == node["id"]:
                n["active_slot"] = slot_id
            elif n.get("active_slot") == slot_id:
                n["active_slot"] = -1
        write_json(CUSTOM_NODES_FILE, cnodes)
        log("INFO", f"Slot{slot_id}", f"自建节点 {node['name']} 连接成功，出口: {st.proxy_ip}")
        return f"连接成功: {node['name']}"
    except Exception as e:
        st.status_msg = f"连接失败: {e}"
        log("ERROR", f"Slot{slot_id}", str(e))
        stop_slot(slot_id)
        raise
    finally:
        st.is_connecting = False

def check_slot_proxy(slot_id: int) -> dict[str, Any]:
    proxy_port = SLOTS[slot_id]["proxy_port"]
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({
                "http":  f"http://127.0.0.1:{proxy_port}",
                "https": f"http://127.0.0.1:{proxy_port}",
            })
        )
        t0 = time.time()
        with opener.open("http://ip-api.com/json/?fields=query,country,org", timeout=12) as resp:
            data = json.loads(resp.read())
        return {"ok": True, "ip": data.get("query", ""),
                "latency_ms": int((time.time()-t0)*1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ── 自动切换（每槽独立规则） ─────────────────────────────────────────
def _get_switch_candidates(slot_id: int, slot_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """
    按 slot_cfg["node_sources"] 的优先级顺序，
    返回第一个有候选节点的来源的候选列表。
    """
    other_node = slot_states[1 - slot_id].node_id
    sources = slot_cfg.get("node_sources", ["vpngate_any"])
    countries = slot_cfg.get("countries", [])
    max_lat = slot_cfg.get("max_latency_ms", 0)

    vpngate_nodes = read_json(NODES_FILE, [])
    custom_nodes  = read_json(CUSTOM_NODES_FILE, [])

    for src in sources:
        if src == "custom":
            cands = [
                n for n in custom_nodes
                if n["id"] != other_node
            ]
            if cands:
                return cands

        elif src in ("vpngate_residential", "vpngate_datacenter", "vpngate_any"):
            cands = [
                n for n in vpngate_nodes
                if n.get("probe_status") == "available"
                and n["id"] != other_node
            ]
            if src == "vpngate_residential":
                cands = [n for n in cands if n.get("ip_type") == "residential"]
            elif src == "vpngate_datacenter":
                cands = [n for n in cands if n.get("ip_type") == "datacenter"]
            if countries:
                cands = [n for n in cands if n.get("country_short", "") in countries]
            if max_lat > 0:
                cands = [n for n in cands if parse_int(n.get("latency_ms", 0)) <= max_lat]
            cands.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999,
                                      -parse_int(n.get("score"))))
            if cands:
                return cands

    # 所有来源都没有，降级到任意可用 vpngate
    fallback = [
        n for n in vpngate_nodes
        if n.get("probe_status") == "available" and n["id"] != other_node
    ]
    return fallback

def auto_switch_slot(slot_id: int) -> None:
    slot_cfgs = load_slot_configs()
    slot_cfg  = slot_cfgs.get(str(slot_id), dict(DEFAULT_SLOT_CFG))
    if not slot_cfg.get("auto_switch", True):
        log("INFO", f"Slot{slot_id}", "自动切换已关闭")
        return

    cands = _get_switch_candidates(slot_id, slot_cfg)
    if not cands:
        log("ERROR", f"Slot{slot_id}", "没有任何可用节点，停止 slot")
        stop_slot(slot_id)
        return

    target = cands[0]
    log("INFO", f"Slot{slot_id}", f"自动切换 → {target.get('name') or target['id']}")
    try:
        if target.get("node_type") == "custom" or "host" in target:
            connect_custom_socks5(slot_id, target)
        else:
            connect_slot(slot_id, target["id"])
    except Exception as e:
        log("ERROR", f"Slot{slot_id}", f"自动切换失败: {e}")

# ── 健康监控 ─────────────────────────────────────────────────────────
def health_monitor() -> None:
    while True:
        time.sleep(30)
        for slot_id in range(2):
            st = slot_states[slot_id]
            if not st.node_id or st.is_connecting:
                continue
            if st.node_type == "vpngate":
                if st.process is None or st.process.poll() is not None:
                    log("WARNING", f"Slot{slot_id}", "OpenVPN 进程退出，触发自动切换")
                    threading.Thread(target=auto_switch_slot, args=(slot_id,), daemon=True).start()

def refresh_nodes_loop() -> None:
    while True:
        time.sleep(960)
        try:
            candidates = fetch_candidates()
            with lock:
                existing = {n["id"]: n for n in read_json(NODES_FILE, [])}
            merged, seen = [], set()
            for c in candidates:
                if c["id"] in existing:
                    ex = existing[c["id"]]
                    ex["config_text"] = c["config_text"]
                    ex["fetched_at"]  = c["fetched_at"]
                    merged.append(ex)
                else:
                    merged.append(c)
                seen.add(c["id"])
            for nid, n in existing.items():
                if nid not in seen:
                    merged.append(n)
            write_json(NODES_FILE, sort_nodes(merged[:1000]))
            log("INFO", "Refresh", f"节点刷新完成，共 {len(merged)} 个")
        except Exception as e:
            log("ERROR", "Refresh", str(e))

# ── Web UI HTML ──────────────────────────────────────────────────────
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPNGate Pro</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
.nav{background:#1a1d27;border-bottom:1px solid #2d3748;padding:12px 24px;display:flex;align-items:center;gap:16px}
.nav h1{font-size:18px;font-weight:700;color:#63b3ed}
.badge{background:#2d3748;border-radius:6px;padding:3px 10px;font-size:12px;color:#a0aec0}
.tabs{display:flex;gap:2px;padding:0 24px;background:#1a1d27;border-bottom:1px solid #2d3748;overflow-x:auto}
.tab{padding:10px 16px;cursor:pointer;font-size:13px;color:#718096;border-bottom:2px solid transparent;transition:.2s;white-space:nowrap}
.tab.active{color:#63b3ed;border-bottom-color:#63b3ed}
.content{padding:20px;max-width:1100px;margin:0 auto}
.card{background:#1a1d27;border:1px solid #2d3748;border-radius:10px;padding:18px;margin-bottom:14px}
.card h2{font-size:14px;font-weight:600;color:#a0aec0;margin-bottom:14px}
.slot-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.slot-card{background:#141720;border:1px solid #2d3748;border-radius:8px;padding:14px}
.slot-card h3{font-size:13px;font-weight:600;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0}
.dot.green{background:#48bb78}.dot.yellow{background:#ecc94b}.dot.red{background:#fc8181}.dot.grey{background:#4a5568}
.stat{display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid #2d3748;font-size:12px}
.stat:last-child{border:none}
.stat .label{color:#718096}.stat .val{color:#e2e8f0;font-family:monospace;text-align:right;max-width:200px;overflow:hidden;text-overflow:ellipsis}
.btn{padding:6px 12px;border:none;border-radius:6px;cursor:pointer;font-size:12px;transition:.2s}
.btn-primary{background:#3182ce;color:#fff}.btn-primary:hover{background:#2b6cb0}
.btn-danger{background:#c53030;color:#fff}.btn-danger:hover{background:#9b2c2c}
.btn-success{background:#276749;color:#fff}.btn-success:hover{background:#22543d}
.btn-grey{background:#2d3748;color:#a0aec0}.btn-grey:hover{background:#4a5568}
.btn-sm{padding:3px 8px;font-size:11px}
.input{background:#141720;border:1px solid #2d3748;border-radius:6px;padding:6px 10px;color:#e2e8f0;font-size:13px;width:100%}
.input:focus{outline:none;border-color:#63b3ed}
.select{background:#141720;border:1px solid #2d3748;border-radius:6px;padding:6px 10px;color:#e2e8f0;font-size:13px}
.tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;margin:1px}
.tag.residential{background:#276749;color:#9ae6b4}
.tag.datacenter{background:#2c5282;color:#90cdf4}
.tag.unknown{background:#2d3748;color:#718096}
.tag.available{background:#276749;color:#9ae6b4}
.tag.unavail{background:#742a2a;color:#feb2b2}
.tag.notcheck{background:#2d3748;color:#a0aec0}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:7px 10px;color:#718096;font-weight:500;border-bottom:1px solid #2d3748;white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid #1a1d27;vertical-align:middle}
tr:hover td{background:#141720}
.filter-row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px}
.filter-group{display:flex;flex-direction:column;gap:4px}
.filter-group label{font-size:11px;color:#718096}
.proto-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid #2d3748}
.proto-row:last-child{border:none}
.proto-name{width:150px;font-size:13px}
.proto-port{width:65px;font-family:monospace;font-size:11px;color:#718096}
.pill{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:500}
.pill.on{background:#276749;color:#9ae6b4}.pill.off{background:#2d3748;color:#718096}
.login-box{max-width:360px;margin:80px auto;background:#1a1d27;border:1px solid #2d3748;border-radius:12px;padding:28px}
.login-box h2{text-align:center;margin-bottom:20px;color:#63b3ed}
.form-group{margin-bottom:12px}
.form-group label{display:block;font-size:12px;color:#718096;margin-bottom:5px}
.alert{padding:8px 12px;border-radius:6px;font-size:12px;margin-top:10px}
.alert.error{background:#742a2a33;border:1px solid #c53030;color:#feb2b2}
.toast{position:fixed;top:16px;right:16px;background:#276749;color:#9ae6b4;padding:9px 16px;border-radius:8px;font-size:12px;z-index:9999;display:none;max-width:320px}
.flex{display:flex}.gap-2{gap:8px}.items-center{align-items:center}.justify-between{justify-content:space-between}
.mt-2{margin-top:8px}.mt-3{margin-top:12px}.mt-4{margin-top:16px}
.text-sm{font-size:12px}.text-xs{font-size:11px}.text-grey{color:#718096}
.page{display:none}.page.active{display:block}
.country-btn{padding:4px 9px;border-radius:4px;font-size:11px;cursor:pointer;border:1px solid #2d3748;background:#141720;color:#a0aec0;transition:.2s;margin:3px}
.country-btn.selected{background:#2b4c7e;border-color:#63b3ed;color:#90cdf4}
.ip-type-btn{padding:5px 14px;border-radius:6px;font-size:12px;cursor:pointer;border:1px solid #2d3748;background:#141720;color:#a0aec0;transition:.2s}
.ip-type-btn.selected{background:#276749;border-color:#48bb78;color:#9ae6b4}
.source-item{display:flex;align-items:center;gap:8px;padding:6px 8px;background:#141720;border:1px solid #2d3748;border-radius:6px;margin-bottom:6px;cursor:move}
.source-item .handle{color:#4a5568;font-size:14px}
.divider{border:none;border-top:1px solid #2d3748;margin:14px 0}
@media(max-width:640px){.slot-grid{grid-template-columns:1fr}}
</style>
</head>
<body>

<div id="loginPage" style="display:none">
  <div class="login-box">
    <h2>🔐 VPNGate Pro</h2>
    <div class="form-group">
      <label>用户名</label>
      <input class="input" id="loginUser" type="text" placeholder="用户名" onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <div class="form-group">
      <label>密码</label>
      <input class="input" id="loginPass" type="password" placeholder="密码" onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <button class="btn btn-primary" style="width:100%;padding:8px" onclick="doLogin()">登录</button>
    <div id="loginErr" class="alert error" style="display:none"></div>
  </div>
</div>

<div id="mainApp" style="display:none">
  <div class="toast" id="toast"></div>
  <div class="nav">
    <h1>🌐 VPNGate Pro</h1>
    <span class="badge" id="navBadge">加载中...</span>
    <div style="margin-left:auto;display:flex;gap:6px">
      <button class="btn btn-sm btn-grey" onclick="refreshAll()">🔄 刷新</button>
      <button class="btn btn-sm btn-grey" onclick="switchTab('settings')">⚙️</button>
      <button class="btn btn-sm btn-danger" onclick="doLogout()">退出</button>
    </div>
  </div>
  <div class="tabs">
    <div class="tab active" onclick="switchTab('dashboard')">📊 控制台</div>
    <div class="tab" onclick="switchTab('nodes')">🗂 节点列表</div>
    <div class="tab" onclick="switchTab('custom')">🔧 自建节点</div>
    <div class="tab" onclick="switchTab('autoswitch')">🔁 自动切换</div>
    <div class="tab" onclick="switchTab('filter')">🎯 过滤设置</div>
    <div class="tab" onclick="switchTab('routing')">🔀 协议路由</div>
    <div class="tab" onclick="switchTab('logs')">📋 日志</div>
    <div class="tab" onclick="switchTab('settings')">⚙️ 设置</div>
  </div>

  <!-- 控制台 -->
  <div class="content page active" id="page-dashboard">
    <div class="slot-grid">
      <div class="slot-card">
        <h3><span class="dot grey" id="s0-dot"></span>节点槽 1 · tun10 · :7920</h3>
        <div class="stat"><span class="label">状态</span><span class="val" id="s0-status">-</span></div>
        <div class="stat"><span class="label">节点</span><span class="val" id="s0-node">-</span></div>
        <div class="stat"><span class="label">出口 IP</span><span class="val" id="s0-ip">-</span></div>
        <div class="stat"><span class="label">延迟</span><span class="val" id="s0-lat">-</span></div>
        <div class="stat"><span class="label">代理地址</span><span class="val">127.0.0.1:7920</span></div>
        <div class="mt-3 flex gap-2">
          <button class="btn btn-sm btn-danger" onclick="stopSlot(0)">断开</button>
          <button class="btn btn-sm btn-grey" onclick="checkSlot(0)">检测出口</button>
          <button class="btn btn-sm btn-grey" onclick="switchSlot(0)">切换节点</button>
        </div>
      </div>
      <div class="slot-card">
        <h3><span class="dot grey" id="s1-dot"></span>节点槽 2 · tun11 · :7921</h3>
        <div class="stat"><span class="label">状态</span><span class="val" id="s1-status">-</span></div>
        <div class="stat"><span class="label">节点</span><span class="val" id="s1-node">-</span></div>
        <div class="stat"><span class="label">出口 IP</span><span class="val" id="s1-ip">-</span></div>
        <div class="stat"><span class="label">延迟</span><span class="val" id="s1-lat">-</span></div>
        <div class="stat"><span class="label">代理地址</span><span class="val">127.0.0.1:7921</span></div>
        <div class="mt-3 flex gap-2">
          <button class="btn btn-sm btn-danger" onclick="stopSlot(1)">断开</button>
          <button class="btn btn-sm btn-grey" onclick="checkSlot(1)">检测出口</button>
          <button class="btn btn-sm btn-grey" onclick="switchSlot(1)">切换节点</button>
        </div>
      </div>
    </div>
    <div class="card mt-3">
      <h2>⚡ 快速连接</h2>
      <div class="flex gap-2 items-center">
        <select class="select" id="quickNode" style="flex:1"></select>
        <select class="select" id="quickSlot">
          <option value="0">槽 1</option>
          <option value="1">槽 2</option>
        </select>
        <button class="btn btn-primary" onclick="quickConnect()">连接</button>
      </div>
    </div>
    <div class="card">
      <h2>📡 协议路由状态</h2>
      <div id="routingStatus"></div>
    </div>
  </div>

  <!-- 节点列表 -->
  <div class="content page" id="page-nodes">
    <div class="card">
      <div class="flex justify-between items-center">
        <h2>🗂 节点列表</h2>
        <div class="flex gap-2">
          <button class="btn btn-sm btn-grey" onclick="fetchNodes()">拉取节点</button>
          <button class="btn btn-sm btn-primary" onclick="testTopNodes()">测试前10个</button>
        </div>
      </div>
      <div class="filter-row mt-2">
        <div class="filter-group">
          <label>状态</label>
          <select class="select" id="flStatus" onchange="renderNodes()">
            <option value="">全部</option>
            <option value="available">可用</option>
            <option value="not_checked">未测试</option>
            <option value="unavailable">不可用</option>
          </select>
        </div>
        <div class="filter-group">
          <label>国家</label>
          <select class="select" id="flCountry" onchange="renderNodes()">
            <option value="">全部</option>
          </select>
        </div>
        <div class="filter-group">
          <label>IP类型</label>
          <select class="select" id="flIpType" onchange="renderNodes()">
            <option value="">全部</option>
            <option value="residential">住宅</option>
            <option value="datacenter">机房</option>
          </select>
        </div>
      </div>
      <div style="overflow-x:auto">
        <table>
          <thead><tr>
            <th>国家/地区</th><th>IP</th><th>延迟</th><th>IP类型</th>
            <th>状态</th><th>归属/位置</th><th>操作</th>
          </tr></thead>
          <tbody id="nodeTable"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- 自建节点 -->
  <div class="content page" id="page-custom">
    <div class="card">
      <h2>➕ 添加自建 SOCKS5 节点</h2>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">
        <div class="filter-group"><label>备注名称 *</label><input class="input" id="cn-name" placeholder="例如：JP住宅节点"></div>
        <div class="filter-group"><label>服务器地址 *</label><input class="input" id="cn-host" placeholder="IP 或域名"></div>
        <div class="filter-group"><label>端口 *</label><input class="input" id="cn-port" type="number" placeholder="1080"></div>
        <div class="filter-group"><label>用户名（可选）</label><input class="input" id="cn-user" placeholder="无认证留空"></div>
        <div class="filter-group"><label>密码（可选）</label><input class="input" id="cn-pass" type="password" placeholder="无认证留空"></div>
        <div class="filter-group"><label>备注（可选）</label><input class="input" id="cn-note" placeholder="例如：住宅IP 美国"></div>
      </div>
      <button class="btn btn-primary" onclick="addCustomNode()">➕ 添加</button>
    </div>
    <div class="card">
      <h2>📋 自建节点列表</h2>
      <table>
        <thead><tr><th>名称</th><th>地址</th><th>端口</th><th>认证</th><th>延迟</th><th>当前槽</th><th>备注</th><th>操作</th></tr></thead>
        <tbody id="customTable"></tbody>
      </table>
    </div>
  </div>

  <!-- 自动切换 -->
  <div class="content page" id="page-autoswitch">
    <div id="slotSwitchCards"></div>
    <button class="btn btn-primary mt-3" onclick="saveSlotConfigs()">💾 保存自动切换配置</button>
  </div>

  <!-- 过滤设置 -->
  <div class="content page" id="page-filter">
    <div class="card">
      <h2>🌍 国家过滤（节点列表显示用）</h2>
      <p class="text-xs text-grey" style="margin-bottom:10px">不选 = 不限国家</p>
      <div id="countriesWrap" style="display:flex;flex-wrap:wrap"></div>
    </div>
    <div class="card">
      <h2>🏠 IP 类型过滤</h2>
      <div class="flex gap-2">
        <div class="ip-type-btn" id="ipt-residential" onclick="toggleIpType('residential')">🏘 住宅 IP</div>
        <div class="ip-type-btn" id="ipt-datacenter" onclick="toggleIpType('datacenter')">🏢 机房 IP</div>
      </div>
    </div>
    <div class="card">
      <h2>⏱ 延迟上限</h2>
      <div class="flex gap-2 items-center">
        <input class="input" type="number" id="maxLat" placeholder="0 = 不限" style="max-width:160px">
        <span class="text-sm text-grey">ms（0 = 不限）</span>
      </div>
    </div>
    <button class="btn btn-primary" onclick="saveFilter()">💾 保存</button>
  </div>

  <!-- 协议路由 -->
  <div class="content page" id="page-routing">
    <div class="card">
      <h2>🔀 协议路由配置</h2>
      <p class="text-xs text-grey" style="margin-bottom:14px">启用后对应端口的出站流量将通过指定节点槽。</p>
      <div id="routingConfig"></div>
      <button class="btn btn-primary mt-3" onclick="saveRouting()">💾 保存并应用</button>
    </div>
  </div>

  <!-- 日志 -->
  <div class="content page" id="page-logs">
    <div class="card">
      <h2>📋 运行日志</h2>
      <div id="logContent" style="font-family:monospace;font-size:11px;color:#a0aec0;max-height:500px;overflow-y:auto;background:#0f1117;padding:10px;border-radius:6px"></div>
    </div>
  </div>

  <!-- 设置 -->
  <div class="content page" id="page-settings">
    <div class="card">
      <h2>🔐 修改登录信息</h2>
      <div style="max-width:360px">
        <div class="form-group mt-2">
          <label class="text-xs text-grey">新用户名</label>
          <input class="input mt-2" id="newUser" placeholder="留空不修改">
        </div>
        <div class="form-group mt-2">
          <label class="text-xs text-grey">新密码</label>
          <input class="input mt-2" id="newPass" type="password" placeholder="留空不修改">
        </div>
        <div class="form-group mt-2">
          <label class="text-xs text-grey">确认密码</label>
          <input class="input mt-2" id="newPass2" type="password" placeholder="再次输入新密码">
        </div>
        <button class="btn btn-primary mt-3" onclick="saveCredentials()">💾 保存</button>
      </div>
    </div>
    <div class="card">
      <h2>ℹ️ 当前信息</h2>
      <div class="stat"><span class="label">Web UI 端口</span><span class="val" id="infoPort">-</span></div>
      <div class="stat"><span class="label">Slot 1 代理</span><span class="val">127.0.0.1:7920</span></div>
      <div class="stat"><span class="label">Slot 2 代理</span><span class="val">127.0.0.1:7921</span></div>
    </div>
  </div>
</div>

<script>
let SESSION = localStorage.getItem('vpn_session') || '';
let allNodes = [], filterData = {countries:[], ip_types:[], max_latency_ms:0};
let selectedCountries = new Set(), selectedIpTypes = new Set();
let slotConfigs = {};

const PROTO_PORTS = {'VLESS-Reality':25476,'Shadowsocks':62026,'VMess-WS':6123,'Hysteria2':53145,'SOCKS5':42447};
const SOURCE_LABELS = {
  'vpngate_residential':'🏘 VPNGate 住宅IP',
  'vpngate_datacenter':'🏢 VPNGate 机房IP',
  'vpngate_any':'🌐 VPNGate 任意',
  'custom':'🔧 自建节点',
};

async function api(path, opts={}) {
  const res = await fetch(path, {
    ...opts,
    headers: {'X-Session': SESSION, 'Content-Type':'application/json', ...(opts.headers||{})},
  });
  if (res.status === 401) { showLogin(); return null; }
  return res.json().catch(()=>null);
}

function showToast(msg, isErr=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.background = isErr ? '#742a2a' : '#276749';
  t.style.color = isErr ? '#feb2b2' : '#9ae6b4';
  t.style.display = 'block';
  clearTimeout(t._tid);
  t._tid = setTimeout(()=>t.style.display='none', 3500);
}

function showLogin() {
  document.getElementById('loginPage').style.display='block';
  document.getElementById('mainApp').style.display='none';
}
function showApp() {
  document.getElementById('loginPage').style.display='none';
  document.getElementById('mainApp').style.display='block';
}

async function doLogin() {
  const u = document.getElementById('loginUser').value;
  const p = document.getElementById('loginPass').value;
  const r = await fetch('/api/login', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({username:u, password:p}),
  });
  const d = await r.json();
  if (d.token) {
    SESSION = d.token;
    localStorage.setItem('vpn_session', SESSION);
    showApp(); refreshAll();
  } else {
    const el = document.getElementById('loginErr');
    el.textContent = d.error || '登录失败';
    el.style.display = 'block';
  }
}
function doLogout() {
  SESSION = ''; localStorage.removeItem('vpn_session'); showLogin();
}

function switchTab(name) {
  const pages = ['dashboard','nodes','custom','autoswitch','filter','routing','logs','settings'];
  document.querySelectorAll('.tab').forEach((t,i)=>{
    t.classList.toggle('active', pages[i]===name);
  });
  document.querySelectorAll('.page').forEach(p=>{
    p.classList.toggle('active', p.id==='page-'+name);
  });
  if(name==='nodes') loadNodes();
  if(name==='custom') loadCustomNodes();
  if(name==='autoswitch') loadAutoSwitch();
  if(name==='filter') loadFilter();
  if(name==='routing') loadRouting();
  if(name==='logs') loadLogs();
  if(name==='settings') loadSettings();
}

async function refreshAll() {
  const d = await api('/api/status');
  if (!d) return;
  document.getElementById('navBadge').textContent =
    `S1:${d.slots[0].node_id?'已连接':'未连接'} | S2:${d.slots[1].node_id?'已连接':'未连接'}`;
  for (let i=0; i<2; i++) {
    const s = d.slots[i];
    document.getElementById(`s${i}-dot`).className = 'dot '+(s.proxy_ok?'green':s.node_id?'yellow':'grey');
    document.getElementById(`s${i}-status`).textContent = s.status_msg||'-';
    document.getElementById(`s${i}-node`).textContent = s.node_id||'-';
    document.getElementById(`s${i}-ip`).textContent = s.proxy_ip||'-';
    document.getElementById(`s${i}-lat`).textContent = s.latency_ms?s.latency_ms+'ms':'-';
  }
  // 路由状态
  const rb = document.getElementById('routingStatus');
  rb.innerHTML = '';
  for (const [proto, port] of Object.entries(PROTO_PORTS)) {
    const rc = d.routing[proto]||{};
    const div = document.createElement('div');
    div.className = 'proto-row';
    div.innerHTML = `<span class="proto-name">${proto}</span>
      <span class="proto-port">:${port}</span>
      <span class="pill ${rc.enabled?'on':'off'}">${rc.enabled?'→ 槽'+(rc.slot+1):'直连'}</span>`;
    rb.appendChild(div);
  }
  // 快速连接下拉
  const sel = document.getElementById('quickNode');
  const cur = sel.value;
  sel.innerHTML = '<option value="">-- 选择节点 --</option>';
  const vpnNodes = (d.nodes||[]).filter(n=>n.probe_status==='available');
  if (vpnNodes.length) {
    const g = document.createElement('optgroup');
    g.label = '── VPNGate 节点 ──';
    vpnNodes.forEach(n=>{
      const o = document.createElement('option');
      o.value = 'vpngate:'+n.id;
      const loc = n.location ? ` · ${n.location}` : '';
      o.textContent = `${n.country||''}${loc} ${n.ip} ${n.latency_ms?n.latency_ms+'ms':''} ${n.quality||''}`;
      g.appendChild(o);
    });
    sel.appendChild(g);
  }
  const cd = await api('/api/custom_nodes');
  if (cd && cd.nodes && cd.nodes.length) {
    const g = document.createElement('optgroup');
    g.label = '── 自建节点 ──';
    cd.nodes.forEach(n=>{
      const o = document.createElement('option');
      o.value = 'custom:'+n.id;
      o.textContent = `🔧 ${n.name} (${n.host}:${n.port})${n.note?' · '+n.note:''}`;
      g.appendChild(o);
    });
    sel.appendChild(g);
  }
  if (cur) sel.value = cur;
}

// ── 节点列表 ──
async function loadNodes() {
  const d = await api('/api/nodes');
  if (!d) return;
  allNodes = d.nodes||[];
  const cs = document.getElementById('flCountry');
  const cur = cs.value;
  cs.innerHTML = '<option value="">全部</option>';
  const countries = [...new Set(allNodes.map(n=>n.country).filter(Boolean))].sort();
  countries.forEach(c=>{ const o=document.createElement('option'); o.value=c; o.textContent=c; cs.appendChild(o); });
  cs.value = cur;
  renderNodes();
}

function renderNodes() {
  const sf = document.getElementById('flStatus').value;
  const cf = document.getElementById('flCountry').value;
  const tf = document.getElementById('flIpType').value;
  let nodes = allNodes;
  if (sf) nodes = nodes.filter(n=>n.probe_status===sf);
  if (cf) nodes = nodes.filter(n=>n.country===cf);
  if (tf) nodes = nodes.filter(n=>n.ip_type===tf);
  const tbody = document.getElementById('nodeTable');
  tbody.innerHTML = '';
  nodes.slice(0,200).forEach(n=>{
    const st = n.probe_status;
    const stTag = st==='available'?'available':st==='unavailable'?'unavail':'notcheck';
    const stLabel = st==='available'?'可用':st==='unavailable'?'不可用':'未测试';
    // 地理位置：优先显示 location（城市+省份），然后是国家
    const geo = [n.country, n.location].filter(Boolean).join(' · ');
    // IP类型标签
    const ipTypeLabel = n.ip_type==='residential'?'住宅':n.ip_type==='datacenter'?'机房':'未知';
    const ipTypeClass = n.ip_type==='residential'?'residential':n.ip_type==='datacenter'?'datacenter':'unknown';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${geo||'-'} <span style="font-size:10px;color:#4a5568">${n.country_short||''}</span></td>
      <td style="font-family:monospace">${n.ip||'-'}</td>
      <td>${n.latency_ms?n.latency_ms+'ms':'-'}</td>
      <td><span class="tag ${ipTypeClass}">${ipTypeLabel}</span></td>
      <td><span class="tag ${stTag}">${stLabel}</span></td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:#718096">${n.as_name||n.owner||'-'}</td>
      <td>
        <button class="btn btn-sm btn-primary" onclick="connectNode('${n.id}',0)">→槽1</button>
        <button class="btn btn-sm btn-grey" onclick="connectNode('${n.id}',1)">→槽2</button>
        <button class="btn btn-sm btn-success" onclick="testOneNode('${n.id}',this)">测试</button>
      </td>`;
    tbody.appendChild(tr);
  });
  if (!nodes.length) tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:20px;color:#718096">无节点数据</td></tr>';
}

// ── 自建节点 ──
async function loadCustomNodes() {
  const d = await api('/api/custom_nodes');
  if (!d) return;
  const tbody = document.getElementById('customTable');
  tbody.innerHTML = '';
  const nodes = d.nodes||[];
  if (!nodes.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:20px;color:#718096">暂无自建节点</td></tr>';
    return;
  }
  nodes.forEach(n=>{
    const slotLabel = n.active_slot>=0?`<span class="pill on">槽${n.active_slot+1}</span>`:'<span class="pill off">-</span>';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-weight:600">${n.name}</td>
      <td style="font-family:monospace">${n.host}</td>
      <td style="font-family:monospace">${n.port}</td>
      <td><span class="tag ${n.username?'available':'unknown'}">${n.username?'有认证':'无认证'}</span></td>
      <td>${n.latency_ms?n.latency_ms+'ms':'-'}</td>
      <td>${slotLabel}</td>
      <td style="color:#718096;font-size:11px">${n.note||''}</td>
      <td>
        <button class="btn btn-sm btn-primary" onclick="connectCustom('${n.id}',0)">→槽1</button>
        <button class="btn btn-sm btn-grey" onclick="connectCustom('${n.id}',1)">→槽2</button>
        <button class="btn btn-sm btn-danger" onclick="deleteCustom('${n.id}')">删除</button>
      </td>`;
    tbody.appendChild(tr);
  });
}

async function addCustomNode() {
  const name = document.getElementById('cn-name').value.trim();
  const host = document.getElementById('cn-host').value.trim();
  const port = parseInt(document.getElementById('cn-port').value)||0;
  if (!name||!host||!port) return showToast('名称、地址、端口必填', true);
  const r = await api('/api/custom_nodes', {method:'POST', body:JSON.stringify({
    action:'add', name, host, port,
    username: document.getElementById('cn-user').value.trim(),
    password: document.getElementById('cn-pass').value,
    note: document.getElementById('cn-note').value.trim(),
  })});
  if (r&&r.ok) {
    showToast('节点已添加');
    ['cn-name','cn-host','cn-port','cn-user','cn-pass','cn-note'].forEach(id=>document.getElementById(id).value='');
    loadCustomNodes();
  } else showToast((r&&r.error)||'添加失败', true);
}

async function deleteCustom(nodeId) {
  const r = await api('/api/custom_nodes', {method:'POST', body:JSON.stringify({action:'delete', node_id:nodeId})});
  showToast(r&&r.ok?'已删除':'删除失败', !(r&&r.ok));
  loadCustomNodes();
}

async function connectCustom(nodeId, slot) {
  showToast(`正在连接自建节点到槽${slot+1}...`);
  const r = await api('/api/connect_custom', {method:'POST', body:JSON.stringify({node_id:nodeId, slot_id:slot})});
  showToast(r&&r.ok?r.message:(r&&r.error)||'连接失败', !(r&&r.ok));
  setTimeout(()=>{refreshAll();loadCustomNodes();}, 2000);
}

// ── 自动切换配置 ──
async function loadAutoSwitch() {
  const r = await api('/api/slot_configs');
  if (!r) return;
  slotConfigs = r.configs;
  renderAutoSwitch();
}

function renderAutoSwitch() {
  const wrap = document.getElementById('slotSwitchCards');
  wrap.innerHTML = '';
  for (let i=0; i<2; i++) {
    const cfg = slotConfigs[String(i)] || {auto_switch:true, node_sources:['vpngate_residential','vpngate_any'], countries:[], max_latency_ms:0};
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      <h2>节点槽 ${i+1} 自动切换规则</h2>
      <div class="flex items-center gap-2 mt-2">
        <input type="checkbox" id="as-en-${i}" ${cfg.auto_switch?'checked':''}>
        <label for="as-en-${i}" style="font-size:13px">启用自动切换</label>
      </div>
      <hr class="divider">
      <div style="font-size:12px;color:#718096;margin-bottom:8px">节点来源优先级（从上到下依次尝试）：</div>
      <div id="sources-${i}"></div>
      <div style="margin-top:10px;font-size:12px;color:#718096">添加来源：</div>
      <div class="flex gap-2 mt-2 flex-wrap">
        ${Object.entries(SOURCE_LABELS).map(([k,v])=>`<button class="btn btn-sm btn-grey" onclick="addSource(${i},'${k}')">${v}</button>`).join('')}
      </div>
      <hr class="divider">
      <div class="filter-group mt-2">
        <label>延迟上限 (ms，0=不限，仅影响 VPNGate 节点)</label>
        <input class="input" id="as-lat-${i}" type="number" value="${cfg.max_latency_ms||0}" style="max-width:140px;margin-top:4px">
      </div>`;
    wrap.appendChild(card);
    renderSources(i, cfg.node_sources||[]);
  }
}

function renderSources(slotId, sources) {
  const wrap = document.getElementById(`sources-${slotId}`);
  if (!wrap) return;
  wrap.innerHTML = '';
  if (!sources.length) {
    wrap.innerHTML = '<div style="color:#718096;font-size:12px;padding:8px">（无来源，将使用任意可用节点）</div>';
    return;
  }
  sources.forEach((src, idx) => {
    const div = document.createElement('div');
    div.className = 'source-item';
    div.innerHTML = `
      <span class="handle">⠿</span>
      <span style="flex:1;font-size:13px">${SOURCE_LABELS[src]||src}</span>
      ${idx>0?`<button class="btn btn-sm btn-grey" onclick="moveSource(${slotId},${idx},-1)">↑</button>`:''}
      ${idx<sources.length-1?`<button class="btn btn-sm btn-grey" onclick="moveSource(${slotId},${idx},1)">↓</button>`:''}
      <button class="btn btn-sm btn-danger" onclick="removeSource(${slotId},${idx})">×</button>`;
    wrap.appendChild(div);
  });
}

function getSlotSources(slotId) {
  const wrap = document.getElementById(`sources-${slotId}`);
  if (!wrap) return [];
  const items = wrap.querySelectorAll('.source-item span:nth-child(2)');
  const labelToKey = Object.fromEntries(Object.entries(SOURCE_LABELS).map(([k,v])=>[v,k]));
  return [...items].map(el => labelToKey[el.textContent.trim()] || el.textContent.trim());
}

function addSource(slotId, src) {
  const cur = getSlotSources(slotId);
  if (cur.includes(src)) return showToast('该来源已存在', true);
  cur.push(src);
  renderSources(slotId, cur);
}

function removeSource(slotId, idx) {
  const cur = getSlotSources(slotId);
  cur.splice(idx, 1);
  renderSources(slotId, cur);
}

function moveSource(slotId, idx, dir) {
  const cur = getSlotSources(slotId);
  const newIdx = idx + dir;
  if (newIdx < 0 || newIdx >= cur.length) return;
  [cur[idx], cur[newIdx]] = [cur[newIdx], cur[idx]];
  renderSources(slotId, cur);
}

async function saveSlotConfigs() {
  const configs = {};
  for (let i=0; i<2; i++) {
    configs[String(i)] = {
      auto_switch: document.getElementById(`as-en-${i}`).checked,
      node_sources: getSlotSources(i),
      countries: slotConfigs[String(i)]?.countries || [],
      max_latency_ms: parseInt(document.getElementById(`as-lat-${i}`)?.value)||0,
    };
  }
  const r = await api('/api/slot_configs', {method:'POST', body:JSON.stringify({configs})});
  showToast(r&&r.ok?'保存成功':'保存失败', !(r&&r.ok));
}

// ── 过滤设置 ──
async function loadFilter() {
  const [fd, nd] = await Promise.all([api('/api/filter'), api('/api/nodes')]);
  if (!fd) return;
  selectedCountries = new Set(fd.countries||[]);
  selectedIpTypes   = new Set(fd.ip_types||[]);
  document.getElementById('maxLat').value = fd.max_latency_ms||0;
  const wrap = document.getElementById('countriesWrap');
  wrap.innerHTML = '';
  const seen = new Set();
  ((nd&&nd.nodes)||[]).forEach(n=>{
    if (!n.country_short || seen.has(n.country_short)) return;
    seen.add(n.country_short);
    const btn = document.createElement('div');
    btn.className = 'country-btn'+(selectedCountries.has(n.country_short)?' selected':'');
    btn.textContent = `${n.country||n.country_zh||''} (${n.country_short})`;
    btn.dataset.code = n.country_short;
    btn.onclick = () => {
      if (selectedCountries.has(n.country_short)) selectedCountries.delete(n.country_short);
      else selectedCountries.add(n.country_short);
      btn.classList.toggle('selected', selectedCountries.has(n.country_short));
    };
    wrap.appendChild(btn);
  });
  ['residential','datacenter'].forEach(t=>{
    document.getElementById('ipt-'+t).classList.toggle('selected', selectedIpTypes.has(t));
  });
}

function toggleIpType(t) {
  if (selectedIpTypes.has(t)) selectedIpTypes.delete(t);
  else selectedIpTypes.add(t);
  document.getElementById('ipt-'+t).classList.toggle('selected', selectedIpTypes.has(t));
}

async function saveFilter() {
  const r = await api('/api/filter', {method:'POST', body:JSON.stringify({
    countries: [...selectedCountries],
    ip_types: [...selectedIpTypes],
    max_latency_ms: parseInt(document.getElementById('maxLat').value)||0,
  })});
  showToast(r&&r.ok?'保存成功':'保存失败', !(r&&r.ok));
}

// ── 协议路由 ──
async function loadRouting() {
  const d = await api('/api/routing');
  if (!d) return;
  const wrap = document.getElementById('routingConfig');
  wrap.innerHTML = '';
  for (const [proto, port] of Object.entries(PROTO_PORTS)) {
    const rc = (d.routing||{})[proto]||{slot:0,enabled:false};
    const div = document.createElement('div');
    div.className = 'proto-row';
    div.innerHTML = `
      <span class="proto-name">${proto}</span>
      <span class="proto-port">:${port}</span>
      <label style="display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer">
        <input type="checkbox" id="rt-en-${proto}" ${rc.enabled?'checked':''}> 启用代理
      </label>
      <select class="select" id="rt-sl-${proto}" style="width:100px">
        <option value="0" ${rc.slot===0?'selected':''}>节点槽 1</option>
        <option value="1" ${rc.slot===1?'selected':''}>节点槽 2</option>
      </select>`;
    wrap.appendChild(div);
  }
}

async function saveRouting() {
  const routing = {};
  for (const proto of Object.keys(PROTO_PORTS)) {
    const en = document.getElementById(`rt-en-${proto}`);
    const sl = document.getElementById(`rt-sl-${proto}`);
    if (en && sl) routing[proto] = {enabled:en.checked, slot:parseInt(sl.value)};
  }
  const r = await api('/api/routing', {method:'POST', body:JSON.stringify({routing})});
  showToast(r&&r.ok?'路由规则已应用':'保存失败', !(r&&r.ok));
}

// ── 日志 ──
async function loadLogs() {
  const d = await api('/api/logs');
  if (!d) return;
  const el = document.getElementById('logContent');
  el.innerHTML = (d.logs||[]).map(l=>
    `<div style="color:${l.level==='ERROR'?'#fc8181':l.level==='WARNING'?'#ecc94b':'#718096'}">[${l.timestamp}][${l.level}][${l.module}] ${l.message}</div>`
  ).join('');
  el.scrollTop = el.scrollHeight;
}

// ── 设置 ──
async function loadSettings() {
  const d = await api('/api/ui_config');
  if (!d) return;
  document.getElementById('infoPort').textContent = d.port||'8787';
}

async function saveCredentials() {
  const newUser = document.getElementById('newUser').value.trim();
  const newPass = document.getElementById('newPass').value;
  const newPass2 = document.getElementById('newPass2').value;
  if (newPass && newPass !== newPass2) return showToast('两次密码不一致', true);
  if (!newUser && !newPass) return showToast('请填写要修改的内容', true);
  const r = await api('/api/update_credentials', {method:'POST', body:JSON.stringify({
    username: newUser||undefined, password: newPass||undefined,
  })});
  if (r&&r.ok) {
    showToast('已更新，请重新登录');
    setTimeout(doLogout, 1500);
  } else {
    showToast((r&&r.error)||'保存失败', true);
  }
}

// ── 节点操作 ──
async function fetchNodes() {
  showToast('正在拉取节点...');
  const r = await api('/api/fetch_nodes', {method:'POST'});
  showToast(r&&r.ok?`已获取 ${r.count} 个节点`:'拉取失败', !(r&&r.ok));
  setTimeout(loadNodes, 1000);
}

async function testTopNodes() {
  showToast('后台测试前10个节点...');
  const r = await api('/api/test_nodes', {method:'POST', body:JSON.stringify({count:10})});
  showToast(r&&r.ok?'测试已在后台运行，稍后刷新查看结果':'失败', !(r&&r.ok));
}

async function testOneNode(nodeId, btn) {
  const orig = btn.textContent;
  btn.textContent = '测试中...';
  btn.disabled = true;
  try {
    const r = await api('/api/test_node', {method:'POST', body:JSON.stringify({node_id:nodeId})});
    if (r && r.probe_status) {
      const statusMap = {available:'✅ 可用', unavailable:'❌ 不可用'};
      showToast(`${statusMap[r.probe_status]||r.probe_status} ${r.latency_ms?r.latency_ms+'ms':''} ${r.quality||''}`);
      // 更新本地列表
      const node = allNodes.find(n=>n.id===nodeId);
      if (node) {
        Object.assign(node, r);
        renderNodes();
      }
    } else {
      showToast((r&&r.error)||'测试失败', true);
    }
  } finally {
    btn.textContent = orig;
    btn.disabled = false;
  }
}

async function connectNode(nodeId, slot) {
  showToast(`正在连接到槽${slot+1}...`);
  const r = await api('/api/connect', {method:'POST', body:JSON.stringify({node_id:nodeId, slot_id:slot})});
  showToast(r&&r.ok?r.message:(r&&r.error)||'连接失败', !(r&&r.ok));
  setTimeout(refreshAll, 3000);
}

async function quickConnect() {
  const raw = document.getElementById('quickNode').value;
  const slot = parseInt(document.getElementById('quickSlot').value);
  if (!raw) return showToast('请选择节点', true);
  if (raw.startsWith('custom:')) {
    await connectCustom(raw.replace('custom:',''), slot);
  } else {
    await connectNode(raw.replace('vpngate:',''), slot);
  }
}

async function stopSlot(slot) {
  const r = await api('/api/stop', {method:'POST', body:JSON.stringify({slot_id:slot})});
  showToast(r&&r.ok?`槽${slot+1}已断开`:'操作失败', !(r&&r.ok));
  setTimeout(refreshAll, 500);
}

async function checkSlot(slot) {
  showToast(`检测槽${slot+1}出口...`);
  const r = await api('/api/check_proxy', {method:'POST', body:JSON.stringify({slot_id:slot})});
  showToast(r&&r.ok?`出口IP: ${r.ip} (${r.latency_ms}ms)`:'检测失败', !(r&&r.ok));
  setTimeout(refreshAll, 500);
}

async function switchSlot(slot) {
  showToast(`槽${slot+1}触发手动切换...`);
  const r = await api('/api/switch_slot', {method:'POST', body:JSON.stringify({slot_id:slot})});
  showToast(r&&r.ok?'切换指令已发送':'切换失败', !(r&&r.ok));
  setTimeout(refreshAll, 3000);
}

// 初始化
(async()=>{
  if (SESSION) {
    const d = await api('/api/status');
    if (d) { showApp(); refreshAll(); }
    else showLogin();
  } else showLogin();
  setInterval(refreshAll, 12000);
})();
</script>
</body>
</html>"""


# ── Web Handler ──────────────────────────────────────────────────────
class WebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_session(self) -> bool:
        token = self.headers.get("X-Session", "")
        now = time.time()
        if token in WEB_SESSIONS and now - WEB_SESSIONS[token] < SESSION_TTL:
            WEB_SESSIONS[token] = now
            return True
        return False

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        if path in ("/", "/index.html"):
            body = HTML_PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not self._check_session():
            self._send_json({"error": "未授权"}, 401)
            return
        if   path == "/api/status":       self._handle_status()
        elif path == "/api/nodes":        self._send_json({"nodes": read_json(NODES_FILE, [])})
        elif path == "/api/custom_nodes": self._send_json({"nodes": read_json(CUSTOM_NODES_FILE, [])})
        elif path == "/api/filter":       self._send_json(load_filter())
        elif path == "/api/routing":      self._send_json({"routing": load_routing()})
        elif path == "/api/slot_configs": self._send_json({"configs": load_slot_configs()})
        elif path == "/api/ui_config":
            cfg = load_ui_config()
            self._send_json({"port": cfg.get("port", 8787)})
        elif path == "/api/logs":         self._handle_logs()
        else:                             self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/login":
            body = self._read_body()
            cfg = load_ui_config()
            if body.get("username") == cfg["username"] and body.get("password") == cfg["password"]:
                token = session_token(cfg["username"], cfg["password"])
                WEB_SESSIONS[token] = time.time()
                self._send_json({"token": token})
            else:
                self._send_json({"error": "用户名或密码错误"}, 401)
            return
        if not self._check_session():
            self._send_json({"error": "未授权"}, 401)
            return
        body = self._read_body()
        if   path == "/api/connect":            self._handle_connect(body)
        elif path == "/api/connect_custom":     self._handle_connect_custom(body)
        elif path == "/api/stop":               self._handle_stop(body)
        elif path == "/api/switch_slot":        self._handle_switch_slot(body)
        elif path == "/api/fetch_nodes":        self._handle_fetch_nodes()
        elif path == "/api/test_nodes":         self._handle_test_nodes(body)
        elif path == "/api/test_node":          self._handle_test_node_sync(body)
        elif path == "/api/check_proxy":        self._handle_check_proxy(body)
        elif path == "/api/custom_nodes":       self._handle_custom_nodes(body)
        elif path == "/api/filter":             save_filter(body); self._send_json({"ok": True})
        elif path == "/api/routing":
            routing = body.get("routing", {})
            save_routing(routing)
            threading.Thread(target=apply_routing_rules, args=(routing,), daemon=True).start()
            self._send_json({"ok": True})
        elif path == "/api/slot_configs":
            save_slot_configs(body.get("configs", {}))
            self._send_json({"ok": True})
        elif path == "/api/update_credentials": self._handle_update_credentials(body)
        else:                                   self._send_json({"error": "not found"}, 404)

    def _handle_status(self):
        slots_info = []
        for s in SLOTS:
            st = slot_states[s["id"]]
            slots_info.append({
                "slot_id": s["id"],
                "node_id": st.node_id,
                "node_type": st.node_type,
                "status_msg": st.status_msg,
                "is_connecting": st.is_connecting,
                "proxy_ok": st.proxy_ok,
                "proxy_ip": st.proxy_ip,
                "latency_ms": st.latency_ms,
            })
        nodes = read_json(NODES_FILE, [])
        self._send_json({
            "slots": slots_info,
            "routing": load_routing(),
            "nodes": [n for n in nodes if n.get("probe_status") == "available"][:60],
        })

    def _handle_connect(self, body: dict):
        node_id = body.get("node_id", "")
        slot_id = int(body.get("slot_id", 0))
        if not node_id:
            self._send_json({"error": "缺少 node_id"}, 400)
            return
        threading.Thread(target=lambda: _safe_connect(slot_id, node_id), daemon=True).start()
        self._send_json({"ok": True, "message": f"正在连接 {node_id} → 槽{slot_id+1}"})

    def _handle_connect_custom(self, body: dict):
        node_id = body.get("node_id", "")
        slot_id = int(body.get("slot_id", 0))
        nodes = read_json(CUSTOM_NODES_FILE, [])
        node = next((n for n in nodes if n["id"] == node_id), None)
        if not node:
            self._send_json({"error": "节点不存在"}, 404)
            return
        threading.Thread(target=lambda: _safe_connect_custom(slot_id, node), daemon=True).start()
        self._send_json({"ok": True, "message": f"正在连接 {node['name']} → 槽{slot_id+1}"})

    def _handle_stop(self, body: dict):
        stop_slot(int(body.get("slot_id", 0)))
        self._send_json({"ok": True})

    def _handle_switch_slot(self, body: dict):
        slot_id = int(body.get("slot_id", 0))
        threading.Thread(target=auto_switch_slot, args=(slot_id,), daemon=True).start()
        self._send_json({"ok": True})

    def _handle_fetch_nodes(self):
        def do():
            try:
                candidates = fetch_candidates()
                with lock:
                    existing = {n["id"]: n for n in read_json(NODES_FILE, [])}
                merged, seen = [], set()
                for c in candidates:
                    if c["id"] in existing:
                        ex = existing[c["id"]]
                        ex["config_text"] = c["config_text"]
                        ex["fetched_at"]  = c["fetched_at"]
                        merged.append(ex)
                    else:
                        merged.append(c)
                    seen.add(c["id"])
                for nid, n in existing.items():
                    if nid not in seen:
                        merged.append(n)
                write_json(NODES_FILE, sort_nodes(merged[:1000]))
            except Exception as e:
                log("ERROR", "Fetch", str(e))
        threading.Thread(target=do, daemon=True).start()
        count = len(read_json(NODES_FILE, []))
        self._send_json({"ok": True, "count": count})

    def _handle_test_nodes(self, body: dict):
        count = int(body.get("count", 10))
        nodes = read_json(NODES_FILE, [])
        ids = [n["id"] for n in nodes if n.get("probe_status") == "not_checked"][:count]
        threading.Thread(target=batch_test_nodes, args=(ids,), daemon=True).start()
        self._send_json({"ok": True, "count": len(ids)})

    def _handle_test_node_sync(self, body: dict):
        """同步测试单个节点，等待结果后返回——前端可直接拿到测试结果"""
        node_id = body.get("node_id", "")
        nodes = read_json(NODES_FILE, [])
        node = next((n for n in nodes if n["id"] == node_id), None)
        if not node:
            self._send_json({"error": "节点不存在"}, 404)
            return
        # 同步执行（阻塞请求，通常 12~15s 内完成）
        updates = test_node_sync(node)
        with lock:
            ns = read_json(NODES_FILE, [])
            for n in ns:
                if n["id"] == node_id:
                    n.update(updates)
            write_json(NODES_FILE, sort_nodes(ns))
        self._send_json({"ok": True, **updates})

    def _handle_check_proxy(self, body: dict):
        slot_id = int(body.get("slot_id", 0))
        result = check_slot_proxy(slot_id)
        st = slot_states[slot_id]
        st.proxy_ok = result["ok"]
        st.proxy_ip = result.get("ip", "")
        self._send_json(result)

    def _handle_custom_nodes(self, body: dict):
        action = body.get("action", "")
        if action == "add":
            name = body.get("name", "").strip()
            host = body.get("host", "").strip()
            port = int(body.get("port", 0))
            if not name or not host or not port:
                self._send_json({"error": "名称、地址、端口为必填项"}, 400)
                return
            node = {
                "id": "custom_" + _uuid_mod.uuid4().hex[:8],
                "node_type": "custom",
                "name": name, "host": host, "port": port,
                "username": body.get("username", ""),
                "password": body.get("password", ""),
                "note": body.get("note", ""),
                "latency_ms": 0, "active_slot": -1,
                "created_at": time.time(),
            }
            nodes = read_json(CUSTOM_NODES_FILE, [])
            nodes.append(node)
            write_json(CUSTOM_NODES_FILE, nodes)
            log("INFO", "CustomNode", f"添加: {name} ({host}:{port})")
            self._send_json({"ok": True, "node_id": node["id"]})
        elif action == "delete":
            node_id = body.get("node_id", "")
            nodes = [n for n in read_json(CUSTOM_NODES_FILE, []) if n["id"] != node_id]
            write_json(CUSTOM_NODES_FILE, nodes)
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "未知 action"}, 400)

    def _handle_update_credentials(self, body: dict):
        cfg = load_ui_config()
        new_user = body.get("username", "").strip()
        new_pass = body.get("password", "")
        if new_user:
            cfg["username"] = new_user
        if new_pass:
            cfg["password"] = new_pass
        if not new_user and not new_pass:
            self._send_json({"error": "未提供修改内容"}, 400)
            return
        save_ui_config(cfg)
        # 清除所有旧 session，强制重新登录
        WEB_SESSIONS.clear()
        log("INFO", "Settings", "登录凭证已更新")
        self._send_json({"ok": True})

    def _handle_logs(self):
        logs = []
        log_file = LOGS_DIR / f"{time.strftime('%Y-%m-%d')}.json"
        if log_file.exists():
            for line in log_file.read_text(encoding="utf-8").splitlines()[-300:]:
                try:
                    logs.append(json.loads(line))
                except Exception:
                    pass
        self._send_json({"logs": logs[-300:]})


# ── 安全包装（避免线程里抛异常无处处理） ────────────────────────────
def _safe_connect(slot_id: int, node_id: str) -> None:
    try:
        connect_slot(slot_id, node_id)
    except Exception as e:
        log("ERROR", "API", f"connect_slot({slot_id},{node_id}): {e}")

def _safe_connect_custom(slot_id: int, node: dict) -> None:
    try:
        connect_custom_socks5(slot_id, node)
    except Exception as e:
        log("ERROR", "API", f"connect_custom({slot_id},{node.get('id')}): {e}")


# ── 主程序 ───────────────────────────────────────────────────────────
def main():
    ensure_dirs()
    log("INFO", "Main", "VPNGate Pro 启动")

    proxy_mod.start_proxy_servers()

    def startup_fetch():
        try:
            candidates = fetch_candidates()
            existing = {n["id"]: n for n in read_json(NODES_FILE, [])}
            merged, seen = [], set()
            for c in candidates:
                merged.append(existing.get(c["id"], c))
                seen.add(c["id"])
            for nid, n in existing.items():
                if nid not in seen:
                    merged.append(n)
            write_json(NODES_FILE, sort_nodes(merged[:1000]))
            to_test = [n for n in merged if n.get("probe_status") == "not_checked"][:6]
            if to_test:
                batch_test_nodes([n["id"] for n in to_test])
        except Exception as e:
            log("ERROR", "Startup", str(e))

    threading.Thread(target=startup_fetch, daemon=True).start()
    threading.Thread(target=health_monitor, daemon=True).start()
    threading.Thread(target=refresh_nodes_loop, daemon=True).start()

    cfg  = load_ui_config()
    host = cfg.get("host", "0.0.0.0")
    port = int(cfg.get("port", 8787))
    server = ThreadingHTTPServer((host, port), WebHandler)
    log("INFO", "WebUI", f"地址: http://{host}:{port}/  用户名: {cfg['username']}  密码: {cfg['password']}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("INFO", "Main", "退出...")
        for sid in range(2):
            stop_slot(sid)
        proxy_mod.stop_proxy_servers()


if __name__ == "__main__":
    main()
