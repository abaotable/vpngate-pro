#!/usr/bin/env python3
"""
双节点本地代理服务器
- Slot 0: fwmark=110，监听 :7920，流量经 ip rule 走 tun10
- Slot 1: fwmark=111，监听 :7921，流量经 ip rule 走 tun11
- src_ip 绑定 tun 本地 IP，确保包从正确接口发出
- VPN 断开时路由表为空，连接失败返回 502，不回落物理网卡
"""
from __future__ import annotations

import select
import socket
import threading
from typing import Any

SO_MARK = 36  # Linux SOL_SOCKET SO_MARK


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("连接意外断开")
        data += chunk
    return data


# ── 上游 SOCKS5 转发（自建节点） ────────────────────────────────────

def connect_via_upstream_socks5(
    target_host: str, target_port: int,
    upstream_host: str, upstream_port: int,
    username: str = "", password: str = "",
    timeout: float = 20.0,
) -> socket.socket:
    sock = socket.create_connection((upstream_host, upstream_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x02\x00\x02" if username else b"\x05\x01\x00")
        resp = recv_exact(sock, 2)
        if resp[0] != 5:
            raise ConnectionError("上游不是 SOCKS5 服务器")
        method = resp[1]
        if method == 0xFF:
            raise ConnectionError("上游 SOCKS5 拒绝认证方式")
        if method == 0x02:
            if not username:
                raise ConnectionError("上游要求认证但未提供用户名密码")
            u, p = username.encode(), password.encode()
            sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
            if recv_exact(sock, 2)[1] != 0:
                raise ConnectionError("上游 SOCKS5 认证失败")
        try:
            socket.inet_aton(target_host)
            addr_bytes = b"\x01" + socket.inet_aton(target_host)
        except OSError:
            h = target_host.encode()
            addr_bytes = bytes([3, len(h)]) + h
        sock.sendall(b"\x05\x01\x00" + addr_bytes + target_port.to_bytes(2, "big"))
        resp_header = recv_exact(sock, 4)
        if resp_header[1] != 0:
            raise ConnectionError(f"上游 CONNECT 失败，代码: {resp_header[1]}")
        atype = resp_header[3]
        if atype == 1:
            recv_exact(sock, 6)
        elif atype == 3:
            recv_exact(sock, recv_exact(sock, 1)[0] + 2)
        elif atype == 4:
            recv_exact(sock, 18)
        return sock
    except Exception:
        sock.close()
        raise


# ── fwmark + src_ip 路由连接（VPNGate 节点） ────────────────────────

def create_marked_connection(host: str, port: int, fwmark: int,
                              src_ip: str = "", timeout: float = 20.0) -> socket.socket:
    """
    创建带 fwmark 标记的 TCP 连接，绑定 tun 本地 IP 作为源地址。
    - fwmark → ip rule → 路由表 → tun 出站
    - src_ip → bind() → 确保源地址为 tun 本地 IP
    VPN 断开时路由表无路由，立即失败，不回落物理网卡。
    """
    for res in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        af, socktype, proto, _, sa = res
        sock = socket.socket(af, socktype, proto)
        sock.settimeout(timeout)
        # 打 fwmark 标记
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_MARK, fwmark)
        except OSError as e:
            sock.close()
            raise RuntimeError(f"SO_MARK 设置失败（需要root）: {e}") from e
        # 绑定 tun 本地 IP 作为源地址
        if src_ip:
            try:
                sock.bind((src_ip, 0))
            except OSError:
                pass
        try:
            sock.connect(sa)
        except OSError as e:
            sock.close()
            raise RuntimeError(f"连接 {host}:{port} 失败（VPN未连接）: {e}") from e
        return sock
    raise OSError(f"无法解析 {host}:{port}")


# ── 流量中继 ─────────────────────────────────────────────────────────

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored:
            return
        for src in readable:
            dst = right if src is left else left
            data = src.recv(65536)
            if not data:
                return
            dst.sendall(data)


# ── HTTP CONNECT 处理 ────────────────────────────────────────────────

def handle_http(client: socket.socket, first_line: str, fwmark: int,
                upstream: dict | None = None, src_ip: str = "") -> None:
    conn = None
    try:
        buf = first_line.encode()
        while b"\r\n\r\n" not in buf:
            chunk = client.recv(4096)
            if not chunk:
                return
            buf += chunk
        if not first_line.upper().startswith("CONNECT "):
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        parts = first_line.split()
        if len(parts) < 2:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        host_port = parts[1]
        host, port = (host_port.rsplit(":", 1) if ":" in host_port else (host_port, "443"))
        port = int(port)
        try:
            if upstream:
                conn = connect_via_upstream_socks5(
                    host, port, upstream["host"], upstream["port"],
                    upstream.get("username", ""), upstream.get("password", ""),
                )
            else:
                conn = create_marked_connection(host, port, fwmark, src_ip)
        except Exception as e:
            client.sendall(f"HTTP/1.1 502 Bad Gateway\r\nX-Error: {e}\r\n\r\n".encode())
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        relay(client, conn)
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ── SOCKS5 处理 ──────────────────────────────────────────────────────

def handle_socks5(client: socket.socket, fwmark: int,
                  upstream: dict | None = None, src_ip: str = "") -> None:
    conn = None
    try:
        methods_count = recv_exact(client, 1)[0]
        recv_exact(client, methods_count)
        client.sendall(b"\x05\x00")
        header = recv_exact(client, 4)
        version, cmd, _, atype = header
        if version != 5 or cmd != 1:
            client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        if atype == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif atype == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode()
        elif atype == 4:
            host = socket.inet6_ntoa(recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = int.from_bytes(recv_exact(client, 2), "big")
        try:
            if upstream:
                conn = connect_via_upstream_socks5(
                    host, port, upstream["host"], upstream["port"],
                    upstream.get("username", ""), upstream.get("password", ""),
                )
            else:
                conn = create_marked_connection(host, port, fwmark, src_ip)
        except Exception:
            client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return
        client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        relay(client, conn)
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ── 客户端分发 ───────────────────────────────────────────────────────

def handle_client(client: socket.socket, fwmark: int,
                  upstream_socks5: dict | None = None,
                  src_ip: str = "") -> None:
    try:
        first_byte = client.recv(1)
        if not first_byte:
            return
        if first_byte == b"\x05":
            handle_socks5(client, fwmark, upstream_socks5, src_ip)
        else:
            rest = b""
            while b"\n" not in rest:
                chunk = client.recv(4096)
                if not chunk:
                    return
                rest += chunk
            first_line = (first_byte + rest).decode(errors="replace").split("\n")[0].strip()
            handle_http(client, first_line, fwmark, upstream_socks5, src_ip)
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass


# ── Slot 代理服务器 ──────────────────────────────────────────────────

class SlotProxyServer:
    def __init__(self, slot_id: int, fwmark: int, listen_host: str, listen_port: int):
        self.slot_id     = slot_id
        self.fwmark      = fwmark
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_socks5: dict | None = None
        self.src_ip: str = ""  # tun 本地 IP，连接后由 manager 更新
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.listen_host, self.listen_port))
        self._server.listen(256)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        print(f"[Proxy-Slot{self.slot_id}] 监听 {self.listen_host}:{self.listen_port} fwmark={self.fwmark}", flush=True)

    def _accept_loop(self) -> None:
        while self._running:
            try:
                self._server.settimeout(1.0)
                client, _ = self._server.accept()
                threading.Thread(
                    target=handle_client,
                    args=(client, self.fwmark, self.upstream_socks5, self.src_ip),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    import traceback
                    traceback.print_exc()
                break

    def set_upstream_socks5(self, upstream: dict | None) -> None:
        self.upstream_socks5 = upstream

    def set_src_ip(self, ip: str) -> None:
        """连接 VPN 后更新 tun 本地 IP"""
        self.src_ip = ip

    def stop(self) -> None:
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass


# ── 模块级单例 ───────────────────────────────────────────────────────

_proxy_slots: dict[int, SlotProxyServer] = {}

SLOT_CONFIG = [
    {"slot_id": 0, "fwmark": 110, "listen_host": "127.0.0.1", "listen_port": 7920},
    {"slot_id": 1, "fwmark": 111, "listen_host": "127.0.0.1", "listen_port": 7921},
]


def start_proxy_servers() -> None:
    for cfg in SLOT_CONFIG:
        sid = cfg["slot_id"]
        if sid not in _proxy_slots:
            srv = SlotProxyServer(
                slot_id=cfg["slot_id"], fwmark=cfg["fwmark"],
                listen_host=cfg["listen_host"], listen_port=cfg["listen_port"],
            )
            srv.start()
            _proxy_slots[sid] = srv


def stop_proxy_servers() -> None:
    for srv in _proxy_slots.values():
        srv.stop()
    _proxy_slots.clear()
