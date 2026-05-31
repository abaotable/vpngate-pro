#!/usr/bin/env python3
"""
双节点本地代理服务器
- Slot 0: 绑定 tun10，监听 :7920
- Slot 1: 绑定 tun11，监听 :7921
- 支持 HTTP CONNECT 和 SOCKS5
- tun 断开时返回 502，不回落到物理网卡
"""
from __future__ import annotations

import select
import socket
import threading
from typing import Any


def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ── 上游 SOCKS5 转发（自建节点） ────────────────────────────────────

def connect_via_upstream_socks5(
    target_host: str, target_port: int,
    upstream_host: str, upstream_port: int,
    username: str = "", password: str = "",
    timeout: float = 20.0
) -> socket.socket:
    """通过上游 SOCKS5 服务器连接目标，返回已建立的 socket"""
    sock = socket.create_connection((upstream_host, upstream_port), timeout=timeout)
    try:
        # 握手：选择认证方式
        if username:
            sock.sendall(b"\x05\x02\x00\x02")  # 支持无认证和用户名密码
        else:
            sock.sendall(b"\x05\x01\x00")       # 只支持无认证
        resp = recv_exact(sock, 2)
        if resp[0] != 5:
            raise ConnectionError("上游不是 SOCKS5 服务器")
        method = resp[1]
        if method == 0xFF:
            raise ConnectionError("上游 SOCKS5 拒绝认证方式")
        # 用户名密码认证
        if method == 0x02:
            if not username:
                raise ConnectionError("上游要求认证但未提供用户名密码")
            u = username.encode()
            p = password.encode()
            auth_req = bytes([1, len(u)]) + u + bytes([len(p)]) + p
            sock.sendall(auth_req)
            auth_resp = recv_exact(sock, 2)
            if auth_resp[1] != 0:
                raise ConnectionError("上游 SOCKS5 认证失败")
        # 发送 CONNECT 请求
        try:
            socket.inet_aton(target_host)
            addr_type = 1
            addr_bytes = socket.inet_aton(target_host)
        except OSError:
            addr_type = 3
            host_bytes = target_host.encode()
            addr_bytes = bytes([len(host_bytes)]) + host_bytes
        port_bytes = target_port.to_bytes(2, "big")
        sock.sendall(b"\x05\x01\x00" + bytes([addr_type]) + addr_bytes + port_bytes)
        # 读响应
        resp_header = recv_exact(sock, 4)
        if resp_header[1] != 0:
            raise ConnectionError(f"上游 SOCKS5 CONNECT 失败，代码: {resp_header[1]}")
        # 跳过绑定地址
        atype = resp_header[3]
        if atype == 1:
            recv_exact(sock, 4 + 2)
        elif atype == 3:
            length = recv_exact(sock, 1)[0]
            recv_exact(sock, length + 2)
        elif atype == 4:
            recv_exact(sock, 16 + 2)
        return sock
    except Exception:
        sock.close()
        raise


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("连接意外断开")
        data += chunk
    return data


def resolve_via_tun(host: str, tun_dev: str, dns_server: str = "8.8.8.8", timeout: float = 3.0) -> str | None:
    """通过指定 tun 网卡做 DNS 解析"""
    try:
        socket.inet_aton(host)
        return host  # 已经是 IP
    except OSError:
        pass
    import random
    tx_id = random.getrandbits(16).to_bytes(2, "big")
    qname = b""
    for part in host.split("."):
        if not part:
            continue
        b = part.encode("idna")
        qname += len(b).to_bytes(1, "big") + b
    qname += b"\x00"
    packet = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, tun_dev.encode() + b"\x00")
        except OSError:
            return None
        sock.sendto(packet, (dns_server, 53))
        resp, _ = sock.recvfrom(2048)
    except Exception:
        return None
    finally:
        sock.close()
    if len(resp) < 12 or resp[:2] != tx_id:
        return None
    if resp[3] & 0x0F != 0:
        return None
    offset = 12
    # 跳过 question section
    while offset < len(resp):
        l = resp[offset]
        if l == 0:
            offset += 1
            break
        elif (l & 0xC0) == 0xC0:
            offset += 2
            break
        else:
            offset += 1 + l
    offset += 4  # qtype + qclass
    answers = int.from_bytes(resp[6:8], "big")
    for _ in range(answers):
        if offset >= len(resp):
            break
        while offset < len(resp):
            l = resp[offset]
            if l == 0:
                offset += 1
                break
            elif (l & 0xC0) == 0xC0:
                offset += 2
                break
            else:
                offset += 1 + l
        if offset + 10 > len(resp):
            break
        atype = int.from_bytes(resp[offset:offset + 2], "big")
        rdlen = int.from_bytes(resp[offset + 8:offset + 10], "big")
        offset += 10
        if atype == 1 and rdlen == 4:
            return socket.inet_ntoa(resp[offset:offset + 4])
        offset += rdlen
    return None


def create_tun_connection(host: str, port: int, tun_dev: str, timeout: float = 20.0) -> socket.socket:
    """创建绑定到指定 tun 网卡的 TCP 连接，失败直接抛异常（不回落物理网卡）"""
    resolved = resolve_via_tun(host, tun_dev)
    if resolved:
        host = resolved
    for res in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        af, socktype, proto, _, sa = res
        sock = socket.socket(af, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, tun_dev.encode() + b"\x00")
        except OSError as e:
            sock.close()
            raise RuntimeError(f"SO_BINDTODEVICE {tun_dev} 失败: {e}，VPN 可能未连接") from e
        sock.connect(sa)
        return sock
    raise OSError(f"无法解析 {host}:{port}")


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


def handle_http(client: socket.socket, first_line: str, tun_dev: str,
                upstream: dict | None = None) -> None:
    """处理 HTTP CONNECT 代理"""
    upstream = None
    try:
        # 读完请求头
        buf = first_line.encode()
        while b"\r\n\r\n" not in buf:
            chunk = client.recv(4096)
            if not chunk:
                return
            buf += chunk

        if not first_line.upper().startswith("CONNECT "):
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return

        # 解析目标
        parts = first_line.split()
        if len(parts) < 2:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        host_port = parts[1]
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = host_port, 443

        try:
            if upstream:
                # 自建 SOCKS5 节点模式
                conn = connect_via_upstream_socks5(
                    host, port,
                    upstream["host"], upstream["port"],
                    upstream.get("username", ""), upstream.get("password", "")
                )
            else:
                conn = create_tun_connection(host, port, tun_dev)
        except Exception as e:
            err_msg = f"HTTP/1.1 502 Bad Gateway\r\nX-Error: {e}\r\n\r\n"
            client.sendall(err_msg.encode())
            return

        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        relay(client, conn)
    except Exception:
        pass
    finally:
        if upstream:
            try:
                upstream.close()
            except Exception:
                pass


def handle_socks5(client: socket.socket, tun_dev: str,
                  upstream: dict | None = None) -> None:
    """处理 SOCKS5 代理"""
    conn = None
    try:
        methods_count = recv_exact(client, 1)[0]
        recv_exact(client, methods_count)
        client.sendall(b"\x05\x00")  # 无认证

        header = recv_exact(client, 4)
        version, cmd, _, atype = header
        if version != 5 or cmd != 1:
            client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return

        if atype == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif atype == 3:
            length = recv_exact(client, 1)[0]
            host = recv_exact(client, length).decode()
        elif atype == 4:
            host = socket.inet6_ntoa(recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return

        port = int.from_bytes(recv_exact(client, 2), "big")

        try:
            if upstream:
                conn = connect_via_upstream_socks5(
                    host, port,
                    upstream["host"], upstream["port"],
                    upstream.get("username", ""), upstream.get("password", "")
                )
            else:
                conn = create_tun_connection(host, port, tun_dev)
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


def handle_client(client: socket.socket, tun_dev: str,
                  upstream_socks5: dict | None = None) -> None:
    try:
        first_byte = client.recv(1)
        if not first_byte:
            return
        if first_byte == b"\x05":
            handle_socks5(client, tun_dev, upstream_socks5)
        else:
            # HTTP
            rest = b""
            while b"\n" not in rest:
                chunk = client.recv(4096)
                if not chunk:
                    return
                rest += chunk
            first_line = (first_byte + rest).decode(errors="replace").split("\n")[0].strip()
            handle_http(client, first_line, tun_dev, upstream_socks5)
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass


class SlotProxyServer:
    """单个 slot 的代理服务器（绑定特定 tun 网卡，或转发到上游 SOCKS5）"""

    def __init__(self, slot_id: int, tun_dev: str, listen_host: str, listen_port: int):
        self.slot_id = slot_id
        self.tun_dev = tun_dev
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_socks5: dict | None = None  # 自建节点时设置
        self.slot_id = slot_id
        self.tun_dev = tun_dev
        self.listen_host = listen_host
        self.listen_port = listen_port
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
        print(f"[Proxy-Slot{self.slot_id}] 监听 {self.listen_host}:{self.listen_port} → {self.tun_dev}", flush=True)

    def _accept_loop(self) -> None:
        while self._running:
            try:
                self._server.settimeout(1.0)
                client, _ = self._server.accept()
                threading.Thread(
                    target=handle_client,
                    args=(client, self.tun_dev, self.upstream_socks5),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    import traceback
                    traceback.print_exc()
                break

    def set_upstream_socks5(self, upstream: dict | None) -> None:
        """切换到自建 SOCKS5 节点模式（传 None 恢复 tun 模式）"""
        self.upstream_socks5 = upstream

    def stop(self) -> None:
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass


# 两个 slot 的代理实例（模块级单例）
_proxy_slots: dict[int, SlotProxyServer] = {}

SLOT_CONFIG = [
    {"slot_id": 0, "tun_dev": "tun10", "listen_host": "127.0.0.1", "listen_port": 7920},
    {"slot_id": 1, "tun_dev": "tun11", "listen_host": "127.0.0.1", "listen_port": 7921},
]


def start_proxy_servers() -> None:
    for cfg in SLOT_CONFIG:
        sid = cfg["slot_id"]
        if sid not in _proxy_slots:
            srv = SlotProxyServer(**cfg)
            srv.start()
            _proxy_slots[sid] = srv


def stop_proxy_servers() -> None:
    for srv in _proxy_slots.values():
        srv.stop()
    _proxy_slots.clear()


def get_slot_proxy_addr(slot_id: int) -> str:
    cfg = SLOT_CONFIG[slot_id]
    return f"http://{cfg['listen_host']}:{cfg['listen_port']}"
