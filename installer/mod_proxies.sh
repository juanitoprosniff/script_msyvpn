#!/bin/bash
# mod_proxies.sh - MSY VPN
# Proxies Python (80, 8080, 8880, 8888) + BadVPN UDPGW (UDP 7300)

# ====================
# PROXY PYTHON
# ====================
echo "Creando Proxy Python..."

cat > /etc/proxy-python/proxy.py <<'PYEOF'
#!/usr/bin/env python3
"""
MSY VPN Proxy - Multi-metodo compatible
Canal: https://t.me/FREEINTERNETVPNMSY
"""
import socket, threading, select, sys, re, base64, hashlib

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 80
BUFLEN = 65536
TIMEOUT = 120
SSH_HOST = '127.0.0.1'
SSH_PORT = 143
RESPONSE_CODE = '101'
BANNER_TEXT = '<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>'
CHANNEL = 't.me/FREEINTERNETVPNMSY'

def ws_handshake_response(key):
    magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()
    return (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )

class ConnectionHandler(threading.Thread):
    def __init__(self, client, server_cfg, addr):
        super().__init__(daemon=True)
        self.client = client
        self.cfg    = server_cfg
        self.addr   = addr
        self.ssh    = None

    def run(self):
        try:
            self.client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            data = self.client.recv(BUFLEN)
            if not data:
                return self._close()
            self._connect_backend()
            if not self.ssh:
                return self._close()
            self._send_response(data)
            self._tunnel()
        except Exception:
            pass
        finally:
            self._close()

    def _connect_backend(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.settimeout(10)
            s.connect((self.cfg['ssh_host'], self.cfg['ssh_port']))
            s.settimeout(None)
            self.ssh = s
        except Exception:
            self.ssh = None

    def _send_response(self, data):
        try:
            head = data[:4096].decode('utf-8', errors='ignore')
            code    = self.cfg['code']
            banner  = self.cfg['banner']
            channel = CHANNEL

            if 'Upgrade: websocket' in head or 'upgrade: websocket' in head:
                m = re.search(r'Sec-WebSocket-Key:\s*(\S+)', head, re.I)
                if m:
                    self.client.sendall(ws_handshake_response(m.group(1)).encode())
                    return
                self.client.sendall(
                    f"HTTP/1.1 101 {banner}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".encode()
                )
                return

            if head.startswith('CONNECT '):
                self.client.sendall(
                    f"HTTP/1.1 200 {banner}\r\n"
                    f"X-Channel: {channel}\r\n"
                    f"Connection: keep-alive\r\n\r\n".encode()
                )
                return

            if re.match(r'(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ', head):
                self.client.sendall((
                    f"HTTP/1.1 {code} {banner}\r\n"
                    f"Content-Length: 999999\r\n"
                    f"Connection: keep-alive\r\n"
                    f"Keep-Alive: timeout=60, max=10000\r\n"
                    f"X-Channel: {channel}\r\n"
                    f"\r\n"
                ).encode())
                return

            self.client.sendall((
                f"HTTP/1.1 {code} {banner}\r\n"
                f"Content-Length: 999999\r\n"
                f"Connection: keep-alive\r\n"
                f"X-Channel: {channel}\r\n"
                f"\r\n"
            ).encode())
        except Exception:
            pass

    def _tunnel(self):
        try:
            while True:
                r, _, _ = select.select([self.client, self.ssh], [], [], TIMEOUT)
                if not r:
                    break
                for s in r:
                    d = s.recv(BUFLEN)
                    if not d:
                        return
                    other = self.ssh if s is self.client else self.client
                    other.sendall(d)
        except Exception:
            pass

    def _close(self):
        for s in (self.client, self.ssh):
            try:
                if s: s.close()
            except Exception:
                pass

class ProxyServer:
    def __init__(self, host, port, ssh_host, ssh_port, code, banner):
        self.cfg = {'host': host, 'port': port,
                    'ssh_host': ssh_host, 'ssh_port': ssh_port,
                    'code': code, 'banner': banner}

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        srv.bind((self.cfg['host'], self.cfg['port']))
        srv.listen(1000)
        while True:
            try:
                c, a = srv.accept()
                ConnectionHandler(c, self.cfg, a).start()
            except KeyboardInterrupt:
                break
            except Exception:
                pass

if __name__ == '__main__':
    port     = int(sys.argv[1]) if len(sys.argv) > 1 else LISTENING_PORT
    code     = sys.argv[2]      if len(sys.argv) > 2 else RESPONSE_CODE
    banner   = sys.argv[3]      if len(sys.argv) > 3 else BANNER_TEXT
    ssh_port = int(sys.argv[4]) if len(sys.argv) > 4 else SSH_PORT
    ProxyServer(LISTENING_ADDR, port, SSH_HOST, ssh_port, code, banner).start()
PYEOF

chmod +x /etc/proxy-python/proxy.py

# Crear conf por defecto
if [ ! -f /etc/proxy-python/proxies.conf ]; then
    echo '80|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143'   > /etc/proxy-python/proxies.conf
    echo '8080|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> /etc/proxy-python/proxies.conf
    echo '8880|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> /etc/proxy-python/proxies.conf
    echo '8888|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> /etc/proxy-python/proxies.conf
fi

# ====================
# SERVICIO RESTORE PROXIES
# ====================
cat > /etc/systemd/system/restore-proxies.service <<'SVCEOF'
[Unit]
Description=MSY VPN - Restaurar proxies Python
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 5
ExecStart=/bin/bash -c 'source /root/ssh-vpn-functions.sh && restore_proxies'
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable restore-proxies >/dev/null 2>&1
echo "✓ Proxy Python configurado"

# ====================
# INSTALAR BADVPN UDPGW
# ====================
echo "Instalando BadVPN UDPGW..."

cd /usr/src
if [ ! -d badvpn ]; then
    git clone --quiet https://github.com/ambrop72/badvpn.git 2>/dev/null
fi
cd badvpn
mkdir -p build && cd build

cmake .. \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_NOTHING_BY_DEFAULT=1 \
    -DBUILD_UDPGW=1 \
    >/dev/null 2>&1

make -j$(nproc) >/dev/null 2>&1
make install >/dev/null 2>&1

cat > /etc/systemd/system/badvpn-udpgw.service <<'EOF'
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=3
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable badvpn-udpgw >/dev/null 2>&1
systemctl start badvpn-udpgw
echo "✓ BadVPN UDPGW activo en puerto UDP 7300"

cd /root
