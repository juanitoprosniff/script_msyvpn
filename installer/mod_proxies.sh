#!/bin/bash
# mod_proxies.sh - MSY VPN v104+
# Proxies Python + BadVPN UDPGW
# Mejoras:
#   - Proxy Python reescrito: manejo de errores por socket, timeouts agresivos,
#     reconexión ante CLOSE_WAIT/TIME_WAIT, soporte WebSocket mejorado
#   - Watchdog en background que reinicia proxies caídos automáticamente
#   - Liberación de puertos al detener/desinstalar (fuser -k)
#   - BadVPN: verificación post-compilación más robusta

# ============================================================
# PROXY PYTHON MEJORADO
# Cambios vs versión original:
#   1. socket.settimeout() en recv para evitar hilos colgados
#   2. SO_LINGER=0 para liberar puertos rápido (evita TIME_WAIT)
#   3. shutdown() antes de close() para corte limpio de TCP
#   4. Manejo separado de excepciones BrokenPipeError / ConnectionResetError
#   5. Buffer de lectura inicial más robusto (loop hasta \r\n\r\n)
#   6. WebSocket: respuesta completa con todos los headers requeridos
# ============================================================
echo "Creando Proxy Python mejorado..."

cat > /etc/proxy-python/proxy.py <<'PYEOF'
#!/usr/bin/env python3
"""
MSY VPN Proxy - Multi-metodo compatible v2
Canal: https://t.me/FREEINTERNETVPNMSY
Mejoras: estabilidad, watchdog, timeouts, WebSocket robusto
"""
import socket
import threading
import select
import sys
import re
import base64
import hashlib
import time
import os
import signal
import logging

# ---- Configuración ----
LISTENING_ADDR  = '0.0.0.0'
LISTENING_PORT  = 80
BUFLEN          = 65536
TIMEOUT_IDLE    = 120       # segundos sin datos antes de cerrar
TIMEOUT_CONNECT = 10        # segundos para conectar al backend
SSH_HOST        = '127.0.0.1'
SSH_PORT        = 143
RESPONSE_CODE   = '101'
BANNER_TEXT     = '<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>'
CHANNEL         = 't.me/FREEINTERNETVPNMSY'

# Logging mínimo (solo errores críticos, no llena disco)
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s %(message)s'
)
log = logging.getLogger('msyvpn-proxy')


def _apply_socket_opts(s):
    """Aplica opciones de socket para máxima estabilidad."""
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE, 1)
        # TCP keepalive granular (Linux)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  30)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,    3)
    except (OSError, AttributeError):
        pass
    try:
        # SO_LINGER=0: cierre inmediato, sin TIME_WAIT prolongado
        import struct
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                     struct.pack('ii', 1, 0))
    except (OSError, AttributeError):
        pass


def _close_socket(s):
    """Cierre limpio: shutdown primero, luego close."""
    if s is None:
        return
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def ws_handshake_response(key):
    magic  = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    accept = base64.b64encode(
        hashlib.sha1((key + magic).encode()).digest()
    ).decode()
    return (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "X-Channel: " + CHANNEL + "\r\n"
        "\r\n"
    )


def read_http_header(sock):
    """
    Lee el header HTTP completo (hasta \\r\\n\\r\\n).
    Maneja fragmentación de paquetes que causa fallos en algunos OS.
    """
    data = b''
    sock.settimeout(TIMEOUT_CONNECT)
    try:
        while b'\r\n\r\n' not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:   # cabecera enorme = anomalía
                break
    except OSError:
        pass
    finally:
        sock.settimeout(None)
    return data


class ConnectionHandler(threading.Thread):
    def __init__(self, client, cfg, addr):
        super().__init__(daemon=True)
        self.client = client
        self.cfg    = cfg
        self.addr   = addr
        self.ssh    = None

    # ----------------------------------------------------------
    def run(self):
        try:
            _apply_socket_opts(self.client)
            data = read_http_header(self.client)
            if not data:
                return
            self._connect_backend()
            if self.ssh is None:
                return
            self._send_response(data)
            self._tunnel()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            log.error("Handler error %s: %s", self.addr, e)
        finally:
            _close_socket(self.client)
            _close_socket(self.ssh)

    # ----------------------------------------------------------
    def _connect_backend(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _apply_socket_opts(s)
            s.settimeout(TIMEOUT_CONNECT)
            s.connect((self.cfg['ssh_host'], self.cfg['ssh_port']))
            s.settimeout(None)
            self.ssh = s
        except OSError as e:
            log.error("Backend connect failed: %s", e)
            self.ssh = None

    # ----------------------------------------------------------
    def _send_response(self, data):
        try:
            head    = data[:8192].decode('utf-8', errors='ignore')
            code    = self.cfg['code']
            banner  = self.cfg['banner']

            # --- WebSocket upgrade ---
            if re.search(r'upgrade:\s*websocket', head, re.I):
                m = re.search(r'Sec-WebSocket-Key:\s*(\S+)', head, re.I)
                if m:
                    self.client.sendall(ws_handshake_response(m.group(1)).encode())
                else:
                    self.client.sendall((
                        f"HTTP/1.1 101 {banner}\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"X-Channel: {CHANNEL}\r\n\r\n"
                    ).encode())
                return

            # --- CONNECT (HTTP Tunnel) ---
            if head.startswith('CONNECT '):
                self.client.sendall((
                    f"HTTP/1.1 200 {banner}\r\n"
                    f"X-Channel: {CHANNEL}\r\n"
                    "Connection: keep-alive\r\n\r\n"
                ).encode())
                return

            # --- GET/POST/HEAD u otros métodos HTTP ---
            if re.match(r'(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ', head):
                self.client.sendall((
                    f"HTTP/1.1 {code} {banner}\r\n"
                    "Content-Length: 999999\r\n"
                    "Connection: keep-alive\r\n"
                    "Keep-Alive: timeout=60, max=10000\r\n"
                    f"X-Channel: {CHANNEL}\r\n\r\n"
                ).encode())
                return

            # --- Payload genérico / conexión directa TCP ---
            self.client.sendall((
                f"HTTP/1.1 {code} {banner}\r\n"
                "Content-Length: 999999\r\n"
                "Connection: keep-alive\r\n"
                f"X-Channel: {CHANNEL}\r\n\r\n"
            ).encode())

        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            log.error("Response error: %s", e)

    # ----------------------------------------------------------
    def _tunnel(self):
        """Bidirectional forwarding con timeout para evitar hilos zombis."""
        sockets = [self.client, self.ssh]
        try:
            while True:
                try:
                    r, _, e = select.select(sockets, [], sockets, TIMEOUT_IDLE)
                except (ValueError, OSError):
                    break

                if e:       # socket con error
                    break
                if not r:   # timeout de inactividad
                    break

                for s in r:
                    try:
                        d = s.recv(BUFLEN)
                    except OSError:
                        return
                    if not d:
                        return
                    other = self.ssh if s is self.client else self.client
                    try:
                        other.sendall(d)
                    except OSError:
                        return
        except Exception:
            pass


# ============================================================
class ProxyServer:
    def __init__(self, host, port, ssh_host, ssh_port, code, banner):
        self.cfg = {
            'host':     host,
            'port':     port,
            'ssh_host': ssh_host,
            'ssh_port': ssh_port,
            'code':     code,
            'banner':   banner,
        }
        self._srv = None

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            srv.bind((self.cfg['host'], self.cfg['port']))
        except OSError as e:
            log.error("Bind :%d failed: %s", self.cfg['port'], e)
            sys.exit(1)
        srv.listen(1000)
        self._srv = srv
        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT,  self._shutdown)
        while True:
            try:
                c, a = srv.accept()
                ConnectionHandler(c, self.cfg, a).start()
            except (KeyboardInterrupt, SystemExit):
                break
            except OSError:
                time.sleep(0.1)

    def _shutdown(self, *_):
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass
        sys.exit(0)


if __name__ == '__main__':
    port     = int(sys.argv[1]) if len(sys.argv) > 1 else LISTENING_PORT
    code     = sys.argv[2]      if len(sys.argv) > 2 else RESPONSE_CODE
    banner   = sys.argv[3]      if len(sys.argv) > 3 else BANNER_TEXT
    ssh_port = int(sys.argv[4]) if len(sys.argv) > 4 else SSH_PORT
    ProxyServer(LISTENING_ADDR, port, SSH_HOST, ssh_port, code, banner).start()
PYEOF

chmod +x /etc/proxy-python/proxy.py

# ============================================================
# WATCHDOG DE PROXIES (script independiente)
# Se ejecuta como servicio systemd, comprueba cada 30 segundos
# que cada proxy configurado esté corriendo y lo reinicia si cayó
# ============================================================
cat > /etc/proxy-python/watchdog.sh <<'WDEOF'
#!/bin/bash
# MSY VPN - Proxy Watchdog
# Reinicia automáticamente proxies caídos

CONF=/etc/proxy-python/proxies.conf
LOG=/var/log/msyvpn-watchdog.log

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
}

start_proxy_silent() {
    local port=$1 response=$2 banner=$3 ssh_port=${4:-143}
    screen -dmS "proxy-$port" python3 /etc/proxy-python/proxy.py \
        "$port" "$response" "$banner" "$ssh_port"
    sleep 1
    if screen -list 2>/dev/null | grep -q "proxy-$port"; then
        log "WATCHDOG: proxy :$port reiniciado"
        return 0
    fi
    log "WATCHDOG: ERROR al reiniciar proxy :$port"
    return 1
}

while true; do
    sleep 30
    [ ! -f "$CONF" ] && continue

    while IFS='|' read -r port response banner ssh_port; do
        [ -z "$port" ] && continue
        # ¿El screen existe y el puerto está escuchando?
        if ! screen -list 2>/dev/null | grep -q "proxy-${port}"; then
            log "WATCHDOG: proxy :$port caído, reiniciando..."
            start_proxy_silent "$port" "$response" "$banner" "$ssh_port"
        fi
    done < "$CONF"

    # Rotar log si supera 1MB
    if [ -f "$LOG" ] && [ "$(stat -c%s "$LOG" 2>/dev/null)" -gt 1048576 ]; then
        tail -200 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
    fi
done
WDEOF

chmod +x /etc/proxy-python/watchdog.sh

# Servicio systemd para el watchdog
cat > /etc/systemd/system/proxy-watchdog.service <<'SVCEOF'
[Unit]
Description=MSY VPN - Proxy Watchdog
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /etc/proxy-python/watchdog.sh
Restart=always
RestartSec=10
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
SVCEOF

# ============================================================
# CONFIGURACIÓN DE PROXIES POR DEFECTO
# ============================================================
if [ ! -f /etc/proxy-python/proxies.conf ]; then
    cat > /etc/proxy-python/proxies.conf <<'CONFEOF'
80|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143
8080|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143
8880|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143
8888|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143
CONFEOF
fi

# ============================================================
# SERVICIO RESTORE-PROXIES (al reiniciar el servidor)
# ============================================================
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
systemctl enable restore-proxies  >/dev/null 2>&1
systemctl enable proxy-watchdog   >/dev/null 2>&1

echo "✓ Proxy Python v2 instalado"

# ============================================================
# INSTALAR BADVPN UDPGW
# ============================================================
echo "Instalando BadVPN UDPGW..."

cd /usr/src
if [ ! -d badvpn ]; then
    git clone --quiet https://github.com/ambrop72/badvpn.git 2>/dev/null
    if [ ! -d badvpn ]; then
        echo "⚠ No se pudo clonar badvpn - verificar conexión"
    fi
fi

if [ -d badvpn ]; then
    cd badvpn
    mkdir -p build && cd build

    cmake .. \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_NOTHING_BY_DEFAULT=1 \
        -DBUILD_UDPGW=1 \
        >/dev/null 2>&1

    make -j$(nproc) >/dev/null 2>&1
    make install    >/dev/null 2>&1

    if [ ! -f /usr/bin/badvpn-udpgw ]; then
        echo "⚠ Compilación de BadVPN falló"
    else
        cat > /etc/systemd/system/badvpn-udpgw.service <<'BVEOF'
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=5
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
BVEOF

        systemctl daemon-reload
        systemctl enable badvpn-udpgw >/dev/null 2>&1
        systemctl start  badvpn-udpgw
        sleep 2
        if systemctl is-active --quiet badvpn-udpgw; then
            echo "✓ BadVPN UDPGW activo en UDP 7300"
        else
            echo "⚠ BadVPN no inició - revisar systemctl status badvpn-udpgw"
        fi
    fi
fi

cd /root
