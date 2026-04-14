#!/bin/bash
# mod_ssl.sh - MSY VPN v106
# SSL/TLS: Stunnel mejorado
# FIXES v106:
#   - Bug grupo stunnel4 no creado en Ubuntu 20/22/24/25
#   - systemctl restart stunnel4 falla (active exited) → triple fallback
#   - SSL Remote Proxy: nuevo servicio socat+stunnel en modo CLIENT
#   - SSH Payload SNI: proxy Python con inyección de SNI al handshake SSL
#   - Ubuntu 24/25: socket IPv4 forzado con 0.0.0.0:PUERTO
#   - Certificado renovado, subjectAltName completo

# ============================================================
# DETECCIÓN OS — Ubuntu 20/22/24/25
# ============================================================
OS_VER=$(lsb_release -rs 2>/dev/null \
    || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null \
    || echo "0")
OS_MAJOR=$(echo "$OS_VER" | cut -d. -f1)

# ============================================================
# FUNCIÓN: reinicio robusto de stunnel
# Referencia: github.com/sous-chefs/stunnel issue #87
# init.d es más confiable que systemctl en Ubuntu 18-25
# ============================================================
stunnel_restart() {
    local quiet=${1:-0}

    # 1. Matar proceso real
    pkill -9 -x stunnel4       2>/dev/null
    pkill -9 -f "stunnel4 /etc" 2>/dev/null
    sleep 1

    # 2. Liberar TODOS los puertos del conf
    if [ -f /etc/stunnel/stunnel.conf ]; then
        while IFS= read -r line; do
            puerto=$(echo "$line" | grep -oP ':\K[0-9]+$')
            [ -n "$puerto" ] && fuser -k ${puerto}/tcp 2>/dev/null
        done < <(grep "^accept" /etc/stunnel/stunnel.conf)
    fi
    for p in 443 444 777; do fuser -k ${p}/tcp 2>/dev/null; done
    sleep 1

    # 3. Asegurar directorio PID con permisos correctos
    mkdir -p /var/run/stunnel4
    if getent group stunnel4 >/dev/null 2>&1; then
        chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null
    else
        chown nobody:nogroup /var/run/stunnel4 2>/dev/null
    fi
    chmod 755 /var/run/stunnel4

    # 4. Primer intento: init.d (más confiable en Ubuntu 18-25)
    if [ -f /etc/init.d/stunnel4 ]; then
        /etc/init.d/stunnel4 stop  2>/dev/null
        sleep 1
        /etc/init.d/stunnel4 start 2>/dev/null
        sleep 2
    fi

    # 5. Segundo intento: systemctl
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null
        systemctl restart stunnel4 2>/dev/null
        sleep 2
    fi

    # 6. Último recurso: invocar el binario directamente
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        /usr/bin/stunnel4 /etc/stunnel/stunnel.conf 2>/dev/null &
        sleep 2
    fi

    if pgrep -x stunnel4 >/dev/null 2>&1; then
        [ "$quiet" = "0" ] && echo "✓ Stunnel activo (PID: $(pgrep -x stunnel4 | head -1))"
        return 0
    else
        [ "$quiet" = "0" ] && echo "✗ Stunnel no pudo iniciar"
        return 1
    fi
}

# ============================================================
# INSTALAR STUNNEL + SOCAT
# ============================================================
echo "Configurando Stunnel SSL..."

DEBIAN_FRONTEND=noninteractive apt-get install -y -q stunnel4 socat 2>/dev/null

# FIX: crear grupo/usuario stunnel4 si faltó durante la instalación
# (bug documentado en Ubuntu 20/22/24/25 cuando dbus no responde al postinst)
if ! getent group stunnel4 >/dev/null 2>&1; then
    echo "  Creando grupo stunnel4 (fix compatibilidad Ubuntu $OS_VER)..."
    groupadd --system stunnel4 2>/dev/null || true
fi
if ! getent passwd stunnel4 >/dev/null 2>&1; then
    echo "  Creando usuario stunnel4 (fix compatibilidad Ubuntu $OS_VER)..."
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid stunnel4 stunnel4 2>/dev/null || true
fi

mkdir -p /var/run/stunnel4 /var/log/stunnel4
if getent passwd stunnel4 >/dev/null 2>&1; then
    chown -R stunnel4:stunnel4 /var/run/stunnel4 /var/log/stunnel4 2>/dev/null
else
    chown -R nobody:nogroup   /var/run/stunnel4 /var/log/stunnel4 2>/dev/null
fi
chmod 755 /var/run/stunnel4

# ============================================================
# CERTIFICADO SSL AUTOFIRMADO (10 años)
# Incluye subjectAltName requerido por Ubuntu 24/25 OpenSSL 3.x
# ============================================================
cat > /tmp/openssl-stunnel.cnf <<'SSLCONF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[dn]
C  = US
ST = California
L  = Los Angeles
O  = MSY-VPN
CN = msyvpn.server

[v3_ca]
subjectAltName     = @alt_names
keyUsage           = digitalSignature, keyEncipherment
extendedKeyUsage   = serverAuth, clientAuth
basicConstraints   = CA:FALSE

[alt_names]
DNS.1 = localhost
DNS.2 = *.msyvpn.com
DNS.3 = msyvpn.server
IP.1  = 127.0.0.1
SSLCONF

openssl req -new -x509 -days 3650 -nodes \
    -config /tmp/openssl-stunnel.cnf \
    -keyout /etc/stunnel/stunnel.key \
    -out    /etc/stunnel/stunnel.crt >/dev/null 2>&1

cat /etc/stunnel/stunnel.crt /etc/stunnel/stunnel.key > /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.pem /etc/stunnel/stunnel.key
chmod 644 /etc/stunnel/stunnel.crt
rm -f /tmp/openssl-stunnel.cnf
echo "✓ Certificado SSL generado (10 años)"

# ============================================================
# CONFIGURACIÓN STUNNEL PRINCIPAL (modo SERVER)
#
# NOTA Ubuntu 24/25 dual-stack:
#   accept = 0.0.0.0:PUERTO  ← fuerza IPv4 explícitamente
#   Sin el 0.0.0.0 stunnel en Ubuntu 24/25 intenta bind en IPv6
#   primero y falla en sistemas con net.ipv6.bindv6only=1.
#
# setuid/setgid OMITIDOS — causan fallo en Ubuntu 20-25 cuando
# el grupo stunnel4 no fue creado por el postinst del paquete.
# ============================================================
cat > /etc/stunnel/stunnel.conf <<'STUNNELCONF'
; MSY VPN - Stunnel SSL/TLS v106
; Compatible Ubuntu 20.04 / 22.04 / 24.04 / 25.04 x86_64

foreground = no
pid        = /var/run/stunnel4/stunnel.pid

socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1

TIMEOUTclose   = 3
TIMEOUTidle    = 86400
TIMEOUTbusy    = 300
TIMEOUTconnect = 15

; TLS: solo TLS 1.2 y 1.3 (compatible HTTP Injector, NapsternetV, v2rayNG)
sslVersion = all
options    = NO_SSLv2
options    = NO_SSLv3
options    = NO_TLSv1
options    = NO_TLSv1_1
options    = CIPHER_SERVER_PREFERENCE
options    = NO_COMPRESSION

ciphers = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384:HIGH:!aNULL:!eNULL:!EXPORT:!MD5:!RC4

; ── Puerto 443 → Dropbear :143 (PRINCIPAL) ─────────────────
[dropbear-ssl-443]
client      = no
accept      = 0.0.0.0:443
connect     = 127.0.0.1:143
cert        = /etc/stunnel/stunnel.pem
verify      = 0
TIMEOUTidle = 86400

; ── Puerto 444 → OpenSSH :22 ───────────────────────────────
[openssh-ssl-444]
client      = no
accept      = 0.0.0.0:444
connect     = 127.0.0.1:22
cert        = /etc/stunnel/stunnel.pem
verify      = 0
TIMEOUTidle = 86400

; ── Puerto 777 → Dropbear :143 (alternativo) ───────────────
[dropbear-ssl-777]
client      = no
accept      = 0.0.0.0:777
connect     = 127.0.0.1:143
cert        = /etc/stunnel/stunnel.pem
verify      = 0
TIMEOUTidle = 86400
STUNNELCONF

echo "ENABLED=1"                     > /etc/default/stunnel4
echo 'FILES="/etc/stunnel/*.conf"'  >> /etc/default/stunnel4

systemctl daemon-reload 2>/dev/null
systemctl enable stunnel4 2>/dev/null

stunnel_restart

if pgrep -x stunnel4 >/dev/null 2>&1; then
    echo "✓ Stunnel activo en puertos 443, 444, 777"
else
    echo "⚠ Stunnel no inició — diagnóstico:"
    timeout 3 /usr/bin/stunnel4 /etc/stunnel/stunnel.conf 2>&1 | head -20 || true
    echo ""
    echo "  Comandos de diagnóstico:"
    echo "    stunnel4 /etc/stunnel/stunnel.conf"
    echo "    journalctl -u stunnel4 --no-pager | tail -30"
fi

# ============================================================
# SSL REMOTE PROXY
# Permite que el cliente se conecte a un servidor SSL externo
# y se tunelice a través de él hacia Dropbear/SSH local.
# Modo: CLIENT stunnel → servidor SSL remoto → Dropbear local
#
# Archivo de config separado para no mezclar con el server:
#   /etc/stunnel/ssl-remote.conf
# Servicio: ssl-remote-proxy (systemd independiente de stunnel4)
# ============================================================
echo ""
echo "Configurando SSL Remote Proxy..."

mkdir -p /etc/stunnel /etc/ssh-vpn

cat > /usr/local/bin/ssl-remote-proxy-start.sh <<'SRLSCRIPT'
#!/bin/bash
# Inicia stunnel en modo CLIENT para SSL Remote Proxy
# Uso: ssl-remote-proxy-start.sh <servidor_remoto> <puerto_remoto> <sni> <puerto_local_salida> <puerto_ssh_destino>

REMOTE_HOST="${1:-}"
REMOTE_PORT="${2:-443}"
SNI_HOST="${3:-$REMOTE_HOST}"
LOCAL_OUT_PORT="${4:-2443}"   # puerto local donde stunnel_client escucha
SSH_DEST_PORT="${5:-143}"     # al que se conecta después (Dropbear)

[ -z "$REMOTE_HOST" ] && echo "✗ Falta servidor remoto" && exit 1

# Configurar stunnel CLIENT
cat > /etc/stunnel/ssl-remote.conf <<CONF
; MSY VPN - SSL Remote Proxy (CLIENT MODE)
foreground = no
pid        = /var/run/stunnel4/ssl-remote.pid

socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1

TIMEOUTidle    = 86400
TIMEOUTconnect = 15

[ssl-remote-client]
client      = yes
accept      = 127.0.0.1:${LOCAL_OUT_PORT}
connect     = ${REMOTE_HOST}:${REMOTE_PORT}
sni         = ${SNI_HOST}
verify      = 0
TIMEOUTidle = 86400
CONF

# Guardar config para restaurar al reinicio
cat > /etc/ssh-vpn/ssl-remote.env <<ENV
REMOTE_HOST="${REMOTE_HOST}"
REMOTE_PORT="${REMOTE_PORT}"
SNI_HOST="${SNI_HOST}"
LOCAL_OUT_PORT="${LOCAL_OUT_PORT}"
SSH_DEST_PORT="${SSH_DEST_PORT}"
ENV

# Matar instancia anterior de ssl-remote
pkill -f "stunnel4 /etc/stunnel/ssl-remote.conf" 2>/dev/null
fuser -k ${LOCAL_OUT_PORT}/tcp 2>/dev/null
sleep 1

/usr/bin/stunnel4 /etc/stunnel/ssl-remote.conf 2>/dev/null
sleep 2

if pgrep -f "ssl-remote.conf" >/dev/null 2>&1; then
    echo "✓ SSL Remote Proxy activo:"
    echo "  Cliente → 127.0.0.1:${LOCAL_OUT_PORT} → SSL → ${REMOTE_HOST}:${REMOTE_PORT} (SNI: ${SNI_HOST})"
    echo "  Para conectar SSH usa: ssh usuario@127.0.0.1 -p ${LOCAL_OUT_PORT}"
    exit 0
else
    echo "✗ SSL Remote Proxy no inició"
    timeout 3 /usr/bin/stunnel4 /etc/stunnel/ssl-remote.conf 2>&1
    exit 1
fi
SRLSCRIPT
chmod +x /usr/local/bin/ssl-remote-proxy-start.sh

cat > /usr/local/bin/ssl-remote-proxy-stop.sh <<'SRLSTOP'
#!/bin/bash
pkill -f "stunnel4 /etc/stunnel/ssl-remote.conf" 2>/dev/null
[ -f /etc/ssh-vpn/ssl-remote.env ] && source /etc/ssh-vpn/ssl-remote.env
[ -n "$LOCAL_OUT_PORT" ] && fuser -k ${LOCAL_OUT_PORT}/tcp 2>/dev/null
rm -f /etc/stunnel/ssl-remote.conf
echo "✓ SSL Remote Proxy detenido"
SRLSTOP
chmod +x /usr/local/bin/ssl-remote-proxy-stop.sh

# Servicio systemd para SSL Remote (se activa solo si hay config guardada)
cat > /etc/systemd/system/ssl-remote-proxy.service <<'SRLSVC'
[Unit]
Description=MSY VPN - SSL Remote Proxy (Client Mode)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/ssh-vpn/ssl-remote.env

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'source /etc/ssh-vpn/ssl-remote.env && /usr/local/bin/ssl-remote-proxy-start.sh "$REMOTE_HOST" "$REMOTE_PORT" "$SNI_HOST" "$LOCAL_OUT_PORT" "$SSH_DEST_PORT"'
ExecStop=/usr/local/bin/ssl-remote-proxy-stop.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SRLSVC

systemctl daemon-reload
systemctl enable ssl-remote-proxy 2>/dev/null
echo "✓ SSL Remote Proxy instalado (activar desde menú → Opción 5)"

# ============================================================
# SSH PAYLOAD SNI PROXY
# Proxy Python que hace handshake SSL con SNI personalizado
# y luego inyecta el payload HTTP antes de tunelizar SSH.
#
# Flujo: App VPN → :PUERTO_LOCAL → [SSL handshake con SNI] →
#        servidor remoto → [payload HTTP CONNECT] → SSH/Dropbear
#
# Diferencia con SSL Remote Proxy:
#   - SSL Remote: usa stunnel binario (más estable, sin payload)
#   - SSH Payload SNI: proxy Python (soporta payload personalizado)
# ============================================================
echo ""
echo "Instalando SSH Payload SNI Proxy..."

cat > /etc/proxy-python/proxy_sni.py <<'SNIEOF'
#!/usr/bin/env python3
"""
MSY VPN - SSH Payload SNI Proxy v106
Conecta via SSL/TLS con SNI personalizado + payload HTTP inyectado
Compatible Ubuntu 20/22/24/25

Uso: proxy_sni.py <local_port> <remote_host> <remote_port> <sni_host> <payload> [ssh_dest_port]

Payload soporta variables:
  [host]       → hostname destino
  [port]       → puerto destino
  [host_port]  → host:puerto
  [crlf]       → \r\n
"""
import socket, ssl, threading, select, sys, re, time, logging, signal, os

logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('msy-sni-proxy')

LOCAL_ADDR    = '0.0.0.0'
BUFLEN        = 65536
TIMEOUT_IDLE  = 120
TIMEOUT_CONN  = 15

def parse_payload(payload, host, port):
    """Reemplaza variables BBCode en el payload."""
    replacements = {
        '[host]':      host,
        '[port]':      str(port),
        '[host_port]': f'{host}:{port}',
        '[method]':    'CONNECT',
        '[protocol]':  'HTTP/1.0',
        '[crlf]':      '\r\n',
        '[cr]':        '\r',
        '[lf]':        '\n',
        '\\r\\n':      '\r\n',
        '\\n':         '\n',
        '\\r':         '\r',
    }
    for k, v in replacements.items():
        payload = payload.replace(k, v)
    return payload

def make_default_payload(host, port):
    return f"CONNECT {host}:{port} HTTP/1.0\r\nHost: {host}:{port}\r\n\r\n"

def apply_socket_opts(s):
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass

def close_socket(s):
    if s is None: return
    try: s.shutdown(socket.SHUT_RDWR)
    except: pass
    try: s.close()
    except: pass

def tunnel(a, b):
    """Forward bidireccional entre dos sockets."""
    sockets = [a, b]
    try:
        while True:
            try:
                r, _, e = select.select(sockets, [], sockets, TIMEOUT_IDLE)
            except (ValueError, OSError):
                break
            if e or not r:
                break
            for s in r:
                try:
                    d = s.recv(BUFLEN)
                except OSError:
                    return
                if not d:
                    return
                other = b if s is a else a
                try:
                    other.sendall(d)
                except OSError:
                    return
    except Exception:
        pass

class SNIProxyHandler(threading.Thread):
    def __init__(self, client, remote_host, remote_port, sni_host, payload, ssh_dest_port):
        super().__init__(daemon=True)
        self.client        = client
        self.remote_host   = remote_host
        self.remote_port   = remote_port
        self.sni_host      = sni_host or remote_host
        self.payload_tmpl  = payload
        self.ssh_dest_port = ssh_dest_port
        self.remote        = None

    def run(self):
        try:
            apply_socket_opts(self.client)

            # Leer la primera línea del cliente (puede ser SSH banner, CONNECT, GET, etc.)
            self.client.settimeout(10)
            header_data = b''
            try:
                while b'\r\n\r\n' not in header_data and b'\n' not in header_data[:8]:
                    chunk = self.client.recv(4096)
                    if not chunk: break
                    header_data += chunk
                    if len(header_data) > 16384: break
            except OSError:
                pass
            self.client.settimeout(None)

            # Conectar al servidor remoto con SSL + SNI
            self._connect_ssl()
            if self.remote is None:
                return

            # Construir payload
            final_payload = self._make_payload()

            # Enviar payload al servidor remoto
            try:
                self.remote.sendall(final_payload.encode('ISO-8859-1', errors='replace'))
            except Exception as e:
                log.error("Error enviando payload: %s", e)
                return

            # Leer respuesta del servidor remoto (esperar 200 o 101)
            resp = b''
            try:
                self.remote.settimeout(TIMEOUT_CONN)
                while b'\r\n\r\n' not in resp:
                    chunk = self.remote.recv(4096)
                    if not chunk: break
                    resp += chunk
                    if len(resp) > 8192: break
                self.remote.settimeout(None)
            except OSError:
                self.remote.settimeout(None)

            resp_str = resp.decode('ISO-8859-1', errors='ignore')
            log.debug("Respuesta servidor: %s", resp_str[:100])

            # Verificar que el túnel fue aceptado
            if not any(code in resp_str for code in ['200', '101', 'Connection established', 'Switching Protocols']):
                log.error("Servidor rechazó el túnel: %s", resp_str[:80])
                # Intentar de todas formas — algunos servidores mandan respuestas no estándar
                if 'HTTP/' not in resp_str:
                    log.error("Respuesta no HTTP, abortando")
                    return

            # Si el cliente envió datos (SSH banner, etc.), reenviarlos al remoto
            if header_data:
                try:
                    self.remote.sendall(header_data)
                except OSError:
                    return

            # Responder al cliente local que el túnel está listo (si usó HTTP CONNECT)
            first_line = header_data[:200].decode('ISO-8859-1', errors='ignore')
            if first_line.startswith('CONNECT '):
                try:
                    self.client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                except OSError:
                    return

            # Tunelizar
            tunnel(self.client, self.remote)

        except Exception as e:
            log.error("Handler error: %s", e)
        finally:
            close_socket(self.client)
            close_socket(self.remote)

    def _connect_ssl(self):
        try:
            raw = socket.create_connection((self.remote_host, self.remote_port), timeout=TIMEOUT_CONN)
            apply_socket_opts(raw)

            # Crear contexto SSL — no verificar certificado (igual que los clientes VPN)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            # Habilitar TLS 1.2 y 1.3
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            except AttributeError:
                pass

            # Wrap con SNI
            ssl_sock = ctx.wrap_socket(raw, server_hostname=self.sni_host)
            ssl_sock.settimeout(None)
            self.remote = ssl_sock

        except Exception as e:
            log.error("SSL connect error (%s:%d SNI=%s): %s",
                      self.remote_host, self.remote_port, self.sni_host, e)
            self.remote = None

    def _make_payload(self):
        if self.payload_tmpl:
            return parse_payload(self.payload_tmpl, self.remote_host, self.ssh_dest_port)
        return make_default_payload(self.remote_host, self.ssh_dest_port)


class SNIProxyServer:
    def __init__(self, local_port, remote_host, remote_port, sni_host, payload, ssh_dest_port):
        self.local_port    = local_port
        self.remote_host   = remote_host
        self.remote_port   = remote_port
        self.sni_host      = sni_host or remote_host
        self.payload       = payload
        self.ssh_dest_port = ssh_dest_port
        self._srv = None

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((LOCAL_ADDR, self.local_port))
        except OSError as e:
            print(f"✗ No se puede abrir :{self.local_port} — {e}")
            sys.exit(1)
        srv.listen(500)
        self._srv = srv

        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT,  self._shutdown)

        print(f"✓ SSH Payload SNI Proxy activo en :{self.local_port}")
        print(f"  → SSL {self.remote_host}:{self.remote_port} (SNI: {self.sni_host})")

        while True:
            try:
                c, _ = srv.accept()
                SNIProxyHandler(c, self.remote_host, self.remote_port,
                                self.sni_host, self.payload, self.ssh_dest_port).start()
            except (KeyboardInterrupt, SystemExit):
                break
            except OSError:
                time.sleep(0.1)

    def _shutdown(self, *_):
        if self._srv:
            try: self._srv.close()
            except: pass
        sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("Uso: proxy_sni.py <local_port> <remote_host> <remote_port> <sni_host> [payload] [ssh_dest_port]")
        sys.exit(1)

    local_port    = int(sys.argv[1])
    remote_host   = sys.argv[2]
    remote_port   = int(sys.argv[3])
    sni_host      = sys.argv[4]
    payload       = sys.argv[5] if len(sys.argv) > 5 else ""
    ssh_dest_port = int(sys.argv[6]) if len(sys.argv) > 6 else 143

    SNIProxyServer(local_port, remote_host, remote_port, sni_host, payload, ssh_dest_port).start()
SNIEOF

chmod +x /etc/proxy-python/proxy_sni.py
echo "✓ SSH Payload SNI Proxy instalado (/etc/proxy-python/proxy_sni.py)"

# Guardar funciones extras para ssh-vpn-functions.sh
cat > /tmp/stunnel_extra_functions.sh <<'EXTRAFUNC'

# -----------------------------------------------------------
# stunnel_restart_menu: wrapper para llamadas desde el menú
# -----------------------------------------------------------
stunnel_restart() {
    local quiet=${1:-0}
    pkill -9 -x stunnel4        2>/dev/null
    pkill -9 -f "stunnel4 /etc" 2>/dev/null
    sleep 1
    if [ -f /etc/stunnel/stunnel.conf ]; then
        while IFS= read -r line; do
            local p; p=$(echo "$line" | grep -oP ':\K[0-9]+$')
            [ -n "$p" ] && fuser -k ${p}/tcp 2>/dev/null
        done < <(grep "^accept" /etc/stunnel/stunnel.conf)
    fi
    for p in 443 444 777; do fuser -k ${p}/tcp 2>/dev/null; done
    sleep 1
    mkdir -p /var/run/stunnel4
    if getent group stunnel4 >/dev/null 2>&1; then
        chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null
    else
        chown nobody:nogroup /var/run/stunnel4 2>/dev/null
    fi
    chmod 755 /var/run/stunnel4
    if [ -f /etc/init.d/stunnel4 ]; then
        /etc/init.d/stunnel4 stop 2>/dev/null; sleep 1
        /etc/init.d/stunnel4 start 2>/dev/null; sleep 2
    fi
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null
        systemctl restart stunnel4 2>/dev/null; sleep 2
    fi
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        /usr/bin/stunnel4 /etc/stunnel/stunnel.conf 2>/dev/null &; sleep 2
    fi
    pgrep -x stunnel4 >/dev/null 2>&1 \
        && { [ "$quiet" = "0" ] && echo "✓ Stunnel activo"; return 0; } \
        || { [ "$quiet" = "0" ] && echo "✗ Stunnel no pudo iniciar"; return 1; }
}

# -----------------------------------------------------------
# ssl_remove_port: elimina un túnel del conf por número de puerto
# -----------------------------------------------------------
ssl_remove_port() {
    local target_port=$1
    local conf=/etc/stunnel/stunnel.conf
    [ -z "$target_port" ] && echo "✗ Indica el puerto a eliminar" && return 1
    local section
    section=$(awk -v port=":${target_port}" '
        /^\[/ { sec=substr($0,2,length($0)-2) }
        /^accept/ && index($0, port) { print sec; exit }
    ' "$conf")
    [ -z "$section" ] && echo "✗ No se encontró túnel en puerto $target_port" && return 1
    python3 - "$conf" "$section" "$target_port" <<'PYREMOVE'
import sys, re
conf_path, section, port = sys.argv[1], sys.argv[2], sys.argv[3]
with open(conf_path, 'r') as f:
    content = f.read()
pattern = r'\n\[' + re.escape(section) + r'\].*?(?=\n\[|\Z)'
new_content = re.sub(pattern, '', content, flags=re.DOTALL)
with open(conf_path, 'w') as f:
    f.write(new_content)
print(f"✓ Túnel [{section}] (puerto {port}) eliminado")
PYREMOVE
    stunnel_restart
}

# -----------------------------------------------------------
# ssl_add_port: agrega un nuevo túnel al conf
# -----------------------------------------------------------
ssl_add_port() {
    local nombre=$1 entrada=$2 destino=$3
    local conf=/etc/stunnel/stunnel.conf
    if grep -q ":${entrada}$" "$conf" 2>/dev/null; then
        echo "✗ Puerto $entrada ya en uso en stunnel"; return 1
    fi
    cat >> "$conf" <<TUNNEL

[${nombre}]
client      = no
accept      = 0.0.0.0:${entrada}
connect     = 127.0.0.1:${destino}
cert        = /etc/stunnel/stunnel.pem
verify      = 0
TIMEOUTidle = 86400
TUNNEL
    echo "✓ Túnel [${nombre}] puerto $entrada → $destino agregado"
    stunnel_restart
}

# -----------------------------------------------------------
# start_sni_proxy: inicia SSH Payload SNI Proxy
# Uso: start_sni_proxy <local_port> <remote_host> <remote_port> <sni_host> [payload] [ssh_port]
# -----------------------------------------------------------
start_sni_proxy() {
    local local_port=$1
    local remote_host=$2
    local remote_port=${3:-443}
    local sni_host=${4:-$remote_host}
    local payload=${5:-""}
    local ssh_port=${6:-143}

    [ -z "$local_port" ] || [ -z "$remote_host" ] && \
        echo "✗ Uso: start_sni_proxy <local_port> <remote_host> <remote_port> <sni_host> [payload] [ssh_port]" && return 1

    # Limpiar si existe
    if screen -list 2>/dev/null | grep -q "sni-$local_port"; then
        screen -X -S "sni-$local_port" quit 2>/dev/null
        fuser -k ${local_port}/tcp 2>/dev/null
        sleep 1
    fi

    screen -dmS "sni-$local_port" python3 /etc/proxy-python/proxy_sni.py \
        "$local_port" "$remote_host" "$remote_port" "$sni_host" \
        "$payload" "$ssh_port"
    sleep 1

    if screen -list 2>/dev/null | grep -q "sni-$local_port"; then
        echo "✓ SNI Proxy :$local_port → SSL $remote_host:$remote_port (SNI: $sni_host)"
        # Guardar en conf
        sed -i "/^SNI_${local_port}|/d" /etc/proxy-python/sni-proxies.conf 2>/dev/null
        echo "SNI_${local_port}|${local_port}|${remote_host}|${remote_port}|${sni_host}|${payload}|${ssh_port}" \
            >> /etc/proxy-python/sni-proxies.conf
    else
        echo "✗ Error al iniciar SNI Proxy en puerto $local_port"
    fi
}

stop_sni_proxy() {
    local port=$1
    screen -X -S "sni-$port" quit 2>/dev/null
    pkill -f "proxy_sni.py $port " 2>/dev/null
    fuser -k ${port}/tcp 2>/dev/null
    sed -i "/^SNI_${port}|/d" /etc/proxy-python/sni-proxies.conf 2>/dev/null
    echo "✓ SNI Proxy :$port detenido"
}

restore_sni_proxies() {
    [ ! -f /etc/proxy-python/sni-proxies.conf ] && return
    while IFS='|' read -r _tag local_port remote_host remote_port sni_host payload ssh_port; do
        [ -z "$local_port" ] && continue
        screen -list 2>/dev/null | grep -q "sni-$local_port" && continue
        start_sni_proxy "$local_port" "$remote_host" "$remote_port" \
                        "$sni_host" "$payload" "$ssh_port"
    done < /etc/proxy-python/sni-proxies.conf
}

# -----------------------------------------------------------
# ssl_remote_start: inicia SSL Remote Proxy (stunnel CLIENT)
# Uso: ssl_remote_start <remote_host> <remote_port> <sni> [local_port] [ssh_port]
# -----------------------------------------------------------
ssl_remote_start() {
    local remote_host=$1
    local remote_port=${2:-443}
    local sni_host=${3:-$remote_host}
    local local_port=${4:-2443}
    local ssh_port=${5:-143}

    [ -z "$remote_host" ] && \
        echo "✗ Uso: ssl_remote_start <remote_host> [remote_port] [sni] [local_port] [ssh_port]" && return 1

    /usr/local/bin/ssl-remote-proxy-start.sh \
        "$remote_host" "$remote_port" "$sni_host" "$local_port" "$ssh_port"
}

ssl_remote_stop() {
    /usr/local/bin/ssl-remote-proxy-stop.sh
}

EXTRAFUNC
