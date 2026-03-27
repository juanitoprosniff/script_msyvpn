#!/bin/bash
# Script MSY By JuanitoProSniff
# Canal: t.me/FREEINTERNETVPNMSY
# Version: 104 - Minimalista

clear
echo "=========================================="
echo "   Instalando Script MSY VPN"
echo "=========================================="
echo ""

# Verificar root
if [[ $EUID -ne 0 ]]; then
   echo "Este script debe ejecutarse como root"
   exit 1
fi

# Colores
cor='\033[1;32m'
red='\033[1;31m'
yellow='\033[1;33m'
off='\033[0m'

# Detener servicios previos
pkill -9 -f "proxy-python" 2>/dev/null
pkill -9 -f "badvpn-udpgw" 2>/dev/null
systemctl stop dropbear-legacy 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop ssh 2>/dev/null

# Detectar arquitectura
ARCH=$(uname -m)
OS_VER=$(lsb_release -rs 2>/dev/null || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null || echo "unknown")
echo "Sistema detectado: Ubuntu $OS_VER | Arquitectura: $ARCH"

# Actualizar sistema
echo "Actualizando sistema..."
apt-get update -y -q
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -q

# Instalar dependencias
echo "Instalando dependencias..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    python3 openssh-server stunnel4 screen lsof curl wget nano \
    net-tools cmake build-essential git zlib1g-dev

# Crear directorios
mkdir -p /etc/proxy-python
mkdir -p /etc/ssh-vpn/users
mkdir -p /etc/dropbear-legacy
mkdir -p /opt/dropbear-2016

# ====================
# CONFIGURAR SWAP 2GB
# ====================
echo "Configurando Swap de 2GB..."

if [ ! -f /swapfile ]; then
    dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile

    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi

    sysctl -w vm.swappiness=11 >/dev/null 2>&1
    if ! grep -q 'vm.swappiness' /etc/sysctl.conf; then
        echo "vm.swappiness=11" >> /etc/sysctl.conf
    fi
    echo "✓ Swap de 2GB configurado"
else
    echo "✓ Swap ya existe"
fi

# ====================
# OPENSSH (PUERTO 22)
# ====================
echo "Configurando OpenSSH en puerto 22..."

cat > /etc/ssh/banner.txt <<'EOF'
═══════════════════════════
t.me/FREEINTERNETVPNMSY
═══════════════════════════
EOF

cat > /etc/ssh/sshd_config <<'EOF'
Port 22
AddressFamily any
ListenAddress 0.0.0.0
Banner /etc/ssh/banner.txt
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
PrintMotd no
PrintLastLog yes
X11Forwarding yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 120
ClientAliveCountMax 3
TCPKeepAlive yes
MaxStartups 100:30:200
MaxSessions 100
Compression no
EOF

systemctl enable ssh >/dev/null 2>&1
systemctl restart ssh

# ====================
# COMPILAR DROPBEAR 2016.74 - PUERTO 143
# ====================
echo "=========================================="
echo "Compilando Dropbear 2016.74 desde fuente..."
echo "Arquitectura: $ARCH"
echo "=========================================="
cd /usr/src

if [ ! -f dropbear-2016.74.tar.bz2 ]; then
    echo "Descargando Dropbear 2016.74..."
    wget -q https://github.com/juanitoprosniff/script_msyvpn/raw/refs/heads/main/installer/dropbear-2016.74.tar.bz2
fi

echo "Extrayendo..."
rm -rf dropbear-2016.74 2>/dev/null
tar xjf dropbear-2016.74.tar.bz2
cd dropbear-2016.74

# Modificar identificador SSH
if [ -f sysoptions.h ]; then
    sed -i 's|^#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' sysoptions.h 2>/dev/null || true
elif [ -f default_options.h ]; then
    sed -i 's/#define LOCAL_IDENT "SSH-2.0-dropbear_" DROPBEAR_VERSION/#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"/' default_options.h 2>/dev/null || true
fi

./configure --prefix=/opt/dropbear-2016 \
    --disable-zlib \
    --disable-wtmp \
    --disable-lastlog \
    >/dev/null 2>&1

echo "Compilando... (2-3 minutos)"
make -j$(nproc) PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1
make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1

if [ ! -f /opt/dropbear-2016/sbin/dropbear ]; then
    echo "⚠ ERROR: No se pudo compilar Dropbear 2016"
else
    echo "✓ Dropbear 2016.74 compilado"

    # Generar llaves
    if [ ! -f /etc/dropbear-legacy/dropbear_rsa_host_key ]; then
        /opt/dropbear-2016/bin/dropbearkey -t rsa -f /etc/dropbear-legacy/dropbear_rsa_host_key -s 2048 >/dev/null 2>&1
    fi
    if [ ! -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ]; then
        /opt/dropbear-2016/bin/dropbearkey -t ecdsa -f /etc/dropbear-legacy/dropbear_ecdsa_host_key >/dev/null 2>&1
    fi

    # Banner
    cat > /etc/dropbear-legacy/banner.txt <<'EOF'
t.me/FREEINTERNETVPNMSY
EOF

    # Servicio systemd
    cat > /etc/systemd/system/dropbear-legacy.service <<'DBEOF'
[Unit]
Description=Dropbear SSH Legacy 2016.74 - Puerto 143
After=network.target

[Service]
Type=simple
ExecStart=/opt/dropbear-2016/sbin/dropbear -F -E -p 143 \
    -r /etc/dropbear-legacy/dropbear_rsa_host_key \
    -r /etc/dropbear-legacy/dropbear_ecdsa_host_key \
    -b /etc/dropbear-legacy/banner.txt \
    -K 60 -I 300
Restart=always
RestartSec=3
KillMode=process
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
DBEOF

    systemctl daemon-reload
    systemctl enable dropbear-legacy >/dev/null 2>&1
    systemctl start dropbear-legacy
    sleep 2
    echo "✓ Dropbear 2016 activo en puerto 143"
fi

cd /root

# ====================
# STUNNEL (PUERTOS 443, 444, 777)
# ====================
echo "Configurando Stunnel SSL..."

# Generar certificado
cat > /tmp/openssl-stunnel.cnf <<'SSLCONF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[dn]
C=US
ST=California
L=Los Angeles
O=MSY-VPN
CN=*

[v3_ca]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth

[alt_names]
DNS.1 = *
DNS.2 = *.msyvpn.com
DNS.3 = localhost
IP.1 = 127.0.0.1
SSLCONF

openssl req -new -x509 -days 3650 -nodes \
    -config /tmp/openssl-stunnel.cnf \
    -keyout /etc/stunnel/stunnel.key \
    -out /etc/stunnel/stunnel.crt >/dev/null 2>&1

cat /etc/stunnel/stunnel.crt /etc/stunnel/stunnel.key > /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.pem /etc/stunnel/stunnel.key
chmod 644 /etc/stunnel/stunnel.crt
rm -f /tmp/openssl-stunnel.cnf

cat > /etc/stunnel/stunnel.conf <<'EOF'
; STUNNEL SSL/TLS - MSY VPN

foreground = no
pid = /var/run/stunnel4/stunnel.pid
output = /dev/null

socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1

TIMEOUTclose = 1
TIMEOUTidle = 86400
TIMEOUTbusy = 300
TIMEOUTconnect = 30

sslVersion = all
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1
options = CIPHER_SERVER_PREFERENCE

ciphers = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384:HIGH:!aNULL:!eNULL:!EXPORT:!MD5:!RC4

[dropbear-ssl-443]
client = no
accept = 0.0.0.0:443
connect = 127.0.0.1:143
cert = /etc/stunnel/stunnel.pem
verify = 0
TIMEOUTidle = 86400

[openssh-ssl-444]
client = no
accept = 0.0.0.0:444
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
verify = 0
TIMEOUTidle = 86400

[dropbear-ssl-777]
client = no
accept = 0.0.0.0:777
connect = 127.0.0.1:143
cert = /etc/stunnel/stunnel.pem
verify = 0
TIMEOUTidle = 86400
EOF

echo "ENABLED=1" > /etc/default/stunnel4
echo 'FILES="/etc/stunnel/*.conf"' >> /etc/default/stunnel4

mkdir -p /var/run/stunnel4 /var/log/stunnel4
chown -R stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || chown -R nobody:nogroup /var/run/stunnel4
chmod 755 /var/run/stunnel4

systemctl daemon-reload
systemctl enable stunnel4 >/dev/null 2>&1
systemctl restart stunnel4
sleep 2

if systemctl is-active --quiet stunnel4; then
    echo "✓ Stunnel activo (443, 444, 777)"
else
    echo "⚠ Stunnel con problemas - revisar configuración"
fi

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

# ====================
# INSTALAR HYSTERIA UDP
# ====================
echo "Instalando Hysteria UDP Manager..."
wget -q -O install_agnudp.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install_agnudp.sh 2>/dev/null
wget -q -O agnudp_manager.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/agnudp_manager.sh 2>/dev/null

if [ -f install_agnudp.sh ] && [ -f agnudp_manager.sh ]; then
    chmod +x install_agnudp.sh agnudp_manager.sh
    bash install_agnudp.sh 2>/dev/null
    cp agnudp_manager.sh /usr/local/bin/hysteria-manager
    chmod +x /usr/local/bin/hysteria-manager
    echo "✓ Hysteria UDP instalado"
else
    echo "⚠ No se pudo descargar Hysteria UDP"
fi

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

# ====================
# FUNCIONES DEL MENÚ
# ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

# -----------------------------------------------------------
# Estado de un puerto (ON/OFF)
# -----------------------------------------------------------
port_status() {
    local port=$1
    local proto=${2:-tcp}
    if ss -${proto}lnp 2>/dev/null | grep -q ":${port} "; then
        echo -e "${GREEN}ON${NC}"
    else
        echo -e "${RED}OFF${NC}"
    fi
}

# -----------------------------------------------------------
# Listar usuarios conectados
# -----------------------------------------------------------
list_connected_users() {
    echo "═══════════════════════════════════════════════"
    echo "           USUARIOS SSH CONECTADOS"
    echo "═══════════════════════════════════════════════"
    echo ""

    local users
    users=$(who 2>/dev/null | grep -v "^$" | awk '{print $1}' | sort -u)

    if [ -z "$users" ]; then
        echo "  Sin usuarios conectados por SSH"
    else
        local n=1
        while IFS= read -r u; do
            [ -z "$u" ] && continue
            local info
            info=$(who 2>/dev/null | grep "^$u " | head -1 | awk '{print $5}' | tr -d '()')
            echo "  $n) $u  [${info:-conectado}]"
            n=$((n+1))
        done <<< "$users"
    fi
    echo ""
    echo "═══════════════════════════════════════════════"
}

# -----------------------------------------------------------
# Gestión de proxies
# -----------------------------------------------------------
start_proxy() {
    local port=$1 response=$2 banner=$3 ssh_port=${4:-143} save=${5:-1}

    if screen -list 2>/dev/null | grep -q "proxy-$port"; then
        echo "✗ Puerto $port ya en uso"
        return 1
    fi

    screen -dmS "proxy-$port" python3 /etc/proxy-python/proxy.py "$port" "$response" "$banner" "$ssh_port"
    sleep 1

    if screen -list 2>/dev/null | grep -q "proxy-$port"; then
        echo "✓ Proxy :$port → SSH:$ssh_port | $response $banner"
        if [ "$save" = "1" ]; then
            sed -i "/^${port}|/d" /etc/proxy-python/proxies.conf 2>/dev/null
            echo "${port}|${response}|${banner}|${ssh_port}" >> /etc/proxy-python/proxies.conf
        fi
    else
        echo "✗ Error al iniciar proxy en puerto $port"
    fi
}

stop_proxy() {
    local port=$1
    screen -X -S "proxy-$port" quit 2>/dev/null
    pkill -f "proxy.py $port " 2>/dev/null
    local pid
    pid=$(lsof -ti:$port 2>/dev/null)
    [ -n "$pid" ] && kill -9 $pid 2>/dev/null
    sleep 1
    fuser -k $port/tcp 2>/dev/null
    sed -i "/^${port}|/d" /etc/proxy-python/proxies.conf 2>/dev/null
    echo "✓ Proxy :$port detenido"
}

stop_all_proxies() {
    screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}' | xargs -I {} screen -X -S {} quit 2>/dev/null
    pkill -9 -f "proxy.py" 2>/dev/null
    echo "✓ Proxies detenidos"
}

restore_proxies() {
    local conf=/etc/proxy-python/proxies.conf
    if [ ! -f "$conf" ] || [ ! -s "$conf" ]; then
        echo '80|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143'   > "$conf"
        echo '8080|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> "$conf"
        echo '8880|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> "$conf"
        echo '8888|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> "$conf"
    fi
    while IFS='|' read -r port response banner ssh_port; do
        [ -z "$port" ] && continue
        screen -list 2>/dev/null | grep -q "proxy-$port" && continue
        start_proxy "$port" "$response" "$banner" "$ssh_port" "0"
    done < "$conf"
}

restart_proxies() {
    echo "Reiniciando proxies..."
    stop_all_proxies
    sleep 1
    restore_proxies
    echo "✓ Proxies reiniciados"
}

restart_all_services() {
    echo "Reiniciando todos los servicios..."
    systemctl restart ssh       && echo "✓ OpenSSH"       || echo "✗ OpenSSH error"
    systemctl restart dropbear-legacy 2>/dev/null && echo "✓ Dropbear 2016" || echo "✗ Dropbear error"
    systemctl restart stunnel4  && echo "✓ Stunnel"       || echo "✗ Stunnel error"
    systemctl restart badvpn-udpgw && echo "✓ BadVPN"     || echo "✗ BadVPN error"
    restart_proxies
    echo "✓ Listo"
}

FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

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

# Crear conf por defecto
if [ ! -f /etc/proxy-python/proxies.conf ]; then
    echo '80|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143'   > /etc/proxy-python/proxies.conf
    echo '8080|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> /etc/proxy-python/proxies.conf
    echo '8880|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> /etc/proxy-python/proxies.conf
    echo '8888|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> /etc/proxy-python/proxies.conf
fi

# ====================
# SCRIPT MENÚ PRINCIPAL
# ====================
cat > /root/vpn-installer.sh << 'MAINSCRIPT'
#!/bin/bash

if [ ! -f /root/ssh-vpn-functions.sh ]; then
    echo "Error: Archivo de funciones no encontrado"
    exit 1
fi

source /root/ssh-vpn-functions.sh

menu_principal() {
    while true; do
        clear
        IP=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

        # Estados de puertos
        S_SSH=$(port_status 22 t)
        S_DB=$(port_status 143 t)
        S_SSL443=$(port_status 443 t)
        S_SSL444=$(port_status 444 t)
        S_SSL777=$(port_status 777 t)
        S_P80=$(port_status 80 t)
        S_P8080=$(port_status 8080 t)
        S_P8880=$(port_status 8880 t)
        S_P8888=$(port_status 8888 t)
        S_UDP=$(port_status 7300 u)

        echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC}     ${BOLD}MSY VPN PANEL - v104 Minimalista${NC}    ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
        echo -e " ${GREEN}IP:${NC} ${YELLOW}$IP${NC}"
        echo ""
        echo -e " ${CYAN}━━━ PUERTOS ACTIVOS ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  SSH   :22   $S_SSH    │  Dropbear :143  $S_DB"
        echo -e "  SSL   :443  $S_SSL443  │  SSL      :444  $S_SSL444"
        echo -e "  SSL   :777  $S_SSL777  │  UDP/BVPN :7300 $S_UDP"
        echo -e "  Proxy :80   $S_P80    │  Proxy    :8080 $S_P8080"
        echo -e "  Proxy :8880 $S_P8880  │  Proxy    :8888 $S_P8888"
        echo -e " ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e " ${BLUE}1)${NC} Crear usuario       ${BLUE}2)${NC} Eliminar usuario"
        echo -e " ${BLUE}3)${NC} Ver conectados      ${BLUE}4)${NC} Proxies Python"
        echo -e " ${BLUE}5)${NC} Túneles SSL/TLS     ${BLUE}6)${NC} Banner HTTP proxy"
        echo -e " ${BLUE}7)${NC} Banner SSH (DB143)  ${BLUE}8)${NC} Hysteria UDP"
        echo -e " ${BLUE}9)${NC} Estado servicios   ${BLUE}10)${NC} Reiniciar servicios"
        echo -e "${RED}D)${NC} Desinstalar script  ${RED} 0)${NC} Salir"
        echo -e " ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        read -p " Opción: " option

        case $option in
            1)
                clear
                echo "CREAR USUARIO VPN"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario: " username
                read -p "Contraseña: " password
                read -p "Días de validez (0 = ilimitado): " days

                if id "$username" &>/dev/null; then
                    echo "El usuario ya existe"
                    read -p "ENTER para continuar..."
                    continue
                fi

                useradd -m -s /bin/bash "$username"
                echo "$username:$password" | chpasswd

                if [ "$days" -gt 0 ] 2>/dev/null; then
                    expiry=$(date -d "+$days days" +%Y-%m-%d)
                    chage -E "$expiry" "$username"
                else
                    expiry="Ilimitado"
                fi

                cat > /etc/ssh-vpn/users/$username.txt <<USEREOF
Usuario: $username
Contraseña: $password
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: $expiry
Estado: Activo
USEREOF

                echo ""
                echo "✓ Usuario $username creado"
                echo "  Expira: $expiry"
                read -p "ENTER para continuar..."
                ;;
            2)
                clear
                echo "ELIMINAR USUARIO"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario a eliminar: " username

                if ! id "$username" &>/dev/null; then
                    echo "El usuario no existe"
                    read -p "ENTER para continuar..."
                    continue
                fi

                pkill -9 -u "$username" 2>/dev/null
                userdel -r "$username" 2>/dev/null
                rm -f /etc/ssh-vpn/users/$username.txt

                echo "✓ Usuario $username eliminado"
                read -p "ENTER para continuar..."
                ;;
            3)
                clear
                list_connected_users
                read -p "ENTER para continuar..."
                ;;
            4)
                clear
                echo "PROXIES PYTHON"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Nuevo proxy"
                echo "2) Detener todos"
                echo "3) Ver activos"
                echo "4) Detener proxy individual"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " proxy_opt

                case $proxy_opt in
                    1)
                        read -p "Puerto (ej: 8081): " port
                        read -p "Response code (ej: 101): " response
                        read -p "Banner text [HTML o texto]: " banner
                        banner=${banner:-'<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>'}
                        echo ""
                        echo "Backend SSH destino:"
                        echo "  1) 22  - OpenSSH"
                        echo "  2) 143 - Dropbear 2016 (recomendado)"
                        echo "  3) Otro puerto"
                        read -p "Opción [2]: " be_opt
                        case ${be_opt:-2} in
                            1) ssh_port=22 ;;
                            2) ssh_port=143 ;;
                            3) read -p "Puerto: " ssh_port ;;
                            *) ssh_port=143 ;;
                        esac
                        start_proxy "$port" "$response" "$banner" "$ssh_port"
                        read -p "ENTER..."
                        ;;
                    2)
                        stop_all_proxies
                        read -p "ENTER..."
                        ;;
                    3)
                        echo "PROXIES ACTIVOS:"
                        screen -ls 2>/dev/null | grep "proxy-" | awk -F'.' '{print $2}' | while read n; do
                            port=$(echo $n | sed 's/proxy-//')
                            cfg=$(grep "^${port}|" /etc/proxy-python/proxies.conf 2>/dev/null)
                            echo "  :$port — ${cfg:-sin config}"
                        done
                        screen -ls 2>/dev/null | grep -q "proxy-" || echo "  Ninguno activo"
                        echo ""
                        echo "Config guardada:"
                        cat /etc/proxy-python/proxies.conf 2>/dev/null || echo "  Sin config"
                        read -p "ENTER..."
                        ;;
                    4)
                        echo "Proxies activos:"
                        screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}'
                        echo ""
                        read -p "Puerto a detener: " del_port
                        [ -n "$del_port" ] && stop_proxy "$del_port"
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            5)
                clear
                echo "TÚNELES SSL/TLS (Stunnel)"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Ver túneles activos"
                echo "2) Agregar nuevo túnel"
                echo "3) Reiniciar Stunnel"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " tunnel_opt

                case $tunnel_opt in
                    1)
                        clear
                        echo "TÚNELES SSL ACTIVOS:"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        grep -E '\[|accept|connect' /etc/stunnel/stunnel.conf
                        echo ""
                        echo "Puertos escuchando:"
                        ss -tlnp | grep stunnel
                        read -p "ENTER..."
                        ;;
                    2)
                        clear
                        echo "AGREGAR NUEVO TÚNEL"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        read -p "Nombre del túnel (ej: tunnel-8443): " tunnel_name
                        read -p "Puerto de escucha (ej: 8443): " tunnel_port
                        echo "Backend destino:"
                        echo "  22  - OpenSSH"
                        echo "  143 - Dropbear 2016 (recomendado)"
                        read -p "Puerto destino [143]: " tunnel_dest
                        tunnel_dest=${tunnel_dest:-143}

                        cat >> /etc/stunnel/stunnel.conf <<TUNNELEOF

[$tunnel_name]
client = no
accept = 0.0.0.0:$tunnel_port
connect = 127.0.0.1:$tunnel_dest
cert = /etc/stunnel/stunnel.pem
verify = 0
TUNNELEOF

                        systemctl restart stunnel4
                        echo "✓ Túnel $tunnel_name en puerto $tunnel_port → $tunnel_dest"
                        read -p "ENTER..."
                        ;;
                    3)
                        systemctl restart stunnel4 && echo "✓ Stunnel reiniciado" || echo "✗ Error"
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            6)
                clear
                echo "BANNER HTTP PROXY"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Banner actual:"
                grep "BANNER_TEXT = " /etc/proxy-python/proxy.py
                echo ""
                read -p "Nuevo texto [HTML o texto simple]: " new_banner
                new_banner=${new_banner:-'<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>'}
                sed -i "s/BANNER_TEXT = .*/BANNER_TEXT = '$new_banner'/" /etc/proxy-python/proxy.py
                echo "✓ Banner actualizado"
                echo "→ Reinicia proxies desde Opción 10"
                read -p "ENTER para continuar..."
                ;;
            7)
                clear
                echo "BANNER DROPBEAR 2016 (Puerto 143)"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Banner actual:"
                cat /etc/dropbear-legacy/banner.txt 2>/dev/null || echo "(vacío)"
                echo ""
                echo "Nuevo banner (multilínea - escribe FIN para terminar):"
                > /tmp/new_banner.txt
                while true; do
                    read -r line
                    [ "$line" = "FIN" ] && break
                    echo "$line" >> /tmp/new_banner.txt
                done
                if [ -s /tmp/new_banner.txt ]; then
                    cp /tmp/new_banner.txt /etc/dropbear-legacy/banner.txt
                    systemctl restart dropbear-legacy 2>/dev/null
                    echo "✓ Banner Dropbear 2016 actualizado"
                fi
                rm -f /tmp/new_banner.txt
                read -p "ENTER..."
                ;;
            8)
                clear
                if [ -f /usr/local/bin/hysteria-manager ]; then
                    bash /usr/local/bin/hysteria-manager
                else
                    echo "⚠ Hysteria UDP no está instalado"
                    read -p "¿Instalar ahora? (s/n): " install_hyst
                    if [[ $install_hyst == "s" || $install_hyst == "S" ]]; then
                        cd /root
                        wget -q -O install_agnudp.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install_agnudp.sh
                        wget -q -O agnudp_manager.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/agnudp_manager.sh
                        if [ -f install_agnudp.sh ]; then
                            chmod +x install_agnudp.sh agnudp_manager.sh
                            bash install_agnudp.sh
                            cp agnudp_manager.sh /usr/local/bin/hysteria-manager
                            chmod +x /usr/local/bin/hysteria-manager
                            echo "✓ Hysteria instalado"
                        fi
                    fi
                    read -p "ENTER..."
                fi
                ;;
            9)
                clear
                echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}          ${BOLD}ESTADO DE SERVICIOS${NC}             ${CYAN}║${NC}"
                echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
                echo ""
                systemctl is-active --quiet ssh         && echo -e "${GREEN}✓ OpenSSH:         Activo${NC}  (puerto 22)"          || echo -e "${RED}✗ OpenSSH:         Inactivo${NC}"
                systemctl is-active --quiet dropbear-legacy && echo -e "${GREEN}✓ Dropbear 2016:   Activo${NC}  (puerto 143)"   || echo -e "${RED}✗ Dropbear 2016:   Inactivo${NC}"
                systemctl is-active --quiet stunnel4    && echo -e "${GREEN}✓ Stunnel:         Activo${NC}  (443, 444, 777)"      || echo -e "${RED}✗ Stunnel:         Inactivo${NC}"
                systemctl is-active --quiet badvpn-udpgw && echo -e "${GREEN}✓ BadVPN UDPGW:    Activo${NC} (UDP 7300)"          || echo -e "${RED}✗ BadVPN UDPGW:    Inactivo${NC}"
                echo ""
                local active_proxies
                active_proxies=$(screen -ls 2>/dev/null | grep -c "proxy-")
                echo -e "${YELLOW}Python Proxies activos:${NC} $active_proxies"
                echo ""
                echo -e "${YELLOW}Disco:${NC} $(df -h / | awk 'NR==2{print $3"/"$2" ("$5" usado)"}')"
                echo -e "${YELLOW}Swap:${NC}  $(free -h | awk '/Swap/{print $3"/"$2}')"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                read -p "ENTER para continuar..."
                ;;
            10)
                clear
                echo "REINICIAR SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Reiniciar proxies HTTP"
                echo "2) Reiniciar OpenSSH"
                echo "3) Reiniciar Dropbear 2016"
                echo "4) Reiniciar Stunnel"
                echo "5) Reiniciar BadVPN"
                echo "6) Reiniciar TODO"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "ENTER..." ;;
                    2) systemctl restart ssh          && echo "✓ OpenSSH reiniciado"   || echo "✗ Error"; read -p "ENTER..." ;;
                    3) systemctl restart dropbear-legacy && echo "✓ Dropbear reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    4) systemctl restart stunnel4     && echo "✓ Stunnel reiniciado"   || echo "✗ Error"; read -p "ENTER..." ;;
                    5) systemctl restart badvpn-udpgw && echo "✓ BadVPN reiniciado"   || echo "✗ Error"; read -p "ENTER..." ;;
                    6) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
                ;;
            D|d)
                clear
                echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
                echo -e "${RED}║         DESINSTALAR MSY VPN SCRIPT           ║${NC}"
                echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}Esto eliminará todos los servicios, archivos y"
                echo -e "configuraciones instaladas por este script.${NC}"
                echo ""
                read -p "¿Confirmar desinstalación? (escribe SI para confirmar): " confirm
                if [ "$confirm" = "SI" ]; then
                    echo ""
                    echo "Desinstalando MSY VPN..."

                    # Detener y deshabilitar servicios
                    echo "Deteniendo servicios..."
                    systemctl stop dropbear-legacy    2>/dev/null
                    systemctl stop badvpn-udpgw       2>/dev/null
                    systemctl stop stunnel4            2>/dev/null
                    systemctl stop restore-proxies     2>/dev/null
                    systemctl stop hysteria            2>/dev/null

                    systemctl disable dropbear-legacy  2>/dev/null
                    systemctl disable badvpn-udpgw     2>/dev/null
                    systemctl disable restore-proxies   2>/dev/null
                    systemctl disable hysteria          2>/dev/null

                    # Matar procesos
                    echo "Eliminando procesos..."
                    pkill -9 -f "proxy.py" 2>/dev/null
                    pkill -9 -f "badvpn-udpgw" 2>/dev/null
                    screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}' | xargs -I {} screen -X -S {} quit 2>/dev/null

                    # Eliminar archivos de servicios systemd
                    echo "Eliminando archivos del sistema..."
                    rm -f /etc/systemd/system/dropbear-legacy.service
                    rm -f /etc/systemd/system/badvpn-udpgw.service
                    rm -f /etc/systemd/system/restore-proxies.service
                    systemctl daemon-reload

                    # Eliminar binarios compilados
                    rm -rf /opt/dropbear-2016
                    rm -f /usr/bin/badvpn-udpgw

                    # Eliminar archivos de configuración
                    rm -rf /etc/dropbear-legacy
                    rm -rf /etc/proxy-python
                    rm -rf /etc/ssh-vpn
                    rm -rf /etc/hysteria 2>/dev/null

                    # Eliminar stunnel config (pero no el paquete)
                    rm -f /etc/stunnel/stunnel.conf
                    rm -f /etc/stunnel/stunnel.pem
                    rm -f /etc/stunnel/stunnel.key
                    rm -f /etc/stunnel/stunnel.crt

                    # Restaurar stunnel4 a estado deshabilitado
                    echo "ENABLED=0" > /etc/default/stunnel4
                    systemctl restart stunnel4 2>/dev/null || true

                    # Eliminar scripts del menú
                    rm -f /root/vpn-installer.sh
                    rm -f /root/ssh-vpn-functions.sh
                    rm -f /root/vpn-info.txt
                    rm -f /usr/local/bin/vpn-panel
                    rm -f /usr/local/bin/vpn-manager
                    rm -f /usr/local/bin/hysteria-manager 2>/dev/null

                    # Eliminar menú automático del bashrc
                    sed -i '/MSY VPN/,/fi/d' /root/.bashrc 2>/dev/null

                    # Eliminar fuentes descargadas
                    rm -rf /usr/src/dropbear-2016.74 2>/dev/null
                    rm -f /usr/src/dropbear-2016.74.tar.bz2 2>/dev/null
                    rm -rf /usr/src/badvpn 2>/dev/null

                    # Eliminar scripts temporales hysteria
                    rm -f /root/install_agnudp.sh 2>/dev/null
                    rm -f /root/agnudp_manager.sh 2>/dev/null

                    # Desactivar swap del script (opcional)
                    echo ""
                    read -p "¿Eliminar también el Swap de 2GB? (s/n): " del_swap
                    if [[ $del_swap == "s" || $del_swap == "S" ]]; then
                        swapoff /swapfile 2>/dev/null
                        rm -f /swapfile
                        sed -i '/swapfile/d' /etc/fstab 2>/dev/null
                        echo "✓ Swap eliminado"
                    fi

                    # Restaurar SSH a configuración básica (mantener activo)
                    echo ""
                    echo -e "${GREEN}✓ Desinstalación completada${NC}"
                    echo ""
                    echo "  Servicios eliminados: Dropbear 2016, BadVPN, Stunnel, Proxies"
                    echo "  OpenSSH se mantiene activo en puerto 22"
                    echo ""
                    echo "  La VPS queda limpia. Puedes instalar otra versión."
                    exit 0
                else
                    echo "Desinstalación cancelada."
                    read -p "ENTER para continuar..."
                fi
                ;;
            0)
                exit 0
                ;;
        esac
    done
}

menu_principal
MAINSCRIPT

chmod +x /root/vpn-installer.sh

# Crear acceso directo
cat > /usr/local/bin/vpn-panel <<'SHORTCUT'
#!/bin/bash
bash /root/vpn-installer.sh
SHORTCUT

chmod +x /usr/local/bin/vpn-panel
ln -sf /usr/local/bin/vpn-panel /usr/local/bin/vpn-manager

# ====================
# MENÚ AUTOMÁTICO AL LOGIN
# ====================
# Limpiar entradas anteriores
sed -i '/MSY VPN/,/fi/d' /root/.bashrc 2>/dev/null

cat >> /root/.bashrc <<'AUTOEOF'

# MSY VPN - Menú automático
if [ -t 0 ] && [ -f /usr/local/bin/vpn-panel ]; then
    vpn-panel
fi
AUTOEOF

# ====================
# FIREWALL - DESACTIVADO
# ====================
ufw --force disable >/dev/null 2>&1
echo "✓ UFW desactivado"

# ====================
# USUARIO INICIAL
# ====================
echo "Creando usuario VPN inicial..."
USER_VPN="vpnuser"
PASS_VPN="msy$(openssl rand -hex 4)"

if id "$USER_VPN" &>/dev/null; then
    userdel -r "$USER_VPN" 2>/dev/null
fi

useradd -m -s /bin/bash "$USER_VPN"
echo "$USER_VPN:$PASS_VPN" | chpasswd

cat > /etc/ssh-vpn/users/$USER_VPN.txt <<USEREOF
Usuario: $USER_VPN
Contraseña: $PASS_VPN
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: Ilimitado
Estado: Activo
USEREOF

# ====================
# INICIAR PROXIES
# ====================
echo "Iniciando proxies por defecto..."
source /root/ssh-vpn-functions.sh
restore_proxies

# ====================
# OPTIMIZACIONES SISTEMA
# ====================
# Evitar duplicados en sysctl
for param in "net.ipv4.ip_forward" "net.ipv4.tcp_keepalive_time" "net.ipv4.tcp_fin_timeout" \
             "net.ipv4.tcp_tw_reuse" "net.core.rmem_max" "net.core.wmem_max" \
             "net.ipv4.tcp_congestion_control"; do
    grep -q "^${param}" /etc/sysctl.conf && \
        sed -i "s|^${param}.*|${param} = $(echo $param | grep -q 'ip_forward' && echo 1 || echo '')|" /etc/sysctl.conf 2>/dev/null || true
done

cat >> /etc/sysctl.conf <<'EOF'

# MSY VPN Optimizaciones
net.ipv4.ip_forward = 1
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl -p >/dev/null 2>&1

# ====================
# RESUMEN FINAL
# ====================
IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

clear
echo -e "
${CYAN}╔══════════════════════════════════════════════╗${NC}
${CYAN}║${NC}  ${GREEN}✓ INSTALACIÓN COMPLETADA - v104${NC}          ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════════════╝${NC}

${YELLOW}IP:${NC} ${CYAN}$IP${NC}

${GREEN}SERVICIOS:${NC}
  ✓ OpenSSH:          puerto 22
  ✓ Dropbear 2016:    puerto 143  (SSH-2.0-ByJuanitoProSniff)
  ✓ Stunnel SSL/TLS:  443, 444, 777
  ✓ Proxies Python:   80, 8080, 8880, 8888 → DB 143
  ✓ BadVPN UDPGW:     UDP 7300

${YELLOW}CREDENCIALES:${NC}
  Usuario:   $USER_VPN
  Password:  $PASS_VPN

${YELLOW}PANEL:${NC} ejecutar ${CYAN}vpn-panel${NC} (auto al conectar)

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
"

# Guardar info
cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v104

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear 2016: 143
- Stunnel: 443 → DB143 | 444 → SSH22 | 777 → DB143
- Proxies Python: 80, 8080, 8880, 8888 → DB 143
- BadVPN UDPGW: UDP 7300

USUARIO INICIAL:
$USER_VPN / $PASS_VPN

COMANDOS:
- Panel: vpn-panel
- Desinstalar: desde el menú opción D

INFOEOF

sleep 2
/usr/local/bin/vpn-panel
