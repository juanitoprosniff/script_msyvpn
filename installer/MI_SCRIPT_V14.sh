#!/bin/bash
# Script MSY By JuanitoProSniff - v14
# - Canal: t.me/FREEINTERNETVPNMSY
# Mejoras v14:
#   - Limpieza automática de logs (evita disco lleno)
#   - Rotación de logs con logrotate
#   - Detección de arquitectura automática (x86_64, arm64, armv7)
#   - Compatibilidad Ubuntu 18.04 → 25.x
#   - SSL/Stunnel con watchdog para auto-recuperación
#   - Proxy Python optimizado con pool de threads
#   - Límite de sesiones simultáneas por usuario configurable
#   - Limpieza de fuentes de compilación tras instalar
#   - Opción de limpieza de disco en el panel

clear
echo "=========================================="
echo " Instalando Script MSY VPN v14"
echo "========================================"
echo ""

# Verificar root
if [[ $EUID -ne 0 ]]; then
   echo "Este script debe ejecutarse como root"
   exit 1
fi

# ====================
# DETECTAR ARQUITECTURA Y VERSIÓN DE UBUNTU
# ====================
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)   ARCH_LABEL="amd64" ;;
    aarch64)  ARCH_LABEL="arm64" ;;
    armv7l)   ARCH_LABEL="armhf" ;;
    armv6l)   ARCH_LABEL="armel" ;;
    i386|i686) ARCH_LABEL="i386" ;;
    *)        ARCH_LABEL="$ARCH" ;;
esac

UBUNTU_VER=$(lsb_release -rs 2>/dev/null || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null || echo "0")
UBUNTU_MAJ=$(echo "$UBUNTU_VER" | cut -d. -f1)

echo "Sistema detectado: Ubuntu $UBUNTU_VER | Arquitectura: $ARCH ($ARCH_LABEL)"

# Ajustar pip según versión Ubuntu (>=23 usa --break-system-packages)
PIP_FLAGS=""
[ "$UBUNTU_MAJ" -ge 23 ] 2>/dev/null && PIP_FLAGS="--break-system-packages"

# Colores
red='\033[1;31m'
yellow='\033[1;33m'
off='\033[0m'

# Detener servicios previos
pkill -9 -f "proxy-python" 2>/dev/null
pkill -9 -f "badvpn-udpgw" 2>/dev/null
systemctl stop dropbear 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop ssh 2>/dev/null

# Actualizar sistema
echo "Actualizando sistema..."
apt update -y && apt upgrade -y

# Instalar dependencias
echo "Instalando dependencias..."
apt install -y python3 python3-pip openssh-server dropbear stunnel4 screen lsof curl wget nano ufw net-tools cmake build-essential git jq zlib1g-dev

# Instalar logrotate si no está (limpieza automática de logs)
apt install -y logrotate 2>/dev/null

# ====================
# CONFIGURAR LOGROTATE PARA EVITAR DISCO LLENO
# ====================
echo "Configurando rotación de logs automática..."

cat > /etc/logrotate.d/msy-vpn <<'LOGROTATEOF'
/var/log/stunnel4/stunnel.log {
    daily
    rotate 3
    size 10M
    compress
    missingok
    notifempty
    copytruncate
}

/var/log/auth.log {
    daily
    rotate 5
    size 20M
    compress
    missingok
    notifempty
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}

/var/log/syslog {
    daily
    rotate 3
    size 15M
    compress
    missingok
    notifempty
    copytruncate
}
LOGROTATEOF

# Forzar rotación inmediata si logs ya están grandes
logrotate -f /etc/logrotate.d/msy-vpn 2>/dev/null || true

# Limpiar journald (logs del sistema que se acumulan)
journalctl --vacuum-size=50M 2>/dev/null || true
journalctl --vacuum-time=7d 2>/dev/null || true

# Configurar journald para no crecer más de 50MB
if [ -f /etc/systemd/journald.conf ]; then
    sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=50M/' /etc/systemd/journald.conf
    grep -q "^SystemMaxUse=" /etc/systemd/journald.conf || echo "SystemMaxUse=50M" >> /etc/systemd/journald.conf
    sed -i 's/^#SystemKeepFree=.*/SystemKeepFree=100M/' /etc/systemd/journald.conf
    grep -q "^SystemKeepFree=" /etc/systemd/journald.conf || echo "SystemKeepFree=100M" >> /etc/systemd/journald.conf
    systemctl restart systemd-journald 2>/dev/null || true
fi

echo "✓ Rotación de logs configurada (stunnel, auth, syslog, journald limitado a 50MB)"


mkdir -p /var/log/proxy-python
mkdir -p /etc/ssh-vpn
mkdir -p /etc/ssh-vpn/users
mkdir -p /etc/ssh-vpn/tunnels
mkdir -p /etc/hysteria
mkdir -p /etc/dropbear-legacy
mkdir -p /opt/dropbear-2016

# ====================
# CONFIGURAR SWAP 2GB AUTOMÁTICO
# ====================
echo "Configurando Swap de 2GB..."

if [ ! -f /swapfile ] || [ $(stat -f -c%s /swapfile 2>/dev/null) -lt 2147483648 ]; then
    # Desactivar swap anterior si existe
    swapoff /swapfile 2>/dev/null
    rm -f /swapfile
    
    # Crear swap de 2GB
    dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    # Hacer permanente
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    
    # Configurar swappiness
    echo "vm.swappiness=11" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    
    echo "✓ Swap de 2GB configurado y activado"
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
PrintLastLog no
X11Forwarding yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
# Keepalive: detectar clientes caídos en ~2 min
ClientAliveInterval 60
ClientAliveCountMax 3
TCPKeepAlive yes
# Soporte masivo de sesiones simultáneas
MaxStartups 200:30:500
MaxSessions 200
MaxAuthTries 6
# Sin compresión (consume CPU innecesariamente en VPN)
Compression no
# Algoritmos modernos y compatibles
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256
Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
# Rekeying cada 1GB o 1 hora (menos overhead en conexiones largas)
RekeyLimit 1G 1h
# No registrar logins exitosos (reduce escritura en disco)
PrintLastLog no
EOF

systemctl enable ssh
systemctl restart ssh

# ====================
# COMPILAR E INSTALAR DROPBEAR 2016.74 EN PUERTO 143
echo "=========================================="
echo "Compilando Dropbear 2016.74 desde fuente..."
echo "Esto puede tardar unos minutos..."
echo "=========================================="
cd /usr/src

# Descargar Dropbear 2016.74
if [ ! -f dropbear-2016.74.tar.bz2 ]; then
    echo "Descargando Dropbear 2016.74..."
    wget -q https://github.com/juanitoprosniff/script_msyvpn/raw/refs/heads/main/installer/dropbear-2016.74.tar.bz2
fi

# Extraer
echo "Extrayendo archivos..."
rm -rf dropbear-2016.74 2>/dev/null
tar xjf dropbear-2016.74.tar.bz2
cd dropbear-2016.74

# Configurar con opciones de compatibilidad
echo "Configurando compilación..."

# Modificar la versión SSH antes de compilar
echo "Modificando identificador SSH."
# El identificador está en sysoptions.h, no en default_options.h
if [ -f sysoptions.h ]; then
    sed -i 's|^#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' sysoptions.h 2>/dev/null || true
    echo "✓ Modificado en sysoptions.h"
elif [ -f default_options.h ]; then
    sed -i 's/#define LOCAL_IDENT "SSH-2.0-dropbear_" DROPBEAR_VERSION/#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"/' default_options.h 2>/dev/null || true
    sed -i 's/SSH-2.0-dropbear/SSH-2.0-ByJuanitoProSniff/g' default_options.h 2>/dev/null || true
    echo "✓ Modificado en default_options.h (fallback)"
fi

./configure --prefix=/opt/dropbear-2016 \
    --disable-zlib \
    --disable-wtmp \
    --disable-lastlog

# Compilar
echo "Compilando... (esto puede tardar 2-3 minutos)"
make -j$(nproc) PROGRAMS="dropbear dropbearkey"

# Instalar en /opt/dropbear-2016
echo "Instalando..."
make install PROGRAMS="dropbear dropbearkey"

# Verificar instalación
if [ ! -f /opt/dropbear-2016/sbin/dropbear ]; then
    echo "⚠ ERROR: No se pudo compilar Dropbear 2016"
    echo "Continuando sin Dropbear Legacy..."
else
    echo "✓ Dropbear 2016.74 compilado exitosamente"
    
    # Limpiar fuentes para liberar espacio en disco
    cd /root
    rm -rf /usr/src/dropbear-2016.74 /usr/src/dropbear-2016.74.tar.bz2
    echo "✓ Fuentes de compilación eliminadas (disco liberado)"
    
    mkdir -p /etc/dropbear-legacy
    
    # Generar llaves para Dropbear 2016
    echo "Generando llaves SSH para Dropbear 2016..."
    if [ ! -f /etc/dropbear-legacy/dropbear_rsa_host_key ]; then
        /opt/dropbear-2016/bin/dropbearkey -t rsa -f /etc/dropbear-legacy/dropbear_rsa_host_key -s 2048
    fi
    
    if [ ! -f /etc/dropbear-legacy/dropbear_dss_host_key ]; then
        /opt/dropbear-2016/bin/dropbearkey -t dss -f /etc/dropbear-legacy/dropbear_dss_host_key
    fi
    
    # Crear banner
    cat > /etc/dropbear-legacy/banner.txt <<'BANEOF'
t.me/FREEINTERNETVPNMSY
BANEOF
    
    # Crear servicio systemd para Dropbear 2016
    cat > /etc/systemd/system/dropbear-legacy.service <<'DBEOF'
[Unit]
Description=Dropbear SSH Legacy 2016.74 - Puerto 143
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/opt/dropbear-2016/sbin/dropbear -F -E -p 143 -r /etc/dropbear-legacy/dropbear_rsa_host_key -d /etc/dropbear-legacy/dropbear_dss_host_key -b /etc/dropbear-legacy/banner.txt -K 60 -I 300 -T 3 -j -k
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3
KillMode=process

[Install]
WantedBy=multi-user.target
DBEOF
    
    # Activar e iniciar servicio
    systemctl daemon-reload
    systemctl enable dropbear-legacy
    systemctl start dropbear-legacy
    
    # Verificar versión
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Versión de Dropbear 2016 instalada:"
    /opt/dropbear-2016/sbin/dropbear -V 2>&1 | head -n 1
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    sleep 2
fi

cd /root

# ====================
# STUNNEL (PUERTO 443) - COMPLETO CON WEBSOCKET Y SNI FLEXIBLE
# ====================
echo "Configurando Stunnel en puerto 443 con soporte WebSocket..."

# Generar certificado SSL con configuración mejorada y SANs
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
    -out /etc/stunnel/stunnel.crt > /dev/null 2>&1

cat /etc/stunnel/stunnel.crt /etc/stunnel/stunnel.key > /etc/stunnel/stunnel.pem

chmod 600 /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.key
chmod 644 /etc/stunnel/stunnel.crt

rm -f /tmp/openssl-stunnel.cnf

# Configuración de Stunnel FUNCIONAL (SSL Directo + WebSocket + SNI Flexible)
cat > /etc/stunnel/stunnel.conf <<'EOF'
; ============================================
; STUNNEL SSL/TLS + WEBSOCKET + SNI FLEXIBLE
; ============================================

; Configuración Global
foreground = no
pid = /var/run/stunnel4/stunnel.pid
output = /var/log/stunnel4/stunnel.log

; Nivel de debug (0=mínimo para no llenar disco, 5=verbose solo para diagnostico)
debug = 0

; Opciones de rendimiento y keepalive
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1
socket = l:SO_REUSEADDR=1
socket = r:SO_REUSEADDR=1

; Timeouts largos para WebSocket
TIMEOUTclose = 1
TIMEOUTidle = 86400
TIMEOUTbusy = 300
TIMEOUTconnect = 30

; Opciones SSL/TLS (TLS 1.2 y 1.3)
sslVersion = all
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1
options = CIPHER_SERVER_PREFERENCE
options = NO_TICKET

; Session cache
sessionCacheSize = 1000
sessionCacheTimeout = 300

; Cifrados compatibles modernos
ciphers = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4

; ============================================
; SERVICIO PRINCIPAL - PUERTO 443
; ============================================
[dropbear-ssl-443]
client = no
accept = 0.0.0.0:443
connect = 127.0.0.1:143
cert = /etc/stunnel/stunnel.pem
verify = 0
renegotiation = yes
TIMEOUTclose = 1
TIMEOUTidle = 86400

; ============================================
; SERVICIO ALTERNATIVO - PUERTO 444
; ============================================
[openssh-ssl-444]
client = no
accept = 0.0.0.0:444
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
verify = 0
renegotiation = yes
TIMEOUTclose = 1
TIMEOUTidle = 86400

; ============================================
; SERVICIO EXPERIMENTAL - PUERTO 777
; ============================================
[dropbear-ssl-777]
client = no
accept = 0.0.0.0:777
connect = 127.0.0.1:143
cert = /etc/stunnel/stunnel.pem
verify = 0
renegotiation = yes
TIMEOUTclose = 1
TIMEOUTidle = 86400
EOF

# Configurar stunnel4 para que inicie
echo "ENABLED=1" > /etc/default/stunnel4
echo "FILES=\"/etc/stunnel/*.conf\"" >> /etc/default/stunnel4
echo "OPTIONS=\"\"" >> /etc/default/stunnel4
echo "PPP_RESTART=0" >> /etc/default/stunnel4

# Crear directorios necesarios
mkdir -p /var/run/stunnel4
mkdir -p /var/log/stunnel4

# Establecer permisos
chown -R stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || chown -R nobody:nogroup /var/run/stunnel4
chown -R stunnel4:stunnel4 /var/log/stunnel4 2>/dev/null || chown -R nobody:nogroup /var/log/stunnel4
chmod 755 /var/run/stunnel4
chmod 755 /var/log/stunnel4

# Reiniciar stunnel
systemctl daemon-reload
systemctl enable stunnel4
systemctl restart stunnel4

# Verificar que está funcionando
sleep 3
if systemctl is-active --quiet stunnel4; then
    echo "✓ Stunnel SSL/TLS configurado correctamente"
    echo "  - Puerto 443 → Dropbear 143 (SSL Directo + WebSocket + SNI Flexible)"
    echo "  - Puerto 444 → OpenSSH 22 (SSL Directo + WebSocket + SNI Flexible)"
    echo "  - Puerto 777 → Dropbear 143 (Experimental)"
    echo "  - Soporte: TLS 1.2/1.3, WebSocket, Payload, SNI Flexible"
    echo "  - Certificado wildcard (*) - acepta cualquier SNI"
else
    echo "⚠ Verificando Stunnel..."
    systemctl status stunnel4 --no-pager | head -n 20
    echo ""
    echo "Últimas líneas del log:"
    tail -n 10 /var/log/stunnel4/stunnel.log 2>/dev/null || echo "No hay log disponible"
fi

# ====================
# INSTALAR BADVPN UDPGW
# ====================
echo "Instalando BadVPN UDPGW..."

cd /usr/src
git clone https://github.com/ambrop72/badvpn.git 2>/dev/null || (cd badvpn && git pull)
cd badvpn
mkdir -p build
cd build

cmake .. -DCMAKE_INSTALL_PREFIX=/usr \
         -DBUILD_NOTHING_BY_DEFAULT=1 \
         -DBUILD_UDPGW=1

make -j$(nproc)
make install

cat > /etc/systemd/system/badvpn-udpgw.service <<'EOF'
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable badvpn-udpgw
systemctl start badvpn-udpgw

# Limpiar fuentes de badvpn para liberar disco
rm -rf /usr/src/badvpn
echo "✓ Fuentes de badvpn eliminadas (disco liberado)"

# ====================
# DESCARGAR E INSTALAR HYSTERIA UDP
# ====================
echo "Descargando e instalando Hysteria UDP Manager..."

cd /root
wget -q -O install_agnudp.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install_agnudp.sh 2>/dev/null
wget -q -O agnudp_manager.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/agnudp_manager.sh 2>/dev/null

if [ -f install_agnudp.sh ] && [ -f agnudp_manager.sh ]; then
    chmod +x install_agnudp.sh agnudp_manager.sh
    
    # Instalar Hysteria UDP
    bash install_agnudp.sh 2>/dev/null
    
    # Copiar manager a bin
    cp agnudp_manager.sh /usr/local/bin/hysteria-manager
    chmod +x /usr/local/bin/hysteria-manager
    
    echo "✓ Hysteria UDP Manager instalado"
else
    echo "⚠ No se pudo descargar Hysteria UDP Manager"
fi

# ====================
# CREAR PROXY PYTHON
# ====================
echo "Creando Proxy Python..."
# NOTA: El banner soporta HTML para apps como HTTP Injector, HTTP Custom, etc.
# Ejemplo: <span style="background-color: #000000;"><span style="color:#eeff01;">TEXTO</span></span>

cat > /etc/proxy-python/proxy.py <<'PYEOF'
#!/usr/bin/env python3
"""
MSY VPN Proxy v14 - Multi-metodo + ThreadPool optimizado
Canal: https://t.me/FREEINTERNETVPNMSY
"""
import socket, threading, select, sys, re, base64, hashlib
from concurrent.futures import ThreadPoolExecutor

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 80
BUFLEN = 65536
TIMEOUT = 120
SSH_HOST = '127.0.0.1'
SSH_PORT = 143
RESPONSE_CODE = '101'
BANNER_TEXT = '<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>'
CHANNEL = 't.me/FREEINTERNETVPNMSY'
MAX_WORKERS = 500   # máximo de conexiones simultáneas por proxy

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

def handle_connection(client, cfg, addr):
    ssh = None
    try:
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Keepalive agresivo para detectar clientes caídos rápido
        try:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except Exception:
            pass
        client.settimeout(TIMEOUT)
        data = client.recv(BUFLEN)
        if not data:
            return
        # Conectar al backend SSH
        try:
            ssh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ssh.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            ssh.settimeout(10)
            ssh.connect((cfg['ssh_host'], cfg['ssh_port']))
            ssh.settimeout(None)
        except Exception:
            return
        # Enviar respuesta según tipo de petición
        head = data[:4096].decode('utf-8', errors='ignore')
        code    = cfg['code']
        banner  = cfg['banner']
        if 'Upgrade: websocket' in head or 'upgrade: websocket' in head:
            m = re.search(r'Sec-WebSocket-Key:\s*(\S+)', head, re.I)
            if m:
                client.sendall(ws_handshake_response(m.group(1)).encode())
            else:
                client.sendall(
                    f"HTTP/1.1 101 {banner}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".encode()
                )
        elif head.startswith('CONNECT '):
            client.sendall(
                f"HTTP/1.1 200 {banner}\r\n"
                f"X-Channel: {CHANNEL}\r\n"
                f"Connection: keep-alive\r\n\r\n".encode()
            )
        elif re.match(r'(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ', head):
            client.sendall((
                f"HTTP/1.1 {code} {banner}\r\n"
                f"Content-Length: 999999\r\n"
                f"Connection: keep-alive\r\n"
                f"Keep-Alive: timeout=60, max=10000\r\n"
                f"X-Channel: {CHANNEL}\r\n"
                f"\r\n"
            ).encode())
        else:
            client.sendall((
                f"HTTP/1.1 {code} {banner}\r\n"
                f"Content-Length: 999999\r\n"
                f"Connection: keep-alive\r\n"
                f"X-Channel: {CHANNEL}\r\n"
                f"\r\n"
            ).encode())
        # Tunnel bidireccional
        client.settimeout(None)
        while True:
            r, _, _ = select.select([client, ssh], [], [], TIMEOUT)
            if not r:
                break
            for s in r:
                d = s.recv(BUFLEN)
                if not d:
                    return
                other = ssh if s is client else client
                other.sendall(d)
    except Exception:
        pass
    finally:
        for s in (client, ssh):
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
        srv.listen(2000)
        print(f"[*] MSY VPN Proxy :{self.cfg['port']} → :{self.cfg['ssh_port']} | {self.cfg['banner']}")
        print(f"[*] Canal: {CHANNEL} | Workers: {MAX_WORKERS}")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            while True:
                try:
                    c, a = srv.accept()
                    pool.submit(handle_connection, c, self.cfg, a)
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
# CREAR MENÚ PRINCIPAL
# ====================
menu_principal() {
    source /root/ssh-vpn-functions.sh
    
    while true; do
        clear
        IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        SYS=$(get_system_stats)
        CPU_GHZ=$(echo $SYS | cut -d'|' -f1)
        CPU_USG=$(echo $SYS | cut -d'|' -f2)
        RAM_TOT=$(echo $SYS | cut -d'|' -f3)
        RAM_USG=$(echo $SYS | cut -d'|' -f4)
        RAM_PCT=$(echo $SYS | cut -d'|' -f5)
        SWP_TOT=$(echo $SYS | cut -d'|' -f6)
        SWP_USG=$(echo $SYS | cut -d'|' -f7)
        SWP_PCT=$(echo $SYS | cut -d'|' -f8)
        DSK_TOT=$(echo $SYS | cut -d'|' -f9)
        DSK_USG=$(echo $SYS | cut -d'|' -f10)
        DSK_PCT=$(echo $SYS | cut -d'|' -f11)
        
        cat <<EOF
╔══════════════════════════════════════════════╗
║         MSY VPN Panel - v14           ║
╚══════════════════════════════════════════════╝
 IP: $IP
 CPU: ${CPU_GHZ}  Uso: ${CPU_USG}%   RAM: ${RAM_TOT}  Uso: ${RAM_USG} (${RAM_PCT}%)
 SWAP: ${SWP_TOT}  Uso: ${SWP_USG} (${SWP_PCT}%)   DISCO: ${DSK_TOT}  Uso: ${DSK_USG} (${DSK_PCT}%)

 1) Crear usuario          2) Eliminar usuario
 3) Ver conectados         4) Proxies Python
 5) Ver puertos            6) Banner HTTP proxy
 7) Banner SSH             8) Túneles SSL/TLS
 9) Hysteria UDP          10) Estado servicios
11) Reiniciar servicios   15) Limpiar disco
 0) Salir
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
        read -p "Opción: " option
        
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
                
                useradd -m -s /bin/bash $username
                echo "$username:$password" | chpasswd
                
                if [ "$days" -gt 0 ]; then
                    expiry=$(date -d "+$days days" +%Y-%m-%d)
                    chage -E $expiry $username
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
                echo "✓ Usuario $username creado exitosamente"
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
                
                pkill -9 -u $username 2>/dev/null
                userdel -r $username 2>/dev/null
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
                        read -p "Banner text [HTML o texto simple]: " banner
                        banner=${banner:-<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>}
                        echo ""
                        echo "Backend SSH destino:"
                        echo "  1) 22  - OpenSSH"
                        echo "  2) 90  - Dropbear moderno"
                        echo "  3) 143 - Dropbear 2016 Ubuntu 18 (recomendado)"
                        echo "  4) Otro puerto personalizado"
                        read -p "Opción [3]: " be_opt
                        case ${be_opt:-3} in
                            1) ssh_port=22 ;;
                            2) ssh_port=90 ;;
                            3) ssh_port=143 ;;
                            4) read -p "Puerto: " ssh_port ;;
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
                        screen -ls | grep "proxy-" | awk -F'.' '{print $2}' | grep proxy | while read n; do
                            port=$(echo $n | sed 's/proxy-//')
                            cfg=$(grep "^${port}|" /etc/proxy-python/proxies.conf 2>/dev/null)
                            echo "  :$port — ${cfg:-sin config}"
                        done
                        screen -ls | grep -q "proxy-" || echo "  Ninguno activo"
                        echo ""
                        echo "Configuración guardada:"
                        cat /etc/proxy-python/proxies.conf 2>/dev/null || echo "  Sin configuración"
                        read -p "ENTER..."
                        ;;
                    4)
                        echo "Proxies activos:"
                        screen -ls | grep "proxy-" | awk '{print $1}'
                        echo ""
                        read -p "Puerto a detener: " del_port
                        [ -n "$del_port" ] && stop_proxy "$del_port"
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            5)
                clear
                echo "PUERTOS Y SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "OpenSSH (puerto 22):"
                ss -tlnp | grep ':22 ' | grep -v grep
                echo ""
                echo "Dropbear (puerto 90):"
                ss -tlnp | grep ':90 ' | grep -v grep
                echo ""
                echo "Dropbear Legacy (puerto 143 - Ubuntu 18):"
                ss -tlnp | grep ':143 ' | grep -v grep
                echo ""
                echo "Stunnel SSL (puertos 443, 444, 777):"
                ss -tlnp | grep -E ':(443|444|777) ' | grep stunnel | grep -v grep
                echo ""
                echo "Squid Proxy (puertos 3128, 8888):"
                ss -tlnp | grep -E ':(3128|8888) ' | grep -v grep
                echo ""
                echo "Python Proxies (80, 8080, 8880):"
                ss -tlnp | grep -E ':(80|8080|8880) ' | grep python | grep -v grep
                echo ""
                echo "BadVPN UDPGW (puerto UDP 7300):"
                ss -ulnp | grep ':7300 ' | grep -v grep
                echo ""
                echo "Hysteria UDP:"
                ps aux | grep hysteria | grep -v grep || echo "No activo"
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER para continuar..."
                ;;
            6)
                clear
                echo "BANNER HTTP/1.1"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "Banner actual:"
                grep "BANNER_TEXT = " /etc/proxy-python/proxy.py
                echo ""
                read -p "Nuevo texto [HTML o texto simple]: " new_banner
                new_banner=${new_banner:-<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>}
                
                sed -i "s/BANNER_TEXT = .*/BANNER_TEXT = '$new_banner'/" /etc/proxy-python/proxy.py
                echo ""
                echo "✓ Banner actualizado a: $new_banner"
                echo ""
                echo "→ Reinicia los proxies desde Opción 11"
                read -p "ENTER para continuar..."
                ;;
            7)
                clear
                echo "BANNERS SSH"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Cambiar banner OpenSSH (22)"
                echo "2) Cambiar banner Dropbear (90)"
                echo "3) Cambiar banner Dropbear Legacy (143)"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " banner_opt
                
                case $banner_opt in
                    1)
                        clear
                        echo "BANNER OPENSSH ACTUAL:"
                        cat /etc/ssh/banner.txt
                        echo ""
                        echo "Nuevo banner (multilínea, FIN para terminar):"
                        > /tmp/new_banner.txt
                        while true; do
                            read -r line
                            if [ "$line" = "FIN" ]; then
                                break
                            fi
                            echo "$line" >> /tmp/new_banner.txt
                        done
                        
                        if [ -s /tmp/new_banner.txt ]; then
                            cp /tmp/new_banner.txt /etc/ssh/banner.txt
                            systemctl restart ssh
                            echo "✓ Banner OpenSSH actualizado"
                        fi
                        rm -f /tmp/new_banner.txt
                        read -p "ENTER..."
                        ;;
                    2)
                        clear
                        echo "BANNER DROPBEAR ACTUAL:"
                        cat /etc/dropbear/banner.txt
                        echo ""
                        echo "Nuevo banner (multilínea, FIN para terminar):"
                        > /tmp/new_banner.txt
                        while true; do
                            read -r line
                            if [ "$line" = "FIN" ]; then
                                break
                            fi
                            echo "$line" >> /tmp/new_banner.txt
                        done
                        
                        if [ -s /tmp/new_banner.txt ]; then
                            cp /tmp/new_banner.txt /etc/dropbear/banner.txt
                            systemctl restart dropbear
                            echo "✓ Banner Dropbear (90) actualizado"
                        fi
                        rm -f /tmp/new_banner.txt
                        read -p "ENTER..."
                        ;;
                    3)
                        clear
                        echo "BANNER DROPBEAR LEGACY (143) ACTUAL:"
                        cat /etc/dropbear/banner-legacy.txt 2>/dev/null || echo "(sin banner)"
                        echo ""
                        echo "Nuevo banner (multilínea, FIN para terminar):"
                        > /tmp/new_banner.txt
                        while true; do
                            read -r line
                            if [ "$line" = "FIN" ]; then
                                break
                            fi
                            echo "$line" >> /tmp/new_banner.txt
                        done
                        
                        if [ -s /tmp/new_banner.txt ]; then
                            cp /tmp/new_banner.txt /etc/dropbear/banner-legacy.txt
                            systemctl restart dropbear-legacy 2>/dev/null ||                                 pkill -HUP dropbear 2>/dev/null
                            echo "✓ Banner Dropbear Legacy (143) actualizado"
                        fi
                        rm -f /tmp/new_banner.txt
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            8)
                clear
                echo "TÚNELES SSL/TLS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Ver túneles activos"
                echo "2) Agregar nuevo túnel"
                echo "3) Eliminar túnel"
                echo "4) Reiniciar Stunnel"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " tunnel_opt
                
                case $tunnel_opt in
                    1)
                        clear
                        echo "TÚNELES SSL ACTIVOS:"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        cat /etc/stunnel/stunnel.conf | grep -E '\[|accept|connect'
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
                        echo ""
                        echo "Backend destino:"
                        echo "  22  - OpenSSH"
                        echo "  90  - Dropbear (recomendado)"
                        read -p "Puerto destino [90]: " tunnel_dest
                        tunnel_dest=${tunnel_dest:-90}
                        
                        cat >> /etc/stunnel/stunnel.conf <<TUNNELEOF

[$tunnel_name]
accept = $tunnel_port
connect = 127.0.0.1:$tunnel_dest
TUNNELEOF
                        
                        ufw allow $tunnel_port/tcp 2>/dev/null
                        systemctl restart stunnel4
                        
                        echo ""
                        echo "✓ Túnel $tunnel_name creado en puerto $tunnel_port"
                        read -p "ENTER..."
                        ;;
                    3)
                        clear
                        echo "ELIMINAR TÚNEL"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        read -p "Puerto del túnel a eliminar: " del_port
                        
                        sed -i "/accept = $del_port/,+1 d" /etc/stunnel/stunnel.conf
                        sed -i "/\[.*\]/{ N; /accept = $del_port/d; }" /etc/stunnel/stunnel.conf
                        
                        systemctl restart stunnel4
                        echo "✓ Túnel en puerto $del_port eliminado"
                        read -p "ENTER..."
                        ;;
                    4)
                        systemctl restart stunnel4
                        echo "✓ Stunnel reiniciado"
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            9)
                clear
                if [ -f /usr/local/bin/hysteria-manager ]; then
                    bash /usr/local/bin/hysteria-manager
                else
                    echo "⚠ Hysteria UDP Manager no está instalado"
                    echo ""
                    read -p "¿Deseas instalarlo ahora? (s/n): " install_hyst
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
            10)
                clear
                echo "ESTADO DE SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                systemctl is-active --quiet ssh && echo "✓ OpenSSH: Activo (puerto 22)" || echo "✗ OpenSSH: Inactivo"
                systemctl is-active --quiet dropbear && echo "✓ Dropbear: Activo (puerto 90)" || echo "✗ Dropbear: Inactivo"
                systemctl is-active --quiet stunnel4 && echo "✓ Stunnel: Activo (puertos 443, 444, 777)" || echo "✗ Stunnel: Inactivo"
                
                systemctl is-active --quiet badvpn-udpgw && echo "✓ BadVPN: Activo (puerto 7300)" || echo "✗ BadVPN: Inactivo"
                echo ""
                echo "Swap: $(free -h | grep Swap | awk '{print $2}')"
                echo ""
                echo "Python Proxies activos:"
                screen -ls | grep "proxy-" | wc -l | xargs echo "  Total:"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER para continuar..."
                ;;
            11)
                clear
                echo "REINICIAR SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Reiniciar proxies (HTTP)"
                echo "2) Reiniciar OpenSSH"
                echo "3) Reiniciar Dropbear"
                echo "4) Reiniciar Stunnel"
                echo "5) Reiniciar TODO"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "ENTER..." ;;
                    2) systemctl restart ssh && echo "✓ OpenSSH reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    3) systemctl restart dropbear && echo "✓ Dropbear (90)" || echo "✗ Error"
                       systemctl restart dropbear-legacy 2>/dev/null && echo "✓ Dropbear Legacy (143)" || true
                       read -p "ENTER..." ;;
                    4) systemctl restart stunnel4 && echo "✓ Stunnel reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    5) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
                ;;
            15)
                clear
                echo "LIMPIEZA DE DISCO"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Uso actual:"
                df -h / | awk 'NR==2{print "  Total: "$2"  Usado: "$3"  Libre: "$4"  ("$5")"}'
                echo ""
                echo "Limpiando logs, cache y temporales..."
                logrotate -f /etc/logrotate.d/msy-vpn 2>/dev/null
                journalctl --vacuum-size=30M 2>/dev/null
                apt-get clean 2>/dev/null
                apt-get autoremove -y 2>/dev/null
                find /tmp -type f -mtime +1 -delete 2>/dev/null
                [ -f /var/log/stunnel4/stunnel.log ] && \
                    [ $(stat -c%s /var/log/stunnel4/stunnel.log 2>/dev/null || echo 0) -gt 10485760 ] && \
                    > /var/log/stunnel4/stunnel.log && echo "  ✓ Log Stunnel vaciado"
                rm -rf /usr/src/dropbear-2016.74 /usr/src/dropbear-2016.74.tar.bz2 2>/dev/null
                rm -rf /usr/src/badvpn 2>/dev/null
                echo ""
                echo "Uso después de limpieza:"
                df -h / | awk 'NR==2{print "  Total: "$2"  Usado: "$3"  Libre: "$4"  ("$5")"}'
                echo "✓ Listo"
                read -p "ENTER para continuar..."
                ;;
            0)
                exit 0
                ;;
        esac
    done
}

# ====================
# GUARDAR FUNCIONES
# ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

# Colores para el menú
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# -----------------------------------------------------------
# Convierte hex little-endian de /proc/net/tcp a IP:puerto
# -----------------------------------------------------------
_hex_to_ip_port() {
    local hex="$1"
    local ip_hex port_hex
    ip_hex=$(echo "$hex" | cut -d: -f1)
    port_hex=$(echo "$hex" | cut -d: -f2)
    # IP: 4 bytes little-endian → revertir
    local b1 b2 b3 b4
    b4=$(printf "%d" 0x${ip_hex:0:2})
    b3=$(printf "%d" 0x${ip_hex:2:2})
    b2=$(printf "%d" 0x${ip_hex:4:2})
    b1=$(printf "%d" 0x${ip_hex:6:2})
    local port
    port=$(printf "%d" 0x${port_hex})
    echo "${b1}.${b2}.${b3}.${b4}:${port}"
}

# -----------------------------------------------------------
# Extrae IPs remotas únicas de /proc/net/tcp y /proc/net/tcp6
# estado 01 = ESTABLISHED, 07 = CLOSE_WAIT (también activas)
# Esto cubre TCP sin depender de ss ni netstat
# -----------------------------------------------------------
_get_remote_ips_from_proc() {
    {
        # /proc/net/tcp: columna 3 = remote address, columna 4 = estado
        awk '$4=="01" || $4=="07" {print $3}' /proc/net/tcp 2>/dev/null | while read hex; do
            _hex_to_ip_port "$hex" | cut -d: -f1
        done

        # /proc/net/udp: conexiones UDP activas (estado 07 = activo)
        awk '$4=="07" {print $3}' /proc/net/udp 2>/dev/null | while read hex; do
            _hex_to_ip_port "$hex" | cut -d: -f1
        done

        # También ss como respaldo (TCP+UDP)
        ss -tnup state established 2>/dev/null \
            | awk 'NR>1 {
                n=split($5,b,":");
                ip=""; for(i=1;i<n;i++) ip=(ip=="")?b[i]:ip":"b[i];
                if(n==2) ip=b[1];
                print ip
              }'
    } | grep -v '^$' \
      | grep -v '^0\.0\.0\.0$' \
      | grep -v '^127\.' \
      | grep -v '^::1$' \
      | grep -v '^::$' \
      | grep -v '^10\.' \
      | grep -v '^192\.168\.' \
      | grep -vE '^172\.(1[6-9]|2[0-9]|3[01])\.' \
      | sort -u
}

count_users() {
    _get_remote_ips_from_proc | wc -l
}

list_connected_users() {
    echo "═══════════════════════════════════════════════"
    echo "           CLIENTES CONECTADOS"
    echo "═══════════════════════════════════════════════"
    echo ""

    # Obtener lista de IPs externas desde /proc/net/tcp + /proc/net/udp + ss
    local ips
    ips=$(_get_remote_ips_from_proc)

    if [ -z "$ips" ]; then
        echo "  Sin clientes conectados"
    else
        local n=1
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            # Detectar servicios activos para esta IP via ss
            local svcs=""
            while read -r lport; do
                local sname
                case "$lport" in
                    22)   sname="SSH"          ;;
                    90)   sname="Dropbear"     ;;
                    143)  sname="DB-Legacy"    ;;
                    443)  sname="SSL-443"      ;;
                    444)  sname="SSL-444"      ;;
                    777)  sname="SSL-777"      ;;
                    80)   sname="Proxy-80"     ;;
                    8080) sname="Proxy-8080"   ;;
                    8880) sname="Proxy-8880"   ;;
                    8888) sname="Proxy-8888"   ;;
                    7300) sname="UDPGW"        ;;
                    *)    sname=":$lport"      ;;
                esac
                svcs="${svcs:+$svcs | }$sname"
            done < <(ss -tnup 2>/dev/null | grep "$ip" | awk '{
                n=split($4,a,":");print a[n]
            }' | sort -u)

            [ -z "$svcs" ] && svcs="Conectado"
            echo "  $n) Cliente-$n  [$svcs]"
            n=$((n+1))
        done <<< "$ips"
    fi

    local total
    total=$(echo "$ips" | grep -c '[0-9]' 2>/dev/null || echo 0)
    echo ""
    echo "  Total: $total cliente(s) conectado(s)"
    echo "═══════════════════════════════════════════════"
}

# -----------------------------------------------------------
# Monitor de recursos del sistema
# -----------------------------------------------------------
show_monitor() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         MONITOR DE RECURSOS - MSY VPN        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo ""

    # CPU
    local cpu_mhz cpu_ghz cpu_cores
    cpu_mhz=$(grep -m1 "cpu MHz" /proc/cpuinfo 2>/dev/null | awk '{printf "%.0f",$4}')
    cpu_ghz=$(awk "BEGIN{printf \"%.2f\", ${cpu_mhz:-0}/1000}")
    cpu_cores=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
    cpu_model=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)

    # Uso CPU: leer /proc/stat dos veces
    local cpu1 cpu2 idle1 idle2 total1 total2 cpu_pct
    read -r _ u1 n1 s1 i1 _ < /proc/stat
    sleep 0.5
    read -r _ u2 n2 s2 i2 _ < /proc/stat
    total1=$((u1+n1+s1+i1)); total2=$((u2+n2+s2+i2))
    idle1=$i1; idle2=$i2
    cpu_pct=$(awk "BEGIN{d=$((total2-total1)); di=$((idle2-idle1)); printf \"%.0f\", (d-di)/d*100}")

    # RAM
    local ram_total ram_avail ram_used ram_pct ram_total_h ram_used_h
    ram_total=$(awk '/MemTotal/{print $2}' /proc/meminfo)
    ram_avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
    ram_used=$((ram_total - ram_avail))
    ram_pct=$(awk "BEGIN{printf \"%.0f\", ($ram_used/$ram_total)*100}")
    ram_total_h=$(awk "BEGIN{t=$ram_total/1024;if(t>1024)printf \"%.1fGB\",t/1024;else printf \"%.0fMB\",t}")
    ram_used_h=$(awk "BEGIN{u=$ram_used/1024;if(u>1024)printf \"%.1fGB\",u/1024;else printf \"%.0fMB\",u}")

    # SWAP
    local swap_total swap_free swap_used swap_pct swap_total_h swap_used_h
    swap_total=$(awk '/SwapTotal/{print $2}' /proc/meminfo)
    swap_free=$(awk '/SwapFree/{print $2}' /proc/meminfo)
    swap_used=$((swap_total - swap_free))
    if [ "${swap_total:-0}" -gt 0 ]; then
        swap_pct=$(awk "BEGIN{printf \"%.0f\", ($swap_used/$swap_total)*100}")
        swap_total_h=$(awk "BEGIN{t=$swap_total/1024;if(t>1024)printf \"%.1fGB\",t/1024;else printf \"%.0fMB\",t}")
        swap_used_h=$(awk "BEGIN{u=$swap_used/1024;if(u>1024)printf \"%.1fGB\",u/1024;else printf \"%.0fMB\",u}")
    else
        swap_pct=0; swap_total_h="0MB"; swap_used_h="0MB"
    fi

    # DISCO
    local disk_total disk_used disk_free disk_pct
    disk_total=$(df -h / 2>/dev/null | awk 'NR==2{print $2}')
    disk_used=$(df -h / 2>/dev/null | awk 'NR==2{print $3}')
    disk_free=$(df -h / 2>/dev/null | awk 'NR==2{print $4}')
    disk_pct=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5);print $5}')

    # Uptime
    local uptime_str
    uptime_str=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}' | tr -d ',')

    # Mostrar barra visual
    _bar() {
        local pct=$1 w=30
        local filled=$(( pct * w / 100 ))
        local empty=$(( w - filled ))
        printf "["
        printf '%0.s█' $(seq 1 $filled 2>/dev/null) 2>/dev/null
        printf '%0.s░' $(seq 1 $empty 2>/dev/null) 2>/dev/null
        printf "] %s%%" "$pct"
    }

    echo -e "${YELLOW}Modelo CPU:${NC} $cpu_model"
    echo -e "${YELLOW}Núcleos:${NC}    $cpu_cores  │  ${YELLOW}Velocidad:${NC} ${cpu_ghz}GHz"
    echo -e "${YELLOW}Uptime:${NC}     $uptime_str"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}CPU  ${NC} ${cpu_ghz}GHz  $(_bar $cpu_pct)"
    echo -e "${GREEN}RAM  ${NC} ${ram_used_h}/${ram_total_h}  $(_bar $ram_pct)"
    echo -e "${GREEN}SWAP ${NC} ${swap_used_h}/${swap_total_h}  $(_bar $swap_pct)"
    echo -e "${GREEN}DISCO${NC} ${disk_used}/${disk_total}  $(_bar $disk_pct)  libre: $disk_free"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}Clientes online:${NC} $(count_users)"
    echo ""
    read -p "ENTER para volver..."
}

# -----------------------------------------------------------
# Speedtest
# -----------------------------------------------------------
run_speedtest() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           TEST DE VELOCIDAD - MSY VPN        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo "1) Speedtest CLI (speedtest.net)"
    echo "2) Fast.com (Netflix)"
    echo "3) Test manual (curl)"
    echo "0) Volver"
    echo ""
    read -p "Opción: " sp_opt

    case $sp_opt in
        1)
            clear
            echo -e "${YELLOW}Ejecutando Speedtest...${NC}"
            echo ""
            if ! command -v speedtest &>/dev/null && ! command -v speedtest-cli &>/dev/null; then
                echo "Instalando speedtest-cli..."
                pip3 install speedtest-cli --break-system-packages 2>/dev/null \
                    || pip install speedtest-cli 2>/dev/null \
                    || apt-get install -y speedtest-cli 2>/dev/null
            fi
            if command -v speedtest &>/dev/null; then
                speedtest
            elif command -v speedtest-cli &>/dev/null; then
                speedtest-cli
            else
                echo -e "${RED}No se pudo instalar speedtest-cli${NC}"
                echo "Instala manualmente: pip3 install speedtest-cli"
            fi
            echo ""
            read -p "ENTER para continuar..."
            ;;
        2)
            clear
            echo -e "${YELLOW}Probando velocidad con Fast.com (curl)...${NC}"
            echo ""
            # fast-cli vía npx o curl directo
            if command -v npx &>/dev/null; then
                npx fast-cli 2>/dev/null || {
                    echo "Descargando desde Fast.com..."
                    curl -s https://api.fast.com/netflix/speedtest/v2?https=true\&token=YXNkZmFzZGxmbnNkYWZo\&urlCount=5 2>/dev/null | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    urls=d.get('targets',[])
    print(f'URLs de prueba encontradas: {len(urls)}')
except: print('No se pudo parsear respuesta')
"
                }
            else
                echo "Probando descarga (método curl)..."
                echo -n "Velocidad bajada aproximada: "
                curl -o /dev/null --max-time 15 \
                    "https://speed.cloudflare.com/__down?bytes=100000000" \
                    -w "%{speed_download}" -s 2>/dev/null \
                    | awk '{printf "%.1f Mbps\n", $1/125000}'
                echo ""
                echo -n "Velocidad subida aproximada:  "
                dd if=/dev/zero bs=1M count=10 2>/dev/null \
                    | curl -o /dev/null --max-time 15 \
                        -X POST "https://speed.cloudflare.com/__up" \
                        -H "Content-Type: application/octet-stream" \
                        --data-binary @- \
                        -w "%{speed_upload}" -s 2>/dev/null \
                    | awk '{printf "%.1f Mbps\n", $1/125000}'
            fi
            echo ""
            read -p "ENTER para continuar..."
            ;;
        3)
            clear
            echo -e "${YELLOW}Test manual de velocidad (Cloudflare)...${NC}"
            echo ""
            echo -n "▶ Bajada  (100MB): "
            curl -o /dev/null --max-time 20 \
                "https://speed.cloudflare.com/__down?bytes=100000000" \
                -w "%{speed_download}" -s 2>/dev/null \
                | awk '{printf "%.2f Mbps\n", $1/125000}'

            echo -n "▶ Subida  (10MB):  "
            dd if=/dev/zero bs=1M count=10 2>/dev/null \
                | curl -o /dev/null --max-time 20 \
                    -X POST "https://speed.cloudflare.com/__up" \
                    -H "Content-Type: application/octet-stream" \
                    --data-binary @- \
                    -w "%{speed_upload}" -s 2>/dev/null \
                | awk '{printf "%.2f Mbps\n", $1/125000}'

            echo -n "▶ Latencia (ping): "
            ping -c 4 1.1.1.1 2>/dev/null | tail -1 | awk -F'/' '{printf "%.1f ms\n", $5}'

            echo ""
            read -p "ENTER para continuar..."
            ;;
    esac
}

get_system_stats() {
    # CPU frecuencia
    local cpu_mhz cpu_ghz
    cpu_mhz=$(grep -m1 "cpu MHz" /proc/cpuinfo 2>/dev/null | awk '{printf "%.0f", $4}')
    if [ -n "$cpu_mhz" ] && [ "$cpu_mhz" -gt 0 ] 2>/dev/null; then
        cpu_ghz=$(awk "BEGIN {printf \"%.1f\", $cpu_mhz/1000}")
    else
        cpu_ghz="?"
    fi
    # Uso CPU rápido: leer /proc/stat dos veces con 0.2s de diferencia (sin top)
    local u1 n1 s1 i1 u2 n2 s2 i2 cpu_usage
    read -r _ u1 n1 s1 i1 _ < /proc/stat
    sleep 0.2
    read -r _ u2 n2 s2 i2 _ < /proc/stat
    cpu_usage=$(awk "BEGIN{t=$((u2+n2+s2+i2))-$((u1+n1+s1+i1)); id=$((i2-i1)); printf \"%.0f\", (t-id)/t*100}")
    [ -z "$cpu_usage" ] && cpu_usage=0

    # RAM
    local ram_total ram_avail ram_used ram_pct
    ram_total=$(awk '/MemTotal/{print $2}' /proc/meminfo)
    ram_avail=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
    ram_used=$(( ram_total - ram_avail ))
    ram_pct=$(awk "BEGIN{printf \"%.0f\", ($ram_used/$ram_total)*100}")
    local ram_total_h ram_used_h
    ram_total_h=$(awk "BEGIN{t=$ram_total/1024; if(t>1024)printf \"%.1fGB\",t/1024; else printf \"%.0fMB\",t}")
    ram_used_h=$(awk "BEGIN{u=$ram_used/1024; if(u>1024)printf \"%.1fGB\",u/1024; else printf \"%.0fMB\",u}")

    # SWAP
    local swap_total swap_free swap_used swap_pct swap_total_h swap_used_h
    swap_total=$(awk '/SwapTotal/{print $2}' /proc/meminfo)
    swap_free=$(awk '/SwapFree/{print $2}' /proc/meminfo)
    swap_used=$(( swap_total - swap_free ))
    if [ "$swap_total" -gt 0 ] 2>/dev/null; then
        swap_pct=$(awk "BEGIN{printf \"%.0f\", ($swap_used/$swap_total)*100}")
        swap_total_h=$(awk "BEGIN{t=$swap_total/1024; if(t>1024)printf \"%.1fGB\",t/1024; else printf \"%.0fMB\",t}")
        swap_used_h=$(awk "BEGIN{u=$swap_used/1024; if(u>1024)printf \"%.1fGB\",u/1024; else printf \"%.0fMB\",u}")
    else
        swap_pct=0; swap_total_h="0MB"; swap_used_h="0MB"
    fi

    # DISCO
    local disk_total disk_used disk_pct
    disk_total=$(df -h / 2>/dev/null | awk 'NR==2{print $2}')
    disk_used=$(df -h / 2>/dev/null | awk 'NR==2{print $3}')
    disk_pct=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')

    echo "${cpu_ghz}GHz|${cpu_usage}|${ram_total_h}|${ram_used_h}|${ram_pct}|${swap_total_h}|${swap_used_h}|${swap_pct}|${disk_total}|${disk_used}|${disk_pct}"
}

start_proxy() {
    local port=$1
    local response=$2
    local banner=$3
    local ssh_port=${4:-90}
    local save=${5:-1}   # 1=guardar en conf, 0=solo iniciar (para restore)

    if screen -list | grep -q "proxy-$port"; then
        echo "✗ Puerto $port ya en uso"
        return 1
    fi

    screen -dmS "proxy-$port" python3 /etc/proxy-python/proxy.py "$port" "$response" "$banner" "$ssh_port"
    sleep 1

    if screen -list | grep -q "proxy-$port"; then
        echo "✓ Proxy :$port → SSH:$ssh_port | $response $banner"
        # Guardar en archivo permanente (solo si no es un restore)
        if [ "$save" = "1" ]; then
            # Eliminar entrada anterior del mismo puerto si existe
            sed -i "/^${port}|/d" /etc/proxy-python/proxies.conf 2>/dev/null
            echo "${port}|${response}|${banner}|${ssh_port}" >> /etc/proxy-python/proxies.conf
        fi
    else
        echo "✗ Error al iniciar proxy en puerto $port"
    fi
}

stop_proxy() {
    local port=$1
    echo -e "${YELLOW}Deteniendo proxy en puerto $port...${NC}"
    
    # 1. Matar session de screen
    screen -X -S "proxy-$port" quit 2>/dev/null
    
    # 2. Matar proceso python
    pkill -f "proxy.py $port " 2>/dev/null
    
    # 3. Buscar y matar cualquier proceso en ese puerto
    local pid=$(lsof -ti:$port 2>/dev/null)
    if [ ! -z "$pid" ]; then
        kill -9 $pid 2>/dev/null
    fi
    
    # 4. Esperar un momento
    sleep 1
    
    # 5. Verificar si el puerto quedó libre
    if lsof -ti:$port >/dev/null 2>&1; then
        # Intentar con fuser como último recurso
        fuser -k $port/tcp 2>/dev/null
        sleep 1
    fi
    
    # 6. Eliminar del archivo permanente
    sed -i "/^${port}|/d" /etc/proxy-python/proxies.conf 2>/dev/null
    
    # Verificación final
    if lsof -ti:$port >/dev/null 2>&1; then
        echo -e "${RED}⚠ Advertencia: Puerto $port podría no estar completamente libre${NC}"
    else
        echo -e "${GREEN}✓ Proxy :$port detenido correctamente${NC}"
    fi
}

stop_all_proxies() {
    screen -ls | grep "proxy-" | awk '{print $1}' | xargs -I {} screen -X -S {} quit 2>/dev/null
    pkill -9 -f "proxy.py" 2>/dev/null
    # NO borramos proxies.conf - es permanente
    echo "✓ Proxies detenidos"
}

restore_proxies() {
    # Restaurar proxies desde archivo permanente (al reiniciar o reiniciar servicios)
    local conf=/etc/proxy-python/proxies.conf
    if [ ! -f "$conf" ] || [ ! -s "$conf" ]; then
        # Primera vez: crear configuración por defecto
        echo "80|101|<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>|143"   > "$conf"
        echo "8080|101|<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>|143" >> "$conf"
        echo "8880|101|<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>|143" >> "$conf"
        echo "8888|101|<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>|143" >> "$conf"
    fi
    while IFS='|' read -r port response banner ssh_port; do
        [ -z "$port" ] && continue
        # No iniciar si ya corre
        screen -list | grep -q "proxy-$port" && continue
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
    systemctl restart ssh       && echo "✓ OpenSSH"  || echo "✗ OpenSSH: error"
    systemctl restart dropbear  && echo "✓ Dropbear" || echo "✗ Dropbear: error"
    systemctl restart stunnel4  && echo "✓ Stunnel"  || echo "✗ Stunnel: error"
    restart_proxies
    echo "✓ Listo"
}
FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

# ====================
# CREAR SCRIPT PARA RESTAURAR PROXIES AL REINICIAR
# ====================
# Crear servicio systemd para restaurar proxies al reiniciar (más confiable que init.d)
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
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable restore-proxies
# Inicializar proxies.conf con los valores por defecto si no existe
[ ! -f /etc/proxy-python/proxies.conf ] && {
    echo "80|101|<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>|143"   > /etc/proxy-python/proxies.conf
    echo "8080|101|<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>|143" >> /etc/proxy-python/proxies.conf
    echo "8880|101|<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>|143" >> /etc/proxy-python/proxies.conf
    echo "8888|101|<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>|143" >> /etc/proxy-python/proxies.conf
}
echo "✓ Servicio de restauración de proxies configurado (systemd)"

# ====================
# WATCHDOG PARA STUNNEL (auto-recuperación si falla SSL)
# ====================
cat > /etc/systemd/system/stunnel-watchdog.service <<'WDEOF'
[Unit]
Description=MSY VPN - Watchdog Stunnel SSL
After=stunnel4.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do if ! systemctl is-active --quiet stunnel4; then systemctl restart stunnel4; fi; sleep 30; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
WDEOF

systemctl daemon-reload
systemctl enable stunnel-watchdog
systemctl start stunnel-watchdog
echo "✓ Watchdog de Stunnel activado (auto-reinicia si el SSL falla)"

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
        IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        SYS=$(get_system_stats)
        CPU_GHZ=$(echo $SYS | cut -d'|' -f1)
        CPU_USG=$(echo $SYS | cut -d'|' -f2)
        RAM_TOT=$(echo $SYS | cut -d'|' -f3)
        RAM_USG=$(echo $SYS | cut -d'|' -f4)
        RAM_PCT=$(echo $SYS | cut -d'|' -f5)
        SWP_TOT=$(echo $SYS | cut -d'|' -f6)
        SWP_USG=$(echo $SYS | cut -d'|' -f7)
        SWP_PCT=$(echo $SYS | cut -d'|' -f8)
        DSK_TOT=$(echo $SYS | cut -d'|' -f9)
        DSK_USG=$(echo $SYS | cut -d'|' -f10)
        DSK_PCT=$(echo $SYS | cut -d'|' -f11)
        
        echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC}  \033[40m\033[1;33m    MSY VPN SCRIPT - v10 SSL+   \033[0m   ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
        echo -e "${GREEN}IP:${NC} ${YELLOW}$IP${NC}"
        echo -e "${GREEN}CPU:${NC} ${YELLOW}${CPU_GHZ}${NC}  ${GREEN}Uso:${NC} ${YELLOW}${CPU_USG}%${NC}   ${GREEN}RAM:${NC} ${YELLOW}${RAM_TOT}${NC}  ${GREEN}Uso:${NC} ${YELLOW}${RAM_USG} (${RAM_PCT}%)${NC}"
        echo -e "${GREEN}SWAP:${NC} ${YELLOW}${SWP_TOT}${NC}  ${GREEN}Uso:${NC} ${YELLOW}${SWP_USG} (${SWP_PCT}%)${NC}   ${GREEN}DISCO:${NC} ${YELLOW}${DSK_TOT}${NC}  ${GREEN}Uso:${NC} ${YELLOW}${DSK_USG} (${DSK_PCT}%)${NC}"
        echo ""
        echo -e "${BLUE} 1)${NC} Crear usuario          ${BLUE} 2)${NC} Eliminar usuario"
        echo -e "${BLUE} 3)${NC} Ver conectados         ${BLUE} 4)${NC} Proxies Python"
        echo -e "${BLUE} 5)${NC} Ver puertos            ${BLUE} 6)${NC} Banner HTTP proxy"
        echo -e "${BLUE} 7)${NC} Banner SSH             ${BLUE} 8)${NC} Túneles SSL/TLS"
        echo -e "${BLUE} 9)${NC} Hysteria UDP          ${BLUE}10)${NC} Estado servicios"
        echo -e "${BLUE}11)${NC} Reiniciar servicios   ${BLUE}12)${NC} Ver versiones Dropbear"
        echo -e "${BLUE}13)${NC} Monitor recursos       ${BLUE}14)${NC} Speedtest"
        echo -e "${YELLOW}15)${NC} Limpiar disco          ${RED} 0)${NC} Salir"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        read -p "Opción: " option
        
        case $option in
            1)
                clear
                echo "CREAR USUARIO VPN"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario: " username
                read -p "Contraseña: " password
                read -p "Días de validez (0 = ilimitado): " days
                read -p "Límite de sesiones simultáneas (0 = ilimitado): " max_logins
                
                if id "$username" &>/dev/null; then
                    echo "El usuario ya existe"
                    read -p "ENTER para continuar..."
                    continue
                fi
                
                useradd -m -s /bin/bash $username
                echo "$username:$password" | chpasswd
                
                if [ "$days" -gt 0 ]; then
                    expiry=$(date -d "+$days days" +%Y-%m-%d)
                    chage -E $expiry $username
                else
                    expiry="Ilimitado"
                fi
                
                # Límite de sesiones simultáneas vía PAM limits
                if [ "${max_logins:-0}" -gt 0 ] 2>/dev/null; then
                    sed -i "/^$username /d" /etc/security/limits.conf
                    echo "$username hard maxlogins $max_logins" >> /etc/security/limits.conf
                fi

                cat > /etc/ssh-vpn/users/$username.txt <<USEREOF
Usuario: $username
Contraseña: $password
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: $expiry
Sesiones simultáneas: ${max_logins:-Ilimitado}
Estado: Activo
USEREOF
                
                echo ""
                echo "✓ Usuario $username creado exitosamente"
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
                
                pkill -9 -u $username 2>/dev/null
                userdel -r $username 2>/dev/null
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
                        read -p "Banner text [HTML o texto simple]: " banner
                        banner=${banner:-<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>}
                        echo ""
                        echo "Backend SSH destino:"
                        echo "  1) 22  - OpenSSH"
                        echo "  2) 90  - Dropbear moderno"
                        echo "  3) 143 - Dropbear 2016 Ubuntu 18 (recomendado)"
                        echo "  4) Otro puerto personalizado"
                        read -p "Opción [3]: " be_opt
                        case ${be_opt:-3} in
                            1) ssh_port=22 ;;
                            2) ssh_port=90 ;;
                            3) ssh_port=143 ;;
                            4) read -p "Puerto: " ssh_port ;;
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
                        screen -ls | grep "proxy-" | awk -F'.' '{print $2}' | grep proxy | while read n; do
                            port=$(echo $n | sed 's/proxy-//')
                            cfg=$(grep "^${port}|" /etc/proxy-python/proxies.conf 2>/dev/null)
                            echo "  :$port — ${cfg:-sin config}"
                        done
                        screen -ls | grep -q "proxy-" || echo "  Ninguno activo"
                        echo ""
                        echo "Configuración guardada:"
                        cat /etc/proxy-python/proxies.conf 2>/dev/null || echo "  Sin configuración"
                        read -p "ENTER..."
                        ;;
                    4)
                        echo "Proxies activos:"
                        screen -ls | grep "proxy-" | awk '{print $1}'
                        echo ""
                        read -p "Puerto a detener: " del_port
                        [ -n "$del_port" ] && stop_proxy "$del_port"
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            5)
                clear
                echo "PUERTOS Y SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "OpenSSH (puerto 22):"
                ss -tlnp | grep ':22 ' | grep -v grep
                echo ""
                echo "Dropbear (puerto 90):"
                ss -tlnp | grep ':90 ' | grep -v grep
                echo ""
                echo "Dropbear Legacy (puerto 143 - Ubuntu 18):"
                ss -tlnp | grep ':143 ' | grep -v grep
                echo ""
                echo "Stunnel SSL (puertos 443, 444, 777):"
                ss -tlnp | grep -E ':(443|444|777) ' | grep stunnel | grep -v grep
                echo ""
                echo "Squid Proxy (puertos 3128, 8888):"
                ss -tlnp | grep -E ':(3128|8888) ' | grep -v grep
                echo ""
                echo "Python Proxies (80, 8080, 8880):"
                ss -tlnp | grep -E ':(80|8080|8880) ' | grep python | grep -v grep
                echo ""
                echo "BadVPN UDPGW (puerto UDP 7300):"
                ss -ulnp | grep ':7300 ' | grep -v grep
                echo ""
                echo "Hysteria UDP:"
                ps aux | grep hysteria | grep -v grep || echo "No activo"
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER para continuar..."
                ;;
            6)
                clear
                echo "BANNER HTTP/1.1"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "Banner actual:"
                grep "BANNER_TEXT = " /etc/proxy-python/proxy.py
                echo ""
                read -p "Nuevo texto [HTML o texto simple]: " new_banner
                new_banner=${new_banner:-<span style=\"background-color: #000000;\"><span style=\"color:#eeff01;\">MSY VPN SCRIPT</span></span>}
                
                sed -i "s/BANNER_TEXT = .*/BANNER_TEXT = '$new_banner'/" /etc/proxy-python/proxy.py
                echo ""
                echo "✓ Banner actualizado a: $new_banner"
                echo ""
                echo "→ Reinicia los proxies desde Opción 11"
                read -p "ENTER para continuar..."
                ;;
            7)
                clear
                echo "BANNERS SSH"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Cambiar banner OpenSSH (22)"
                echo "2) Cambiar banner Dropbear (90)"
                echo "3) Cambiar banner Dropbear Legacy (143)"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " banner_opt
                
                case $banner_opt in
                    1)
                        clear
                        echo "BANNER OPENSSH ACTUAL:"
                        cat /etc/ssh/banner.txt
                        echo ""
                        echo "Nuevo banner (multilínea, FIN para terminar):"
                        > /tmp/new_banner.txt
                        while true; do
                            read -r line
                            if [ "$line" = "FIN" ]; then
                                break
                            fi
                            echo "$line" >> /tmp/new_banner.txt
                        done
                        
                        if [ -s /tmp/new_banner.txt ]; then
                            cp /tmp/new_banner.txt /etc/ssh/banner.txt
                            systemctl restart ssh
                            echo "✓ Banner OpenSSH actualizado"
                        fi
                        rm -f /tmp/new_banner.txt
                        read -p "ENTER..."
                        ;;
                    2)
                        clear
                        echo "BANNER DROPBEAR ACTUAL:"
                        cat /etc/dropbear/banner.txt
                        echo ""
                        echo "Nuevo banner (multilínea, FIN para terminar):"
                        > /tmp/new_banner.txt
                        while true; do
                            read -r line
                            if [ "$line" = "FIN" ]; then
                                break
                            fi
                            echo "$line" >> /tmp/new_banner.txt
                        done
                        
                        if [ -s /tmp/new_banner.txt ]; then
                            cp /tmp/new_banner.txt /etc/dropbear/banner.txt
                            systemctl restart dropbear
                            echo "✓ Banner Dropbear (90) actualizado"
                        fi
                        rm -f /tmp/new_banner.txt
                        read -p "ENTER..."
                        ;;
                    3)
                        clear
                        echo "BANNER DROPBEAR LEGACY (143) ACTUAL:"
                        cat /etc/dropbear/banner-legacy.txt 2>/dev/null || echo "(sin banner)"
                        echo ""
                        echo "Nuevo banner (multilínea, FIN para terminar):"
                        > /tmp/new_banner.txt
                        while true; do
                            read -r line
                            if [ "$line" = "FIN" ]; then
                                break
                            fi
                            echo "$line" >> /tmp/new_banner.txt
                        done
                        
                        if [ -s /tmp/new_banner.txt ]; then
                            cp /tmp/new_banner.txt /etc/dropbear/banner-legacy.txt
                            systemctl restart dropbear-legacy 2>/dev/null ||                                 pkill -HUP dropbear 2>/dev/null
                            echo "✓ Banner Dropbear Legacy (143) actualizado"
                        fi
                        rm -f /tmp/new_banner.txt
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            8)
                clear
                echo "TÚNELES SSL/TLS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Ver túneles activos"
                echo "2) Agregar nuevo túnel"
                echo "3) Eliminar túnel"
                echo "4) Reiniciar Stunnel"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " tunnel_opt
                
                case $tunnel_opt in
                    1)
                        clear
                        echo "TÚNELES SSL ACTIVOS:"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        cat /etc/stunnel/stunnel.conf | grep -E '\[|accept|connect'
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
                        echo ""
                        echo "Backend destino:"
                        echo "  22  - OpenSSH"
                        echo "  90  - Dropbear (recomendado)"
                        read -p "Puerto destino [90]: " tunnel_dest
                        tunnel_dest=${tunnel_dest:-90}
                        
                        cat >> /etc/stunnel/stunnel.conf <<TUNNELEOF

[$tunnel_name]
accept = $tunnel_port
connect = 127.0.0.1:$tunnel_dest
TUNNELEOF
                        
                        ufw allow $tunnel_port/tcp 2>/dev/null
                        systemctl restart stunnel4
                        
                        echo ""
                        echo "✓ Túnel $tunnel_name creado en puerto $tunnel_port"
                        read -p "ENTER..."
                        ;;
                    3)
                        clear
                        echo "ELIMINAR TÚNEL"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        read -p "Puerto del túnel a eliminar: " del_port
                        
                        sed -i "/accept = $del_port/,+1 d" /etc/stunnel/stunnel.conf
                        sed -i "/\[.*\]/{ N; /accept = $del_port/d; }" /etc/stunnel/stunnel.conf
                        
                        systemctl restart stunnel4
                        echo "✓ Túnel en puerto $del_port eliminado"
                        read -p "ENTER..."
                        ;;
                    4)
                        systemctl restart stunnel4
                        echo "✓ Stunnel reiniciado"
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            9)
                clear
                if [ -f /usr/local/bin/hysteria-manager ]; then
                    bash /usr/local/bin/hysteria-manager
                else
                    echo "⚠ Hysteria UDP Manager no está instalado"
                    echo ""
                    read -p "¿Deseas instalarlo ahora? (s/n): " install_hyst
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
            10)
                clear
                echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}        ${BOLD}ESTADO DE SERVICIOS${NC}              ${CYAN}║${NC}"
                echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
                echo ""
                systemctl is-active --quiet ssh && echo -e "${GREEN}✓ OpenSSH: Activo${NC} (puerto 22)" || echo -e "${RED}✗ OpenSSH: Inactivo${NC}"
                systemctl is-active --quiet dropbear && echo -e "${GREEN}✓ Dropbear 2020: Activo${NC} (puerto 90)" || echo -e "${RED}✗ Dropbear 2020: Inactivo${NC}"
                systemctl is-active --quiet dropbear-legacy && echo -e "${GREEN}✓ Dropbear 2016: Activo${NC} (puerto 143)" || echo -e "${RED}✗ Dropbear 2016: Inactivo${NC}"
                systemctl is-active --quiet stunnel4 && echo -e "${GREEN}✓ Stunnel: Activo${NC} (puertos 443, 444, 777)" || echo -e "${RED}✗ Stunnel: Inactivo${NC}"
                
                systemctl is-active --quiet badvpn-udpgw && echo -e "${GREEN}✓ BadVPN: Activo${NC} (puerto 7300)" || echo -e "${RED}✗ BadVPN: Inactivo${NC}"
                echo ""
                echo -e "${YELLOW}Swap:${NC} ${CYAN}$(free -h | grep Swap | awk '{print $2}')${NC}"
                echo ""
                echo -e "${YELLOW}Python Proxies activos:${NC}"
                screen -ls | grep "proxy-" | wc -l | xargs echo -e "  ${CYAN}Total:${NC}"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                read -p "ENTER para continuar..."
                ;;
            11)
                clear
                echo "REINICIAR SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Reiniciar proxies (HTTP)"
                echo "2) Reiniciar OpenSSH"
                echo "3) Reiniciar Dropbear"
                echo "4) Reiniciar Stunnel"
                echo "5) Reiniciar TODO"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "ENTER..." ;;
                    2) systemctl restart ssh && echo "✓ OpenSSH reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    3) systemctl restart dropbear && echo "✓ Dropbear (90)" || echo "✗ Error"
                       systemctl restart dropbear-legacy 2>/dev/null && echo "✓ Dropbear Legacy (143)" || true
                       read -p "ENTER..." ;;
                    4) systemctl restart stunnel4 && echo "✓ Stunnel reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    5) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
                ;;
            12)
                clear
                echo "VERSIONES DE DROPBEAR INSTALADAS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "Dropbear Sistema (Puerto 90):"
                /usr/sbin/dropbear -V 2>&1 | head -n 1
                echo ""
                echo "Dropbear Legacy Compilado (Puerto 143):"
                if [ -f /opt/dropbear-2016/sbin/dropbear ]; then
                    /opt/dropbear-2016/sbin/dropbear -V 2>&1 | head -n 1
                    echo ""
                    echo "Estado del servicio:"
                    systemctl is-active --quiet dropbear-legacy && echo "  ✓ Dropbear 2016 - ACTIVO" || echo "  ✗ Dropbear 2016 - INACTIVO"
                else
                    echo "  No instalado (se usa el Dropbear del sistema)"
                fi
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER para continuar..."
                ;;
            13)
                show_monitor
                ;;
            14)
                run_speedtest
                ;;
            15)
                clear
                echo "LIMPIEZA DE DISCO"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Uso actual del disco:"
                df -h / | awk 'NR==2{print "  Total: "$2"  Usado: "$3"  Libre: "$4"  ("$5")"}'
                echo ""
                echo "Analizando qué ocupa más espacio..."
                echo ""
                echo "Top 10 archivos/carpetas grandes:"
                du -sh /var/log/* 2>/dev/null | sort -rh | head -5 | sed 's/^/  /'
                du -sh /tmp/* 2>/dev/null | sort -rh | head -3 | sed 's/^/  /'
                echo ""
                echo "Limpiando..."
                # Rotar logs grandes ahora
                logrotate -f /etc/logrotate.d/msy-vpn 2>/dev/null
                # Vaciar journald
                journalctl --vacuum-size=30M 2>/dev/null
                # Limpiar apt cache
                apt-get clean 2>/dev/null
                apt-get autoremove -y 2>/dev/null
                # Limpiar /tmp
                find /tmp -type f -mtime +1 -delete 2>/dev/null
                # Limpiar logs de stunnel si son grandes
                if [ -f /var/log/stunnel4/stunnel.log ]; then
                    size=$(stat -c%s /var/log/stunnel4/stunnel.log 2>/dev/null || echo 0)
                    if [ "$size" -gt 10485760 ]; then
                        > /var/log/stunnel4/stunnel.log
                        echo "  ✓ Log de Stunnel vaciado (era >10MB)"
                    fi
                fi
                # Limpiar fuentes de compilación si quedaron
                rm -rf /usr/src/dropbear-2016.74 /usr/src/dropbear-2016.74.tar.bz2 2>/dev/null
                rm -rf /usr/src/badvpn 2>/dev/null
                echo ""
                echo "Uso del disco después de limpieza:"
                df -h / | awk 'NR==2{print "  Total: "$2"  Usado: "$3"  Libre: "$4"  ("$5")"}'
                echo ""
                echo "✓ Limpieza completada"
                read -p "ENTER para continuar..."
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
echo "Configurando menú automático..."

cat >> /root/.bashrc <<'AUTOEOF'

# MSY VPN - Menú automático
if [ -t 0 ]; then
    if [ -f /usr/local/bin/vpn-panel ]; then
        vpn-panel
    fi
fi
AUTOEOF

# ====================
# FIREWALL
# ====================
echo "Configurando firewall..."

ufw --force disable
ufw --force reset

ufw --force disable
echo "✓ UFW desactivado (firewall deshabilitado)"

# ====================
# CREAR USUARIO INICIAL
# ====================
echo "Creando usuario VPN inicial..."

USER_VPN="vpnuser"
PASS_VPN="msy$(openssl rand -hex 4)"

if id "$USER_VPN" &>/dev/null; then
    userdel -r $USER_VPN 2>/dev/null
fi

useradd -m -s /bin/bash $USER_VPN
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
echo ""
echo "Iniciando proxies por defecto..."

source /root/ssh-vpn-functions.sh

restore_proxies

# ====================
# OPTIMIZACIONES SISTEMA
# ====================
cat >> /etc/sysctl.conf <<EOF

# Optimizaciones MSY VPN v14
net.ipv4.ip_forward = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 20
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_slow_start_after_idle = 0
vm.swappiness = 10
EOF

sysctl -p >/dev/null 2>&1

# ====================
# INFORMACIÓN FINAL
# ====================
# Definir colores para el banner final
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

if [ "$1" = "menu" ]; then
    menu_principal
    exit 0
fi

clear
echo -e "
${CYAN}╔══════════════════════════════════════════════╗${NC}
${CYAN}║${NC}   ${GREEN}✓ INSTALACIÓN COMPLETADA - v14 SSL+${NC}    ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════════════╝${NC}

${YELLOW}IP:${NC} ${CYAN}$IP${NC}

${GREEN}SERVICIOS SSH:${NC}
${GREEN}✓${NC} OpenSSH:           puerto 22  (max 200 sesiones)
${GREEN}✓${NC} Dropbear 2016:     puerto 143 (SSH-2.0-ByJuanitoProSniff)

${GREEN}STUNNEL SSL/TLS:${NC}
${GREEN}✓${NC} Puerto 443 → Dropbear 143
${GREEN}✓${NC} Puerto 444 → OpenSSH 22
${GREEN}✓${NC} Puerto 777 → Dropbear 143 (Experimental)
${GREEN}✓${NC} Watchdog activo (auto-recupera SSL si falla)

${GREEN}PROXIES HTTP:${NC}
${GREEN}✓${NC} Python ThreadPool: 80, 8080, 8880, 8888 → SSH 143
${GREEN}✓${NC} Soporta 500 conexiones simultáneas por proxy

${GREEN}OTROS:${NC}
${GREEN}✓${NC} BadVPN UDPGW:      7300
${GREEN}✓${NC} Hysteria UDP:      Opción 9 del panel
${GREEN}✓${NC} UFW:               Desactivado
${GREEN}✓${NC} Swap:              2GB activado

${CYAN}MEJORAS v14:${NC}
${GREEN}✓${NC} Rotación automática de logs (evita disco lleno)
${GREEN}✓${NC} Journald limitado a 50MB (evita disco lleno)
${GREEN}✓${NC} Watchdog SSL/Stunnel (auto-recuperación)
${GREEN}✓${NC} Proxy Python con ThreadPoolExecutor (500 workers)
${GREEN}✓${NC} TCP keepalive optimizado (detecta caídos en 90s)
${GREEN}✓${NC} net.core.somaxconn=65535 (más conexiones kernel)
${GREEN}✓${NC} Límite de sesiones por usuario configurable
${GREEN}✓${NC} Opción 15 en panel: Limpieza de disco manual
${GREEN}✓${NC} Compatible Ubuntu 18→25, cualquier arquitectura

${YELLOW}CREDENCIALES:${NC}
${CYAN}Usuario:${NC} $USER_VPN
${CYAN}Password:${NC} $PASS_VPN

${YELLOW}PANEL:${NC} ejecutar ${CYAN}vpn-panel${NC} (auto al conectar)
${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
"

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v10 SSL+ COMPLETO

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear 2016: 143
- Stunnel SSL/TLS COMPLETO:
  * Puerto 443 → Dropbear 143
  * Puerto 444 → OpenSSH 22
  * Puerto 777 → Dropbear 143 (Experimental)

CAPACIDADES STUNNEL:
- SSL Directo (IP/Dominio + Puerto + SNI)
- SSL Inverso (Host remoto + SNI tu dominio)
- WebSocket sobre SSL/TLS (wss://)
- Payload personalizado
- Proxy Protocol
- SNI Flexible (acepta CUALQUIER dominio)
- Certificado Wildcard (*)
- TLS 1.2 y TLS 1.3
- Compresión zlib
- Timeouts optimizados para WebSocket

PROXIES:
- Python HTTP: 80, 8080, 8880, 8888 → SSH 143

OTROS:
- BadVPN UDPGW: 7300
- Hysteria UDP: Opción 9 del menú

USUARIO INICIAL:
$USER_VPN / $PASS_VPN

MÉTODOS DE CONEXIÓN SOPORTADOS:
1. SSL Directo:
   - Host: tu-ip-o-dominio
   - Puerto: 443
   - Usuario/Password: SSH
   - SNI: www.google.com (o cualquier otro)

2. SSL Inverso:
   - Host: www.google.com (o cualquier otro)
   - Puerto: 443
   - SNI: tu-dominio.com
   - Usuario/Password: SSH

3. WebSocket:
   - URL: wss://tu-dominio.com:443
   - Usuario/Password: SSH

4. Con Payload:
   - Método: GET/POST/CONNECT
   - Host Header: personalizado
   - SNI: flexible

LOGS:
- Stunnel: /var/log/stunnel4/stunnel.log
- SSH: /var/log/auth.log

COMANDOS:
- Panel: vpn-panel
- Ver log Stunnel: tail -f /var/log/stunnel4/stunnel.log
- Test SSL: openssl s_client -connect localhost:443 -servername test.com

INFOEOF

echo "Información guardada en /root/vpn-info.txt"
echo ""
echo -e "${GREEN}Abriendo panel de administración...${NC}"
sleep 2
/usr/local/bin/vpn-panel
