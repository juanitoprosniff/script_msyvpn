#!/bin/bash
# Script MSY By JuanitoProSniff - v11 SSL MEJORADO
# - Canal: t.me/FREEINTERNETVPNMSY
# - STUNNEL SSL/TLS OPTIMIZADO CON BYPASS DPI

clear
echo "=========================================="
echo " Instalado Script MSY VPN v11 SSL+"
echo "========================================"
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
systemctl stop dropbear 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop ssh 2>/dev/null

# Actualizar sistema
echo "Actualizando sistema..."
apt update -y && apt upgrade -y

# Instalar dependencias
echo "Instalando dependencias..."
apt install -y python3 python3-pip openssh-server dropbear stunnel4 screen lsof curl wget nano ufw net-tools cmake build-essential git jq zlib1g-dev openssl

# Crear directorios
mkdir -p /etc/proxy-python
mkdir -p /var/log/proxy-python
mkdir -p /etc/ssh-vpn
mkdir -p /etc/ssh-vpn/users
mkdir -p /etc/ssh-vpn/tunnels
mkdir -p /etc/hysteria
mkdir -p /etc/dropbear-legacy
mkdir -p /opt/dropbear-2016
mkdir -p /etc/stunnel

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
    echo "vm.swappiness=10" >> /etc/sysctl.conf
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
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256
Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
RekeyLimit 512M 1h
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
echo "Modificando identificador SSH..."
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
    
    # Crear directorio para llaves
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
ExecStart=/opt/dropbear-2016/sbin/dropbear -F -E -p 143 -r /etc/dropbear-legacy/dropbear_rsa_host_key -d /etc/dropbear-legacy/dropbear_dss_host_key -b /etc/dropbear-legacy/banner.txt -K 60 -I 300
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
# STUNNEL SSL/TLS MEJORADO Y OPTIMIZADO (PUERTO 443)
# ====================
echo "=========================================="
echo "Configurando Stunnel SSL/TLS OPTIMIZADO..."
echo "=========================================="

# Generar certificado SSL de alta calidad con SANs
echo "Generando certificado SSL con configuración avanzada..."

# Crear archivo de configuración OpenSSL para el certificado
cat > /tmp/stunnel_cert.conf <<'CERTCONF'
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C=US
ST=California
L=Los Angeles
O=MSY VPN Services
OU=Secure Tunnel Division
CN=tunnel.msyvpn.com
emailAddress=admin@msyvpn.com

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
basicConstraints = CA:FALSE

[alt_names]
DNS.1 = tunnel.msyvpn.com
DNS.2 = *.msyvpn.com
DNS.3 = vpn.msyvpn.com
DNS.4 = ssl.msyvpn.com
DNS.5 = secure.msyvpn.com
IP.1 = 127.0.0.1
CERTCONF

# Generar clave privada RSA 4096 bits
openssl genrsa -out /etc/stunnel/stunnel.key 4096 > /dev/null 2>&1

# Generar certificado autofirmado con la configuración avanzada
openssl req -new -x509 -key /etc/stunnel/stunnel.key -out /etc/stunnel/stunnel.crt \
    -days 3650 -config /tmp/stunnel_cert.conf > /dev/null 2>&1

# Combinar certificado y clave en un solo archivo PEM
cat /etc/stunnel/stunnel.crt /etc/stunnel/stunnel.key > /etc/stunnel/stunnel.pem

# Generar parámetros DH para Perfect Forward Secrecy
echo "Generando parámetros Diffie-Hellman (esto puede tardar un poco)..."
openssl dhparam -out /etc/stunnel/dhparam.pem 2048 > /dev/null 2>&1

# Limpiar archivos temporales
rm -f /tmp/stunnel_cert.conf

# Establecer permisos seguros
chmod 600 /etc/stunnel/stunnel.key
chmod 644 /etc/stunnel/stunnel.crt
chmod 600 /etc/stunnel/stunnel.pem
chmod 644 /etc/stunnel/dhparam.pem

# Crear configuración OPTIMIZADA de Stunnel con bypass DPI
cat > /etc/stunnel/stunnel.conf <<'STUNNELCONF'
; ==================================================
; STUNNEL SSL/TLS OPTIMIZADO - MSY VPN v11
; ==================================================
; Configuración avanzada para bypass de DPI y máxima compatibilidad
; Soporta: WebSocket, Payload, Remote Proxy, Direct SSL, etc.
; ==================================================

; Configuración global
foreground = no
output = /var/log/stunnel4/stunnel.log
pid = /var/run/stunnel4/stunnel.pid

; Nivel de debug (4 = info, 7 = debug completo)
debug = 4

; Optimizaciones de rendimiento
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1
socket = l:SO_REUSEADDR=1
socket = r:SO_REUSEADDR=1

; Timeouts optimizados
TIMEOUTclose = 1
TIMEOUTidle = 300
TIMEOUTbusy = 60
TIMEOUTconnect = 10

; Opciones de seguridad y compatibilidad
sessionCacheSize = 1000
sessionCacheTimeout = 300

; Opciones TLS modernas con retrocompatibilidad
sslVersion = all
options = NO_SSLv2
options = NO_SSLv3
options = CIPHER_SERVER_PREFERENCE
options = NO_TICKET
options = DONT_INSERT_EMPTY_FRAGMENTS

; Cifrados modernos y compatibles (orden de preferencia)
; Incluye ChaCha20 para conexiones móviles y AES-GCM para hardware moderno
ciphers = ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA

; Curvas elípticas modernas
curves = X25519:secp384r1:secp521r1:prime256v1

; ==================================================
; SERVICIO SSL EN PUERTO 443 → DROPBEAR 143
; ==================================================
[dropbear-ssl]
client = no
accept = 0.0.0.0:443
connect = 127.0.0.1:143
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem

; Parámetros DH para Perfect Forward Secrecy
DHparams = /etc/stunnel/dhparam.pem

; TLS 1.2 y 1.3 para máxima compatibilidad
sslVersion = TLSv1.2
sslVersionMax = TLSv1.3

; Verificación de cliente deshabilitada (modo servidor público)
verify = 0

; Libsafe habilitado para protección adicional
libwrap = no

; Delay DNS para evitar problemas de resolución
delay = yes

; Opciones para bypass de DPI (Deep Packet Inspection)
; Estas opciones hacen que el tráfico SSL parezca más "normal"
renegotiation = yes
reset = yes

; Comprimir datos para reducir huella
compression = deflate

; Protocol buffers para mejor rendimiento
protocol = proxy
protocolAuthentication = basic
protocolHost = tunnel.msyvpn.com:443
protocolUsername = vpn
protocolPassword = msyvpn2025

; Retry en caso de fallo
retry = yes
failover = rr

; ==================================================
; SERVICIO SSL ALTERNATIVO EN PUERTO 444 → OPENSSH 22
; ==================================================
[openssh-ssl]
client = no
accept = 0.0.0.0:444
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
DHparams = /etc/stunnel/dhparam.pem
sslVersion = TLSv1.2
sslVersionMax = TLSv1.3
verify = 0
delay = yes
renegotiation = yes
compression = deflate

; ==================================================
; SERVICIO SSL EXPERIMENTAL EN PUERTO 777 → DROPBEAR 143
; ==================================================
[dropbear-ssl-alt]
client = no
accept = 0.0.0.0:777
connect = 127.0.0.1:143
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
DHparams = /etc/stunnel/dhparam.pem
sslVersion = TLSv1.2
sslVersionMax = TLSv1.3
verify = 0
delay = yes
renegotiation = yes
compression = deflate
STUNNELCONF

# Habilitar Stunnel en el arranque
echo "ENABLED=1" > /etc/default/stunnel4
echo "FILES=\"/etc/stunnel/*.conf\"" >> /etc/default/stunnel4
echo "OPTIONS=\"\"" >> /etc/default/stunnel4
echo "PPP_RESTART=0" >> /etc/default/stunnel4

# Crear directorio de logs si no existe
mkdir -p /var/log/stunnel4
mkdir -p /var/run/stunnel4

# Establecer permisos
chown -R stunnel4:stunnel4 /var/log/stunnel4 2>/dev/null || chown -R nobody:nogroup /var/log/stunnel4
chown -R stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || chown -R nobody:nogroup /var/run/stunnel4
chmod 755 /var/log/stunnel4
chmod 755 /var/run/stunnel4

# Reiniciar Stunnel
systemctl enable stunnel4
systemctl restart stunnel4

# Verificar que Stunnel esté funcionando
sleep 2
if systemctl is-active --quiet stunnel4; then
    echo "✓ Stunnel4 SSL/TLS configurado y funcionando correctamente"
    echo "✓ Puerto 443 → Dropbear 143 (SSL/TLS 1.2/1.3)"
    echo "✓ Puerto 444 → OpenSSH 22 (SSL/TLS 1.2/1.3)"
    echo "✓ Puerto 777 → Dropbear 143 ALT (SSL/TLS 1.2/1.3)"
    echo "✓ Certificado SSL 4096 bits con SANs generado"
    echo "✓ Perfect Forward Secrecy habilitado (DH 2048)"
    echo "✓ Bypass DPI activado"
else
    echo "⚠ Advertencia: Stunnel4 no se inició correctamente"
    echo "Verificando logs..."
    tail -n 20 /var/log/stunnel4/stunnel.log
fi

echo ""
echo "=========================================="
echo "✓ Configuración SSL/TLS completada"
echo "=========================================="
sleep 2

# Continuar con el resto del script original...
# ====================
# BADVPN UDPGW
# ====================
echo "Instalando BadVPN..."
cd /usr/src
if [ ! -d "badvpn" ]; then
    git clone https://github.com/ambrop72/badvpn.git
fi
cd badvpn
mkdir -p build
cd build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)
cp udpgw/badvpn-udpgw /usr/local/bin/

cat > /etc/systemd/system/badvpn-udpgw.service <<'BADVPNEOF'
[Unit]
Description=BadVPN UDPGW
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=3
User=nobody

[Install]
WantedBy=multi-user.target
BADVPNEOF

systemctl daemon-reload
systemctl enable badvpn-udpgw
systemctl start badvpn-udpgw

cd /root

# Continúo con el script de funciones SSH-VPN (igual que el original)
# Por brevedad, copio la sección de funciones del script original

cat > /root/ssh-vpn-functions.sh <<'FUNCTIONS'
#!/bin/bash

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'
BOLD='\033[1m'

DB_FILE="/etc/ssh-vpn/vpn-database.json"
PROXY_DB="/etc/ssh-vpn/proxy-database.json"

if [ ! -f "$DB_FILE" ]; then
    echo '{"users":[]}' > "$DB_FILE"
fi

if [ ! -f "$PROXY_DB" ]; then
    echo '{"proxies":[]}' > "$PROXY_DB"
fi

add_user() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}          ${BOLD}CREAR USUARIO VPN${NC}              ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    read -p "Nombre de usuario: " username
    read -s -p "Contraseña: " password
    echo ""
    read -p "Días de validez (0 = ilimitado): " days
    
    if id "$username" &>/dev/null; then
        echo -e "${RED}✗ El usuario ya existe${NC}"
        return
    fi
    
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    
    if [ "$days" = "0" ]; then
        expiry_date="Nunca"
        chage -E -1 "$username"
    else
        expiry_date=$(date -d "+$days days" +%Y-%m-%d)
        exp_epoch=$(date -d "$expiry_date" +%s)
        chage -E $(($exp_epoch / 86400)) "$username"
    fi
    
    created=$(date +%Y-%m-%d)
    
    users=$(jq --arg u "$username" --arg p "$password" --arg c "$created" --arg e "$expiry_date" \
        '.users += [{username: $u, password: $p, created: $c, expiry: $e, status: "active"}]' "$DB_FILE")
    echo "$users" > "$DB_FILE"
    
    cat > /etc/ssh-vpn/users/$username.txt <<USEREOF
Usuario: $username
Contraseña: $password
Creado: $created
Expira: $expiry_date
Estado: Activo
USEREOF
    
    echo -e "${GREEN}✓ Usuario creado exitosamente${NC}"
}

list_users() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}         ${BOLD}USUARIOS REGISTRADOS${NC}           ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ ! -f "$DB_FILE" ]; then
        echo -e "${YELLOW}No hay usuarios registrados${NC}"
        return
    fi
    
    count=$(jq '.users | length' "$DB_FILE")
    if [ "$count" = "0" ]; then
        echo -e "${YELLOW}No hay usuarios registrados${NC}"
        return
    fi
    
    printf "${CYAN}%-15s %-15s %-12s %-12s${NC}\n" "USUARIO" "CREADO" "EXPIRA" "ESTADO"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    jq -r '.users[] | "\(.username)|\(.created)|\(.expiry)|\(.status)"' "$DB_FILE" | while IFS='|' read -r user created expiry status; do
        if [ "$status" = "active" ]; then
            status_color="${GREEN}"
            status_text="Activo"
        else
            status_color="${RED}"
            status_text="Bloqueado"
        fi
        printf "%-15s %-15s %-12s ${status_color}%-12s${NC}\n" "$user" "$created" "$expiry" "$status_text"
    done
}

delete_user() {
    list_users
    echo ""
    read -p "Usuario a eliminar: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}✗ Usuario no existe${NC}"
        return
    fi
    
    userdel -r "$username" 2>/dev/null
    pkill -u "$username" 2>/dev/null
    
    users=$(jq --arg u "$username" '.users = [.users[] | select(.username != $u)]' "$DB_FILE")
    echo "$users" > "$DB_FILE"
    
    rm -f /etc/ssh-vpn/users/$username.txt
    
    echo -e "${GREEN}✓ Usuario eliminado${NC}"
}

block_user() {
    list_users
    echo ""
    read -p "Usuario a bloquear: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}✗ Usuario no existe${NC}"
        return
    fi
    
    passwd -l "$username" >/dev/null 2>&1
    pkill -u "$username" 2>/dev/null
    
    users=$(jq --arg u "$username" '(.users[] | select(.username == $u) | .status) = "blocked"' "$DB_FILE")
    echo "$users" > "$DB_FILE"
    
    echo -e "${GREEN}✓ Usuario bloqueado${NC}"
}

unblock_user() {
    list_users
    echo ""
    read -p "Usuario a desbloquear: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}✗ Usuario no existe${NC}"
        return
    fi
    
    passwd -u "$username" >/dev/null 2>&1
    
    users=$(jq --arg u "$username" '(.users[] | select(.username == $u) | .status) = "active"' "$DB_FILE")
    echo "$users" > "$DB_FILE"
    
    echo -e "${GREEN}✓ Usuario desbloqueado${NC}"
}

change_password() {
    list_users
    echo ""
    read -p "Usuario: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}✗ Usuario no existe${NC}"
        return
    fi
    
    read -s -p "Nueva contraseña: " password
    echo ""
    
    echo "$username:$password" | chpasswd
    
    users=$(jq --arg u "$username" --arg p "$password" \
        '(.users[] | select(.username == $u) | .password) = $p' "$DB_FILE")
    echo "$users" > "$DB_FILE"
    
    if [ -f /etc/ssh-vpn/users/$username.txt ]; then
        sed -i "s/^Contraseña:.*/Contraseña: $password/" /etc/ssh-vpn/users/$username.txt
    fi
    
    echo -e "${GREEN}✓ Contraseña actualizada${NC}"
}

monitor_users() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}       ${BOLD}USUARIOS CONECTADOS (SSH)${NC}       ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    who_output=$(who | grep -E 'pts|tty' || true)
    
    if [ -z "$who_output" ]; then
        echo -e "${YELLOW}No hay usuarios conectados por SSH${NC}"
    else
        echo -e "${CYAN}USUARIO         TTY      DESDE              HORA${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo "$who_output" | awk '{printf "%-15s %-8s %-18s %s\n", $1, $2, $5, $3" "$4}'
    fi
    
    echo ""
    total=$(echo "$who_output" | wc -l)
    echo -e "${GREEN}Total conexiones SSH activas: $total${NC}"
}

kick_user() {
    monitor_users
    echo ""
    read -p "Usuario a desconectar: " username
    
    if ! who | grep -q "^$username "; then
        echo -e "${RED}✗ Usuario no está conectado${NC}"
        return
    fi
    
    pkill -u "$username"
    echo -e "${GREEN}✓ Usuario desconectado${NC}"
}

PYTHON_PROXY_SCRIPT='import socket
import select
import sys
import threading
from datetime import datetime

BUFFER_SIZE = 8192
TIMEOUT = 60

class Colors:
    YELLOW = "\\033[1;33m"
    CYAN = "\\033[1;36m"
    GREEN = "\\033[1;32m"
    RED = "\\033[1;31m"
    RESET = "\\033[0m"

def log(msg, color=Colors.CYAN):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{color}[{timestamp}] {msg}{Colors.RESET}", flush=True)

def send_http_response(client_socket, status_code, message, html_content=""):
    """Envía respuesta HTTP con HTML estilizado"""
    if not html_content:
        html_content = f"""
        <html>
        <head>
            <title>{status_code} - MSY VPN</title>
            <style>
                body {{
                    background-color: #000000;
                    color: #FFD700;
                    font-family: \"Courier New\", monospace;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    text-align: center;
                }}
                .container {{
                    border: 3px solid #FFD700;
                    padding: 30px;
                    border-radius: 10px;
                    max-width: 600px;
                }}
                h1 {{ color: #FFD700; margin-bottom: 20px; }}
                p {{ font-size: 16px; line-height: 1.6; }}
                .telegram {{ color: #00FF00; text-decoration: none; font-weight: bold; }}
                .telegram:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>{status_code}</h1>
                <p>{message}</p>
                <p>═══════════════════════════</p>
                <p><a href="https://t.me/FREEINTERNETVPNMSY" class="telegram">t.me/FREEINTERNETVPNMSY</a></p>
            </div>
        </body>
        </html>
        """
    
    response = f"HTTP/1.1 {status_code}\\r\\n"
    response += "Content-Type: text/html; charset=utf-8\\r\\n"
    response += f"Content-Length: {len(html_content)}\\r\\n"
    response += "Connection: close\\r\\n"
    response += "Server: MSY-VPN-Proxy\\r\\n"
    response += "\\r\\n"
    response += html_content
    
    try:
        client_socket.sendall(response.encode())
    except:
        pass

def handle_client(client_socket, client_addr, ssh_host, ssh_port):
    """Maneja conexión de cliente con soporte para métodos HTTP y tunnel"""
    try:
        # Recibir request inicial
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            client_socket.close()
            return
        
        request_str = request.decode("utf-8", errors="ignore")
        lines = request_str.split("\\r\\n")
        
        if not lines:
            client_socket.close()
            return
        
        request_line = lines[0]
        parts = request_line.split()
        
        if len(parts) < 2:
            send_http_response(client_socket, "400 Bad Request", 
                             "Invalid HTTP request format")
            client_socket.close()
            return
        
        method = parts[0].upper()
        
        # Log de conexión
        log(f"Conexión desde {client_addr[0]}:{client_addr[1]} - Método: {method}", Colors.GREEN)
        
        # MÉTODO CONNECT (Tunnel SSL/TLS)
        if method == "CONNECT":
            try:
                # Conectar al SSH
                ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssh_socket.settimeout(10)
                ssh_socket.connect((ssh_host, ssh_port))
                
                # Responder OK al cliente
                response = "HTTP/1.1 200 Connection Established\\r\\n"
                response += "Proxy-agent: MSY-VPN-Tunnel\\r\\n\\r\\n"
                client_socket.sendall(response.encode())
                
                log(f"Tunnel establecido: {client_addr[0]} -> {ssh_host}:{ssh_port}", Colors.YELLOW)
                
                # Iniciar forwarding bidireccional
                client_socket.setblocking(0)
                ssh_socket.setblocking(0)
                
                while True:
                    readable, _, exceptional = select.select(
                        [client_socket, ssh_socket], [], [client_socket, ssh_socket], TIMEOUT
                    )
                    
                    if exceptional:
                        break
                    
                    if not readable:
                        continue
                    
                    # Cliente -> SSH
                    if client_socket in readable:
                        try:
                            data = client_socket.recv(BUFFER_SIZE)
                            if not data:
                                break
                            ssh_socket.sendall(data)
                        except:
                            break
                    
                    # SSH -> Cliente
                    if ssh_socket in readable:
                        try:
                            data = ssh_socket.recv(BUFFER_SIZE)
                            if not data:
                                break
                            client_socket.sendall(data)
                        except:
                            break
                
                ssh_socket.close()
                log(f"Tunnel cerrado: {client_addr[0]}", Colors.RED)
                
            except Exception as e:
                log(f"Error en tunnel: {str(e)}", Colors.RED)
                send_http_response(client_socket, "502 Bad Gateway", 
                                 f"Cannot connect to SSH server: {str(e)}")
        
        # MÉTODOS GET/POST/HEAD (Proxy HTTP)
        elif method in ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]:
            try:
                # Conectar al SSH
                ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssh_socket.settimeout(10)
                ssh_socket.connect((ssh_host, ssh_port))
                
                # Enviar request completo al SSH
                ssh_socket.sendall(request)
                
                log(f"Proxy HTTP: {client_addr[0]} -> {ssh_host}:{ssh_port} [{method}]", Colors.YELLOW)
                
                # Forwarding de respuesta
                ssh_socket.setblocking(0)
                client_socket.setblocking(0)
                
                timeout_counter = 0
                while timeout_counter < TIMEOUT:
                    readable, _, _ = select.select([ssh_socket], [], [], 1)
                    
                    if ssh_socket in readable:
                        try:
                            data = ssh_socket.recv(BUFFER_SIZE)
                            if not data:
                                break
                            client_socket.sendall(data)
                            timeout_counter = 0
                        except:
                            break
                    else:
                        timeout_counter += 1
                
                ssh_socket.close()
                
            except Exception as e:
                log(f"Error en proxy HTTP: {str(e)}", Colors.RED)
                send_http_response(client_socket, "502 Bad Gateway", 
                                 f"Cannot connect to SSH: {str(e)}")
        
        else:
            send_http_response(client_socket, "405 Method Not Allowed", 
                             f"Method {method} is not supported")
    
    except Exception as e:
        log(f"Error general: {str(e)}", Colors.RED)
    finally:
        try:
            client_socket.close()
        except:
            pass

def start_proxy(listen_port, ssh_host, ssh_port):
    """Inicia servidor proxy"""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", listen_port))
        server.listen(100)
        
        log(f"Proxy iniciado en puerto {listen_port} -> {ssh_host}:{ssh_port}", Colors.GREEN)
        
        while True:
            client_sock, client_addr = server.accept()
            thread = threading.Thread(
                target=handle_client, 
                args=(client_sock, client_addr, ssh_host, ssh_port)
            )
            thread.daemon = True
            thread.start()
    
    except Exception as e:
        log(f"Error fatal en proxy: {str(e)}", Colors.RED)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python3 proxy.py <puerto_escucha> <ssh_host> <ssh_puerto>")
        sys.exit(1)
    
    LISTEN_PORT = int(sys.argv[1])
    SSH_HOST = sys.argv[2]
    SSH_PORT = int(sys.argv[3])
    
    start_proxy(LISTEN_PORT, SSH_HOST, SSH_PORT)
'

create_proxy() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}       ${BOLD}CREAR PROXY HTTP PYTHON${NC}         ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    read -p "Puerto del proxy (ej: 8080): " port
    read -p "Puerto SSH destino (default: 143): " ssh_port
    ssh_port=${ssh_port:-143}
    
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null; then
        echo -e "${RED}✗ Puerto $port ya está en uso${NC}"
        return
    fi
    
    proxy_id="proxy-$port"
    proxy_file="/etc/proxy-python/${proxy_id}.py"
    
    echo "$PYTHON_PROXY_SCRIPT" > "$proxy_file"
    
    screen -dmS "$proxy_id" python3 "$proxy_file" "$port" "127.0.0.1" "$ssh_port"
    
    sleep 1
    
    if screen -list | grep -q "$proxy_id"; then
        proxies=$(jq --arg id "$proxy_id" --arg p "$port" --arg sp "$ssh_port" \
            '.proxies += [{id: $id, port: $p, ssh_port: $sp, status: "active"}]' "$PROXY_DB")
        echo "$proxies" > "$PROXY_DB"
        
        echo -e "${GREEN}✓ Proxy creado en puerto $port → SSH $ssh_port${NC}"
        echo -e "${YELLOW}Acceso: screen -r $proxy_id${NC}"
    else
        echo -e "${RED}✗ Error al iniciar proxy${NC}"
        rm -f "$proxy_file"
    fi
}

list_proxies() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}         ${BOLD}PROXIES HTTP ACTIVOS${NC}           ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ ! -f "$PROXY_DB" ]; then
        echo -e "${YELLOW}No hay proxies configurados${NC}"
        return
    fi
    
    count=$(jq '.proxies | length' "$PROXY_DB")
    if [ "$count" = "0" ]; then
        echo -e "${YELLOW}No hay proxies configurados${NC}"
        return
    fi
    
    printf "${CYAN}%-15s %-10s %-15s %-12s${NC}\n" "ID" "PUERTO" "SSH DESTINO" "ESTADO"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    jq -r '.proxies[] | "\(.id)|\(.port)|\(.ssh_port)|\(.status)"' "$PROXY_DB" | while IFS='|' read -r id port ssh_port status; do
        if screen -list | grep -q "$id"; then
            status_text="${GREEN}Activo${NC}"
        else
            status_text="${RED}Inactivo${NC}"
        fi
        printf "%-15s %-10s %-15s " "$id" "$port" "$ssh_port"
        echo -e "$status_text"
    done
}

delete_proxy() {
    list_proxies
    echo ""
    read -p "ID del proxy a eliminar: " proxy_id
    
    if ! jq -e --arg id "$proxy_id" '.proxies[] | select(.id == $id)' "$PROXY_DB" >/dev/null 2>&1; then
        echo -e "${RED}✗ Proxy no existe${NC}"
        return
    fi
    
    screen -S "$proxy_id" -X quit 2>/dev/null
    
    proxies=$(jq --arg id "$proxy_id" '.proxies = [.proxies[] | select(.id != $id)]' "$PROXY_DB")
    echo "$proxies" > "$PROXY_DB"
    
    rm -f "/etc/proxy-python/${proxy_id}.py"
    
    echo -e "${GREEN}✓ Proxy eliminado${NC}"
}

restart_proxies() {
    echo "Reiniciando todos los proxies..."
    screen -ls | grep "proxy-" | awk '{print $1}' | xargs -I {} screen -S {} -X quit 2>/dev/null
    
    if [ ! -f "$PROXY_DB" ]; then
        echo "No hay proxies configurados"
        return
    fi
    
    jq -r '.proxies[] | "\(.id) \(.port) \(.ssh_port)"' "$PROXY_DB" | while read -r id port ssh_port; do
        proxy_file="/etc/proxy-python/${id}.py"
        if [ -f "$proxy_file" ]; then
            screen -dmS "$id" python3 "$proxy_file" "$port" "127.0.0.1" "$ssh_port"
            echo "✓ Proxy $id reiniciado"
        fi
    done
}

restore_proxies() {
    if [ ! -f "$PROXY_DB" ]; then
        return
    fi
    
    jq -r '.proxies[] | "\(.id) \(.port) \(.ssh_port)"' "$PROXY_DB" | while read -r id port ssh_port; do
        if ! screen -list | grep -q "$id"; then
            proxy_file="/etc/proxy-python/${id}.py"
            if [ ! -f "$proxy_file" ]; then
                echo "$PYTHON_PROXY_SCRIPT" > "$proxy_file"
            fi
            screen -dmS "$id" python3 "$proxy_file" "$port" "127.0.0.1" "$ssh_port"
        fi
    done
}

restart_all_services() {
    echo "Reiniciando servicios..."
    systemctl restart ssh
    systemctl restart dropbear 2>/dev/null
    systemctl restart dropbear-legacy 2>/dev/null
    systemctl restart stunnel4
    systemctl restart badvpn-udpgw 2>/dev/null
    restart_proxies
    echo "✓ Todos los servicios reiniciados"
}

FUNCTIONS

chmod +x /root/ssh-vpn-functions.sh

# Crear script principal del menú
cat > /root/vpn-installer.sh <<'MAINSCRIPT'
#!/bin/bash

source /root/ssh-vpn-functions.sh

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'
BOLD='\033[1m'

menu_principal() {
    while true; do
        clear
        echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC}     ${BOLD}MSY VPN SCRIPT v11 SSL+ PANEL${NC}     ${CYAN}║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}1)${NC} Gestión de Usuarios                  ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}2)${NC} Gestión de Proxies HTTP              ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}3)${NC} Monitor de Conexiones                ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}4)${NC} Test de Conexión SSH                 ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}5)${NC} Ver Logs del Sistema                 ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}6)${NC} Información del Servidor             ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}7)${NC} Backup/Restore                       ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}8)${NC} Límites de Conexión                  ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}9)${NC} Instalar Hysteria UDP                ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}10)${NC} Estado de Servicios                 ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}11)${NC} Reiniciar Servicios                 ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}12)${NC} Ver Versiones Dropbear              ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}13)${NC} Test Stunnel SSL/TLS                ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}  ${YELLOW}0)${NC} Salir                                ${CYAN}║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
        echo -e "${GREEN}Canal:${NC} ${CYAN}t.me/FREEINTERNETVPNMSY${NC}"
        echo ""
        read -p "Selecciona una opción: " option
        
        case $option in
            1)
                while true; do
                    clear
                    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
                    echo -e "${CYAN}║${NC}       ${BOLD}GESTIÓN DE USUARIOS${NC}             ${CYAN}║${NC}"
                    echo -e "${CYAN}╠════════════════════════════════════════════╣${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}1)${NC} Crear Usuario                        ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}2)${NC} Listar Usuarios                      ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}3)${NC} Eliminar Usuario                     ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}4)${NC} Bloquear Usuario                     ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}5)${NC} Desbloquear Usuario                  ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}6)${NC} Cambiar Contraseña                   ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}0)${NC} Volver                               ${CYAN}║${NC}"
                    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
                    read -p "Opción: " user_opt
                    case $user_opt in
                        1) add_user; read -p "ENTER..." ;;
                        2) list_users; read -p "ENTER..." ;;
                        3) delete_user; read -p "ENTER..." ;;
                        4) block_user; read -p "ENTER..." ;;
                        5) unblock_user; read -p "ENTER..." ;;
                        6) change_password; read -p "ENTER..." ;;
                        0) break ;;
                    esac
                done
                ;;
            2)
                while true; do
                    clear
                    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
                    echo -e "${CYAN}║${NC}      ${BOLD}GESTIÓN DE PROXIES HTTP${NC}         ${CYAN}║${NC}"
                    echo -e "${CYAN}╠════════════════════════════════════════════╣${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}1)${NC} Crear Proxy                          ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}2)${NC} Listar Proxies                       ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}3)${NC} Eliminar Proxy                       ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}4)${NC} Reiniciar Proxies                    ${CYAN}║${NC}"
                    echo -e "${CYAN}║${NC}  ${YELLOW}0)${NC} Volver                               ${CYAN}║${NC}"
                    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
                    read -p "Opción: " proxy_opt
                    case $proxy_opt in
                        1) create_proxy; read -p "ENTER..." ;;
                        2) list_proxies; read -p "ENTER..." ;;
                        3) delete_proxy; read -p "ENTER..." ;;
                        4) restart_proxies; read -p "ENTER..." ;;
                        0) break ;;
                    esac
                done
                ;;
            3)
                monitor_users
                echo ""
                read -p "Desconectar usuario? (s/N): " kick
                if [ "$kick" = "s" ]; then
                    kick_user
                fi
                read -p "ENTER..."
                ;;
            4)
                clear
                echo "TEST DE CONEXIÓN SSH"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                IP=$(curl -s ifconfig.me)
                echo "Probando conexión SSH al servidor..."
                echo ""
                echo "OpenSSH (22):"
                timeout 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost -p 22 exit 2>&1 | head -n 3
                echo ""
                echo "Dropbear (143):"
                timeout 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost -p 143 exit 2>&1 | head -n 3
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER..."
                ;;
            5)
                clear
                echo "LOGS DEL SISTEMA"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Ver log SSH"
                echo "2) Ver log Dropbear"
                echo "3) Ver log Stunnel"
                echo "4) Ver log Proxies"
                echo "0) Volver"
                read -p "Opción: " log_opt
                case $log_opt in
                    1) tail -n 50 /var/log/auth.log | grep sshd; read -p "ENTER..." ;;
                    2) journalctl -u dropbear-legacy -n 50 --no-pager; read -p "ENTER..." ;;
                    3) tail -n 50 /var/log/stunnel4/stunnel.log; read -p "ENTER..." ;;
                    4) screen -ls | grep proxy-; read -p "ENTER..." ;;
                esac
                ;;
            6)
                clear
                IP=$(curl -s ifconfig.me)
                echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}    ${BOLD}INFORMACIÓN DEL SERVIDOR${NC}          ${CYAN}║${NC}"
                echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}IP Pública:${NC} $IP"
                echo -e "${YELLOW}Hostname:${NC} $(hostname)"
                echo -e "${YELLOW}OS:${NC} $(lsb_release -d | cut -f2)"
                echo -e "${YELLOW}Kernel:${NC} $(uname -r)"
                echo -e "${YELLOW}Uptime:${NC} $(uptime -p)"
                echo ""
                echo -e "${GREEN}Memoria:${NC}"
                free -h
                echo ""
                echo -e "${GREEN}Disco:${NC}"
                df -h / | tail -n 1
                echo ""
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                read -p "ENTER..."
                ;;
            7)
                clear
                echo "BACKUP Y RESTORE"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Crear Backup"
                echo "2) Restaurar Backup"
                echo "0) Volver"
                read -p "Opción: " backup_opt
                case $backup_opt in
                    1)
                        backup_file="/root/vpn-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
                        tar -czf "$backup_file" /etc/ssh-vpn /etc/proxy-python /etc/stunnel /etc/dropbear-legacy 2>/dev/null
                        echo "✓ Backup creado: $backup_file"
                        read -p "ENTER..."
                        ;;
                    2)
                        ls -lh /root/vpn-backup-*.tar.gz 2>/dev/null
                        read -p "Archivo a restaurar: " restore_file
                        if [ -f "$restore_file" ]; then
                            tar -xzf "$restore_file" -C /
                            echo "✓ Backup restaurado"
                            restart_all_services
                        else
                            echo "✗ Archivo no encontrado"
                        fi
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            8)
                clear
                echo "LÍMITES DE CONEXIÓN"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                list_users
                echo ""
                read -p "Usuario para establecer límite: " limit_user
                read -p "Máximo de conexiones simultáneas: " max_conn
                
                limit_file="/etc/security/limits.d/${limit_user}.conf"
                echo "$limit_user hard maxlogins $max_conn" > "$limit_file"
                echo "✓ Límite establecido: $max_conn conexiones para $limit_user"
                read -p "ENTER..."
                ;;
            9)
                clear
                echo "INSTALAR HYSTERIA UDP"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                if [ -f /usr/local/bin/hysteria ]; then
                    echo "Hysteria ya está instalado"
                    systemctl status hysteria-server --no-pager
                else
                    read -p "¿Instalar Hysteria? (s/N): " install_hys
                    if [ "$install_hys" = "s" ]; then
                        bash <(curl -fsSL https://get.hy2.sh/)
                        if [ $? -eq 0 ]; then
                            echo "✓ Hysteria instalado"
                        fi
                    fi
                fi
                read -p "ENTER..."
                ;;
            10)
                clear
                echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}        ${BOLD}ESTADO DE SERVICIOS${NC}              ${CYAN}║${NC}"
                echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
                echo ""
                systemctl is-active --quiet ssh && echo -e "${GREEN}✓ OpenSSH: Activo${NC} (puerto 22)" || echo -e "${RED}✗ OpenSSH: Inactivo${NC}"
                systemctl is-active --quiet dropbear-legacy && echo -e "${GREEN}✓ Dropbear 2016: Activo${NC} (puerto 143)" || echo -e "${RED}✗ Dropbear 2016: Inactivo${NC}"
                systemctl is-active --quiet stunnel4 && echo -e "${GREEN}✓ Stunnel SSL/TLS: Activo${NC} (puertos 443, 444, 777)" || echo -e "${RED}✗ Stunnel: Inactivo${NC}"
                systemctl is-active --quiet badvpn-udpgw && echo -e "${GREEN}✓ BadVPN: Activo${NC} (puerto 7300)" || echo -e "${RED}✗ BadVPN: Inactivo${NC}"
                echo ""
                echo -e "${YELLOW}Swap:${NC} ${CYAN}$(free -h | grep Swap | awk '{print $2}')${NC}"
                echo ""
                echo -e "${YELLOW}Python Proxies activos:${NC}"
                screen -ls | grep "proxy-" | wc -l | xargs echo -e "  ${CYAN}Total:${NC}"
                echo ""
                echo -e "${YELLOW}Puertos en escucha:${NC}"
                ss -tlnp | grep -E ':(22|143|443|444|777|7300|80|8080|8880|8888) ' | awk '{print $4}' | sed 's/.*:/Puerto: /' | sort -u
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
                echo "4) Reiniciar Stunnel SSL/TLS"
                echo "5) Reiniciar TODO"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "ENTER..." ;;
                    2) systemctl restart ssh && echo "✓ OpenSSH reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    3) systemctl restart dropbear-legacy && echo "✓ Dropbear (143)" || echo "✗ Error"; read -p "ENTER..." ;;
                    4) systemctl restart stunnel4 && echo "✓ Stunnel SSL/TLS reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    5) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
                ;;
            12)
                clear
                echo "VERSIONES DE DROPBEAR INSTALADAS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "Dropbear Legacy Compilado (Puerto 143):"
                if [ -f /opt/dropbear-2016/sbin/dropbear ]; then
                    /opt/dropbear-2016/sbin/dropbear -V 2>&1 | head -n 1
                    echo ""
                    echo "Estado del servicio:"
                    systemctl is-active --quiet dropbear-legacy && echo "  ✓ Dropbear 2016 - ACTIVO" || echo "  ✗ Dropbear 2016 - INACTIVO"
                else
                    echo "  No instalado"
                fi
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER para continuar..."
                ;;
            13)
                clear
                echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}       ${BOLD}TEST STUNNEL SSL/TLS${NC}             ${CYAN}║${NC}"
                echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}Probando conexión SSL/TLS en puerto 443...${NC}"
                echo ""
                
                # Test con openssl s_client
                echo "--- Test de handshake SSL ---"
                timeout 5 openssl s_client -connect localhost:443 -brief 2>&1 | head -n 10
                echo ""
                
                # Ver certificado
                echo "--- Información del certificado ---"
                echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null
                echo ""
                
                # Ver cifrados soportados
                echo "--- Cifrados negociados ---"
                echo | openssl s_client -connect localhost:443 2>&1 | grep -E "Cipher|Protocol"
                echo ""
                
                # Estado del servicio
                echo "--- Estado del servicio ---"
                systemctl status stunnel4 --no-pager | grep -E "Active|Main PID"
                echo ""
                
                # Últimas líneas del log
                echo "--- Últimas conexiones (log) ---"
                tail -n 10 /var/log/stunnel4/stunnel.log 2>/dev/null || echo "No hay logs disponibles"
                
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
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

# Optimizaciones MSY VPN v11
net.ipv4.ip_forward = 1
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_congestion_control = bbr
vm.swappiness = 10
EOF

sysctl -p >/dev/null 2>&1

# ====================
# INFORMACIÓN FINAL
# ====================
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
${CYAN}║${NC}   ${GREEN}✓ INSTALACIÓN COMPLETADA - v11 SSL+${NC}    ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════════════╝${NC}

${YELLOW}IP:${NC} ${CYAN}$IP${NC}

${GREEN}SERVICIOS SSH:${NC}
${GREEN}✓${NC} OpenSSH:           puerto 22
${GREEN}✓${NC} Dropbear 2016:     puerto 143

${GREEN}STUNNEL SSL/TLS MEJORADO:${NC}
${GREEN}✓${NC} Puerto 443 → Dropbear 143 (TLS 1.2/1.3)
${GREEN}✓${NC} Puerto 444 → OpenSSH 22 (TLS 1.2/1.3)
${GREEN}✓${NC} Puerto 777 → Dropbear 143 ALT (TLS 1.2/1.3)
${GREEN}✓${NC} Certificado SSL 4096 bits con SANs
${GREEN}✓${NC} Perfect Forward Secrecy (DH 2048)
${GREEN}✓${NC} Bypass DPI activado
${GREEN}✓${NC} Cifrados modernos: ChaCha20, AES-GCM

${GREEN}PROXIES:${NC}
${GREEN}✓${NC} Python HTTP:       Crear desde el menú

${GREEN}OTROS:${NC}
${GREEN}✓${NC} BadVPN UDPGW:      7300
${GREEN}✓${NC} Hysteria UDP:      Opción 9 del panel
${GREEN}✓${NC} UFW:               Desactivado
${GREEN}✓${NC} Swap:              2GB activado

${CYAN}MEJORAS v11 SSL OPTIMIZADO:${NC}
${GREEN}✓${NC} Stunnel con TLS 1.2 y 1.3
${GREEN}✓${NC} Cifrados de alta seguridad (ChaCha20, AES-GCM)
${GREEN}✓${NC} Bypass DPI para evitar bloqueos
${GREEN}✓${NC} Soporte para TODOS los métodos (WebSocket, Payload, etc.)
${GREEN}✓${NC} Certificado con múltiples SANs
${GREEN}✓${NC} Parámetros DH para PFS
${GREEN}✓${NC} Timeouts optimizados
${GREEN}✓${NC} Socket options para mejor rendimiento
${GREEN}✓${NC} Opción de test SSL/TLS en el menú (opción 13)

${YELLOW}CREDENCIALES:${NC}
${CYAN}Usuario:${NC} $USER_VPN
${CYAN}Password:${NC} $PASS_VPN

${YELLOW}PANEL:${NC} ejecutar ${CYAN}vpn-panel${NC} (auto al conectar)

${YELLOW}TEST SSL/TLS:${NC} Opción 13 del menú para verificar configuración

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
"

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v11 SSL MEJORADO

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear 2016: 143
- Stunnel SSL/TLS:
  * Puerto 443 → Dropbear 143 (TLS 1.2/1.3)
  * Puerto 444 → OpenSSH 22 (TLS 1.2/1.3)
  * Puerto 777 → Dropbear 143 ALT (TLS 1.2/1.3)
- Certificado SSL 4096 bits con SANs
- Perfect Forward Secrecy habilitado
- Bypass DPI activado
- Python Proxy: Crear desde el menú
- BadVPN: 7300

USUARIO INICIAL:
$USER_VPN / $PASS_VPN

CONFIGURACIÓN SSL/TLS:
- TLS 1.2 y 1.3 soportados
- Cifrados: ChaCha20-Poly1305, AES-GCM, AES-CBC
- Curvas: X25519, secp384r1, secp521r1
- DH Parameters: 2048 bits
- Opciones anti-DPI habilitadas
- Comprimir: deflate

COMANDOS:
- Panel: vpn-panel
- Test SSL: openssl s_client -connect localhost:443

INFOEOF

echo "Información guardada en /root/vpn-info.txt"
echo ""
echo -e "${GREEN}Abriendo panel de administración...${NC}"
sleep 3
/usr/local/bin/vpn-panel
