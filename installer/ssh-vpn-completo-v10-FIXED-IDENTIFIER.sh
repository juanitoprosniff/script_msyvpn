#!/bin/bash
# Script SSH VPN Completo - V10
# - OpenSSH: 22, Dropbear: 90, Dropbear Legacy 2016 (Ubuntu 18): 143
# - Dropbear 2016.74 COMPILADO DESDE FUENTE
# - Proxy Python multi-método: HTTP, CONNECT, WebSocket
# - Proxies persistentes con systemd (auto-restore al reiniciar)
# - Contador usuarios real (IPs únicas por ss)
# - Swap 2GB, Hysteria UDP, BadVPN UDPGW
# - UFW desactivado
# - Canal: t.me/FREEINTERNETVPNMSY

clear
echo "================================================"
echo "   SSH VPN Server - Versión Final v10"
echo "   Dropbear 2020 + 2016 + Hysteria + Swap 2GB"
echo "================================================"
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
systemctl stop squid 2>/dev/null
systemctl stop dropbear 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop ssh 2>/dev/null

# Actualizar sistema
echo "Actualizando sistema..."
apt update -y && apt upgrade -y

# Instalar dependencias
echo "Instalando dependencias..."
apt install -y python3 python3-pip openssh-server dropbear squid stunnel4 screen lsof curl wget nano ufw net-tools cmake build-essential git jq zlib1g-dev

# Crear directorios
mkdir -p /etc/proxy-python
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
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    
    echo "✓ Swap de 2GB configurado y activado"
else
    echo "✓ Swap ya existe"
fi

# ====================
# CONFIGURAR OPENSSH (PUERTO 22)
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
# CONFIGURAR DROPBEAR (PUERTO 90)
# ====================
echo "Configurando Dropbear en puerto 90..."

cat > /etc/dropbear/banner.txt <<'EOF'
═══════════════════════════
t.me/FREEINTERNETVPNMSY
═══════════════════════════
EOF

cat > /etc/default/dropbear <<'EOF'
NO_START=0
DROPBEAR_PORT=90
DROPBEAR_EXTRA_ARGS="-w -b /etc/dropbear/banner.txt -K 60 -I 300"
DROPBEAR_BANNER=""
DROPBEAR_RECEIVE_WINDOW=65536
EOF

systemctl enable dropbear
systemctl restart dropbear

# ====================
# COMPILAR E INSTALAR DROPBEAR 2016.74 EN PUERTO 143
# Compatible con clientes SSH más antiguos de Ubuntu 18
# ====================
echo "===================================================="
echo "Compilando Dropbear 2016.74 desde fuente..."
echo "Esto puede tardar unos minutos..."
echo "===================================================="

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

# MODIFICAR EL IDENTIFICADOR SSH CORRECTAMENTE
echo "===================================================="
echo "Modificando identificador SSH a 'SSH-2.0-ByJuanitoProSniff'..."
echo "===================================================="

# Verificar si existe sysoptions.h (archivo correcto)
if [ -f sysoptions.h ]; then
    echo "✓ Archivo sysoptions.h encontrado"
    
    # Hacer backup del archivo original
    cp sysoptions.h sysoptions.h.backup
    
    # Modificar el LOCAL_IDENT en sysoptions.h
    # Buscar la línea que contiene LOCAL_IDENT y reemplazarla
    sed -i 's|^#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' sysoptions.h
    
    # Verificar el cambio
    if grep -q 'LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"' sysoptions.h; then
        echo "✓ Identificador SSH modificado correctamente"
        echo ""
        echo "Cambio realizado:"
        grep "LOCAL_IDENT" sysoptions.h
        echo ""
    else
        echo "⚠ Advertencia: No se pudo verificar el cambio automáticamente"
        echo "Intentando método alternativo..."
        
        # Método alternativo: buscar y reemplazar cualquier variante
        sed -i '/LOCAL_IDENT/c\#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"' sysoptions.h
    fi
else
    echo "⚠ Advertencia: sysoptions.h no encontrado, intentando con default_options.h"
    
    if [ -f default_options.h ]; then
        sed -i 's|^#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' default_options.h
        echo "✓ Modificado en default_options.h"
    fi
fi

sleep 2

# Configurar con opciones de compatibilidad
echo "Configurando compilación..."

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
═══════════════════════════
t.me/FREEINTERNETVPNMSY
═══════════════════════════
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
    echo ""
    echo "Para verificar el identificador SSH personalizado,"
    echo "conecta con un cliente SSH y observa el banner de versión"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    sleep 3
fi

cd /root

# ====================
# CONFIGURAR STUNNEL (PUERTO 443)
# ====================
echo "Configurando Stunnel en puerto 443..."

# Generar certificado SSL
openssl req -new -x509 -days 3650 -nodes \
    -out /etc/stunnel/stunnel.pem \
    -keyout /etc/stunnel/stunnel.pem \
    -subj "/C=US/ST=State/L=City/O=MSY/CN=vpn.msy.com" 2>/dev/null

chmod 600 /etc/stunnel/stunnel.pem

cat > /etc/stunnel/stunnel.conf <<'EOF'
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem

[dropbear-ssl-143]
accept = 443
connect = 127.0.0.1:143

[dropbear-ssl-90]
accept = 444
connect = 127.0.0.1:90

[dropbear-ssl2-143]
accept = 777
connect = 127.0.0.1:143
EOF

cat > /etc/default/stunnel4 <<'EOF'
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER=""
PPP_RESTART=0
EOF

systemctl enable stunnel4
systemctl restart stunnel4

# ====================
# CONFIGURAR SQUID (PUERTOS 3128, 8888)
# ====================
echo "Configurando Squid proxy..."

cat > /etc/squid/squid.conf <<'EOF'
http_port 3128
http_port 8888
acl all src 0.0.0.0/0
http_access allow all
dns_nameservers 8.8.8.8 1.1.1.1
EOF

systemctl enable squid
systemctl restart squid

# ====================
# BADVPN UDPGW (PUERTO 7300)
# ====================
echo "Instalando BadVPN UDPGW..."

if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
    cd /usr/src
    git clone https://github.com/ambrop72/badvpn.git
    cd badvpn
    mkdir build
    cd build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make -j$(nproc)
    cp udpgw/badvpn-udpgw /usr/local/bin/
    cd /root
fi

cat > /etc/systemd/system/badvpn-udpgw.service <<'EOF'
[Unit]
Description=BadVPN UDPGW
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable badvpn-udpgw
systemctl start badvpn-udpgw

# ====================
# PROXY PYTHON MULTI-MÉTODO
# ====================
echo "Creando proxy Python multi-método..."

cat > /etc/proxy-python/multi-proxy.py <<'PYEOF'
#!/usr/bin/env python3
import socket
import select
import sys
import threading
import base64
import hashlib
import struct

class MultiProxy:
    def __init__(self, listen_port, ssh_host, ssh_port):
        self.listen_port = listen_port
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        
    def handle_client(self, client):
        try:
            request = client.recv(4096)
            if not request:
                client.close()
                return
            
            # Detectar tipo de protocolo
            if request.startswith(b'GET ') or request.startswith(b'POST ') or \
               request.startswith(b'HEAD ') or request.startswith(b'PUT '):
                self.handle_http(client, request)
            elif request.startswith(b'CONNECT '):
                self.handle_connect(client, request)
            elif self.is_websocket_upgrade(request):
                self.handle_websocket(client, request)
            else:
                self.handle_direct(client, request)
        except:
            pass
        finally:
            try:
                client.close()
            except:
                pass
    
    def is_websocket_upgrade(self, request):
        return b'Upgrade: websocket' in request or b'upgrade: websocket' in request
    
    def handle_http(self, client, request):
        try:
            ssh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh.connect((self.ssh_host, self.ssh_port))
            ssh.sendall(request)
            self.tunnel(client, ssh)
        except:
            client.close()
    
    def handle_connect(self, client, request):
        try:
            client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            ssh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh.connect((self.ssh_host, self.ssh_port))
            self.tunnel(client, ssh)
        except:
            client.close()
    
    def handle_websocket(self, client, request):
        try:
            # Aceptar WebSocket upgrade
            key = None
            for line in request.split(b'\r\n'):
                if line.startswith(b'Sec-WebSocket-Key:'):
                    key = line.split(b': ')[1]
                    break
            
            if key:
                accept = base64.b64encode(
                    hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest()
                )
                response = (
                    b'HTTP/1.1 101 Switching Protocols\r\n'
                    b'Upgrade: websocket\r\n'
                    b'Connection: Upgrade\r\n'
                    b'Sec-WebSocket-Accept: ' + accept + b'\r\n\r\n'
                )
                client.sendall(response)
                
                ssh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssh.connect((self.ssh_host, self.ssh_port))
                self.tunnel(client, ssh)
        except:
            client.close()
    
    def handle_direct(self, client, request):
        try:
            ssh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh.connect((self.ssh_host, self.ssh_port))
            ssh.sendall(request)
            self.tunnel(client, ssh)
        except:
            client.close()
    
    def tunnel(self, client, remote):
        try:
            while True:
                r, w, e = select.select([client, remote], [], [], 60)
                if client in r:
                    data = client.recv(8192)
                    if not data:
                        break
                    remote.sendall(data)
                if remote in r:
                    data = remote.recv(8192)
                    if not data:
                        break
                    client.sendall(data)
        except:
            pass
        finally:
            client.close()
            remote.close()
    
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.listen_port))
        server.listen(200)
        
        print(f"Proxy escuchando en puerto {self.listen_port} -> SSH {self.ssh_host}:{self.ssh_port}")
        
        while True:
            try:
                client, addr = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client,))
                thread.daemon = True
                thread.start()
            except KeyboardInterrupt:
                break
            except:
                continue

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Uso: multi-proxy.py <puerto_escucha> <ssh_host> <ssh_puerto>")
        sys.exit(1)
    
    proxy = MultiProxy(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]))
    proxy.start()
PYEOF

chmod +x /etc/proxy-python/multi-proxy.py

# ====================
# SCRIPT DE GESTIÓN
# ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

# Funciones del sistema VPN

function start_proxy() {
    local port=$1
    local ssh_port=${2:-143}
    local screen_name="proxy-${port}"
    
    # Verificar si ya existe
    if screen -list | grep -q "$screen_name"; then
        echo "Proxy en puerto $port ya está ejecutándose"
        return 1
    fi
    
    # Iniciar proxy
    screen -dmS "$screen_name" python3 /etc/proxy-python/multi-proxy.py "$port" "127.0.0.1" "$ssh_port"
    
    # Verificar inicio
    sleep 0.5
    if screen -list | grep -q "$screen_name"; then
        echo "✓ Proxy iniciado en puerto $port → SSH:$ssh_port"
        
        # Guardar configuración para persistencia
        echo "$port:$ssh_port" >> /etc/ssh-vpn/active-proxies.txt
        sort -u /etc/ssh-vpn/active-proxies.txt -o /etc/ssh-vpn/active-proxies.txt
        return 0
    else
        echo "✗ Error iniciando proxy en puerto $port"
        return 1
    fi
}

function stop_proxy() {
    local port=$1
    local screen_name="proxy-${port}"
    
    if screen -list | grep -q "$screen_name"; then
        screen -S "$screen_name" -X quit
        # Remover de configuración
        sed -i "/^$port:/d" /etc/ssh-vpn/active-proxies.txt
        echo "✓ Proxy detenido: puerto $port"
        return 0
    else
        echo "Proxy en puerto $port no está ejecutándose"
        return 1
    fi
}

function stop_all_proxies() {
    screen -ls | grep "proxy-" | cut -d. -f1 | awk '{print $1}' | xargs -I {} screen -S {} -X quit 2>/dev/null
    > /etc/ssh-vpn/active-proxies.txt
    echo "✓ Todos los proxies detenidos"
}

function list_proxies() {
    echo "PROXIES ACTIVOS:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local count=0
    for session in $(screen -ls | grep "proxy-" | cut -d. -f2 | awk '{print $1}'); do
        local port=$(echo "$session" | cut -d- -f2)
        local ssh_port=$(grep "^$port:" /etc/ssh-vpn/active-proxies.txt | cut -d: -f2)
        echo "  Puerto $port → SSH:${ssh_port:-143}"
        ((count++))
    done
    
    if [ $count -eq 0 ]; then
        echo "  (ninguno)"
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

function restore_proxies() {
    if [ -f /etc/ssh-vpn/active-proxies.txt ]; then
        echo "Restaurando proxies configurados..."
        while IFS=: read -r port ssh_port; do
            if [ -n "$port" ] && [ -n "$ssh_port" ]; then
                start_proxy "$port" "$ssh_port" >/dev/null 2>&1
            fi
        done < /etc/ssh-vpn/active-proxies.txt
    fi
}

function restart_proxies() {
    echo "Reiniciando proxies..."
    local temp_file=$(mktemp)
    cp /etc/ssh-vpn/active-proxies.txt "$temp_file" 2>/dev/null
    
    stop_all_proxies
    sleep 1
    
    if [ -f "$temp_file" ]; then
        while IFS=: read -r port ssh_port; do
            if [ -n "$port" ] && [ -n "$ssh_port" ]; then
                start_proxy "$port" "$ssh_port"
            fi
        done < "$temp_file"
        rm -f "$temp_file"
    fi
    
    echo "✓ Proxies reiniciados"
}

function count_users() {
    # Contar IPs únicas conectadas por SSH (ss)
    ss -tn state established '( sport = :22 or sport = :90 or sport = :143 )' | \
        awk 'NR>1 {print $5}' | cut -d: -f1 | sort -u | wc -l
}

function restart_all_services() {
    echo "Reiniciando todos los servicios..."
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart dropbear-legacy 2>/dev/null
    systemctl restart stunnel4
    systemctl restart squid
    systemctl restart badvpn-udpgw
    restart_proxies
    echo "✓ Todos los servicios reiniciados"
}
FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

# Crear servicio systemd para auto-restaurar proxies
cat > /etc/systemd/system/ssh-vpn-restore.service <<'SVCEOF'
[Unit]
Description=SSH VPN Proxy Restore
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'source /root/ssh-vpn-functions.sh && restore_proxies'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable ssh-vpn-restore

# Crear archivo de proxies activos
touch /etc/ssh-vpn/active-proxies.txt

# ====================
# MENÚ PRINCIPAL
# ====================
cat > /root/vpn-installer.sh <<'MAINSCRIPT'
#!/bin/bash

# Colores
BOLD='\033[1m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m' # Sin color

source /root/ssh-vpn-functions.sh

function menu_principal() {
    while true; do
        clear
        
        # Banner colorido
        echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC}     ${BOLD}${YELLOW}MSY VPN SERVER MANAGER v10${NC}         ${CYAN}║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
        echo ""
        
        # Información del sistema
        IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        USERS=$(count_users)
        SWAP=$(free -h | grep Swap | awk '{print $2}')
        
        echo -e "${GREEN}IP Servidor:${NC} ${CYAN}$IP${NC}"
        echo -e "${GREEN}Usuarios conectados:${NC} ${CYAN}$USERS${NC}"
        echo -e "${GREEN}Swap disponible:${NC} ${CYAN}$SWAP${NC}"
        echo ""
        
        # Opciones del menú
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}1)${NC}  Crear usuario SSH"
        echo -e "${YELLOW}2)${NC}  Eliminar usuario SSH"
        echo -e "${YELLOW}3)${NC}  Renovar expiración de usuario"
        echo -e "${YELLOW}4)${NC}  Información de usuario"
        echo -e "${YELLOW}5)${NC}  Lista de todos los usuarios"
        echo -e "${YELLOW}6)${NC}  Usuarios conectados (monitor)"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}7)${NC}  Gestionar Python Proxies"
        echo -e "${YELLOW}8)${NC}  Limitar conexiones de usuario"
        echo -e "${YELLOW}9)${NC}  Instalar Hysteria (UDP VPN)"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}10)${NC} Ver estado de servicios"
        echo -e "${YELLOW}11)${NC} Reiniciar servicios"
        echo -e "${YELLOW}12)${NC} Ver versiones de Dropbear"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}0)${NC}  Salir"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        read -p "Selecciona una opción: " option
        
        case $option in
            1)
                clear
                echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}          ${BOLD}CREAR USUARIO SSH${NC}               ${CYAN}║${NC}"
                echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
                echo ""
                read -p "Nombre de usuario: " username
                read -p "Contraseña: " password
                read -p "Días de expiración (0 = ilimitado): " days
                
                if id "$username" &>/dev/null; then
                    echo -e "${RED}✗ El usuario ya existe${NC}"
                    read -p "ENTER para continuar..."
                    continue
                fi
                
                useradd -m -s /bin/bash "$username"
                echo "$username:$password" | chpasswd
                
                if [ "$days" -gt 0 ]; then
                    expire_date=$(date -d "+$days days" +%Y-%m-%d)
                    chage -E $(date -d "$expire_date" +%Y-%m-%d) "$username"
                    expire_info="$expire_date"
                else
                    expire_info="Ilimitado"
                fi
                
                cat > /etc/ssh-vpn/users/$username.txt <<USEREOF
Usuario: $username
Contraseña: $password
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: $expire_info
Estado: Activo
USEREOF
                
                clear
                echo -e "${GREEN}✓ Usuario creado exitosamente${NC}"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${YELLOW}Usuario:${NC} $username"
                echo -e "${YELLOW}Contraseña:${NC} $password"
                echo -e "${YELLOW}Expiración:${NC} $expire_info"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                read -p "ENTER para continuar..."
                ;;
            2)
                clear
                echo "ELIMINAR USUARIO"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario: " username
                
                if ! id "$username" &>/dev/null; then
                    echo "✗ El usuario no existe"
                    read -p "ENTER..."
                    continue
                fi
                
                userdel -r "$username" 2>/dev/null
                rm -f /etc/ssh-vpn/users/$username.txt
                pkill -u "$username"
                
                echo "✓ Usuario eliminado: $username"
                read -p "ENTER..."
                ;;
            3)
                clear
                echo "RENOVAR EXPIRACIÓN"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario: " username
                
                if ! id "$username" &>/dev/null; then
                    echo "✗ El usuario no existe"
                    read -p "ENTER..."
                    continue
                fi
                
                read -p "Nuevos días de expiración (0 = ilimitado): " days
                
                if [ "$days" -gt 0 ]; then
                    expire_date=$(date -d "+$days days" +%Y-%m-%d)
                    chage -E $(date -d "$expire_date" +%Y-%m-%d) "$username"
                    sed -i "s/Fecha expiración:.*/Fecha expiración: $expire_date/" /etc/ssh-vpn/users/$username.txt
                    echo "✓ Expiración renovada hasta: $expire_date"
                else
                    chage -E -1 "$username"
                    sed -i "s/Fecha expiración:.*/Fecha expiración: Ilimitado/" /etc/ssh-vpn/users/$username.txt
                    echo "✓ Expiración establecida como ilimitada"
                fi
                
                read -p "ENTER..."
                ;;
            4)
                clear
                echo "INFORMACIÓN DE USUARIO"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario: " username
                
                if [ -f /etc/ssh-vpn/users/$username.txt ]; then
                    cat /etc/ssh-vpn/users/$username.txt
                else
                    echo "✗ Usuario no encontrado en el sistema"
                fi
                
                echo ""
                read -p "ENTER..."
                ;;
            5)
                clear
                echo "LISTA DE USUARIOS SSH"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                
                if [ "$(ls -A /etc/ssh-vpn/users/ 2>/dev/null)" ]; then
                    for userfile in /etc/ssh-vpn/users/*.txt; do
                        if [ -f "$userfile" ]; then
                            echo ""
                            cat "$userfile"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        fi
                    done
                else
                    echo "No hay usuarios creados"
                fi
                
                echo ""
                read -p "ENTER..."
                ;;
            6)
                clear
                echo "USUARIOS CONECTADOS (CTRL+C para salir)"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                
                watch -n 2 'echo "=== SSH (22) ==="; ss -tn state established "( sport = :22 )" | awk "NR>1 {print \$5}" | cut -d: -f1 | sort -u; echo ""; echo "=== DROPBEAR (90) ==="; ss -tn state established "( sport = :90 )" | awk "NR>1 {print \$5}" | cut -d: -f1 | sort -u; echo ""; echo "=== DROPBEAR 2016 (143) ==="; ss -tn state established "( sport = :143 )" | awk "NR>1 {print \$5}" | cut -d: -f1 | sort -u'
                ;;
            7)
                clear
                echo "GESTIONAR PYTHON PROXIES"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                list_proxies
                echo ""
                echo "1) Iniciar nuevo proxy"
                echo "2) Detener proxy"
                echo "3) Detener todos los proxies"
                echo "4) Reiniciar proxies"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " proxy_opt
                
                case $proxy_opt in
                    1)
                        read -p "Puerto del proxy (ej: 80, 8080): " port
                        read -p "Puerto SSH destino (22/90/143) [143]: " ssh_port
                        ssh_port=${ssh_port:-143}
                        start_proxy "$port" "$ssh_port"
                        read -p "ENTER..."
                        ;;
                    2)
                        read -p "Puerto del proxy a detener: " port
                        stop_proxy "$port"
                        read -p "ENTER..."
                        ;;
                    3)
                        read -p "¿Detener TODOS los proxies? (s/n): " confirm
                        if [[ $confirm == "s" || $confirm == "S" ]]; then
                            stop_all_proxies
                        fi
                        read -p "ENTER..."
                        ;;
                    4)
                        restart_proxies
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            8)
                clear
                echo "LIMITAR CONEXIONES (usermod -m)"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Usuario: " username
                read -p "Máximo de conexiones: " max_conn
                
                if id "$username" &>/dev/null; then
                    usermod -m $max_conn "$username" 2>/dev/null
                    echo "✓ Límite configurado"
                else
                    echo "✗ Usuario no existe"
                fi
                
                read -p "ENTER..."
                ;;
            9)
                clear
                echo "INSTALAR HYSTERIA (UDP VPN)"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                
                if [ -f /etc/hysteria/installed ]; then
                    echo "Hysteria ya está instalado"
                    read -p "¿Reinstalar? (s/n): " reinstall
                    if [[ $reinstall != "s" && $reinstall != "S" ]]; then
                        read -p "ENTER..."
                        continue
                    fi
                fi
                
                echo "Descargando Hysteria..."
                bash <(curl -fsSL https://get.hy2.sh/) 2>/dev/null || {
                    echo "✗ Error descargando Hysteria"
                    read -p "ENTER..."
                    continue
                }
                
                # Configuración básica
                cat > /etc/hysteria/config.yaml <<HYEOF
listen: :36712

acme:
  domains:
    - $(hostname -f 2>/dev/null || echo "vpn.example.com")
  email: admin@example.com

auth:
  type: password
  password: $(openssl rand -hex 16)

masquerade:
  type: proxy
  proxy:
    url: https://www.google.com
    rewriteHost: true
HYEOF
                
                touch /etc/hysteria/installed
                
                echo "✓ Hysteria instalado"
                echo "Configuración: /etc/hysteria/config.yaml"
                echo ""
                read -p "¿Iniciar Hysteria ahora? (s/n): " start_hys
                if [[ $start_hys == "s" || $start_hys == "S" ]]; then
                    systemctl enable hysteria-server
                    systemctl start hysteria-server
                    echo "✓ Hysteria iniciado"
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
                systemctl is-active --quiet dropbear && echo -e "${GREEN}✓ Dropbear 2020: Activo${NC} (puerto 90)" || echo -e "${RED}✗ Dropbear 2020: Inactivo${NC}"
                systemctl is-active --quiet dropbear-legacy && echo -e "${GREEN}✓ Dropbear 2016: Activo${NC} (puerto 143)" || echo -e "${RED}✗ Dropbear 2016: Inactivo${NC}"
                systemctl is-active --quiet stunnel4 && echo -e "${GREEN}✓ Stunnel: Activo${NC} (puertos 443, 444, 777)" || echo -e "${RED}✗ Stunnel: Inactivo${NC}"
                systemctl is-active --quiet squid && echo -e "${GREEN}✓ Squid: Activo${NC} (puertos 3128, 8888)" || echo -e "${RED}✗ Squid: Inactivo${NC}"
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
                    echo ""
                    echo "Verificar identificador SSH personalizado:"
                    echo "  Conecta con: ssh -p 143 user@$IP"
                    echo "  Deberías ver: SSH-2.0-ByJuanitoProSniff"
                else
                    echo "  No instalado (se usa el Dropbear del sistema)"
                fi
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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

# Optimizaciones MSY VPN
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
IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

if [ "$1" = "menu" ]; then
    menu_principal
    exit 0
fi

clear
cat <<EOF

╔══════════════════════════════════════╗
║   ✓ INSTALACIÓN COMPLETADA - v10    ║
╚══════════════════════════════════════╝

IP: $IP

SERVICIOS SSH:
✓ OpenSSH:           puerto 22
✓ Dropbear 2020:     puerto 90
✓ Dropbear 2016:     puerto 143 (SSH-2.0-ByJuanitoProSniff)
✓ Stunnel SSL:       443→143, 444→90, 777→143

PROXIES:
✓ Proxies HTTP:      80, 8080, 8880 (→ puerto 143 por defecto)
✓ Squid:             3128, 8888

OTROS:
✓ BadVPN UDPGW:      7300
✓ Hysteria UDP:      Opción 9 del panel
✓ UFW:               Desactivado
✓ Swap:              2GB activado

MEJORAS v10 CUSTOM:
✓ Dropbear 2016.74 con identificador SSH-2.0-ByJuanitoProSniff
✓ Puerto 443 Stunnel → Dropbear 2016 (puerto 143)
✓ Banners SSH reducidos y limpios
✓ Menú colorido "MSY VPN SCRIPT"
✓ Sistema de detención de proxies mejorado
✓ Opción 12: Ver versiones instaladas

CREDENCIALES:
Usuario: $USER_VPN
Password: $PASS_VPN

PANEL: ejecutar vpn-panel (auto al conectar)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PARA VERIFICAR EL IDENTIFICADOR SSH:
Conecta con: ssh -v -p 143 $USER_VPN@$IP
Busca la línea que dice: "Remote protocol version 2.0, remote software version ByJuanitoProSniff"

EOF

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v10 CUSTOM

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear 2020: 90
- Dropbear 2016: 143 (SSH-2.0-ByJuanitoProSniff)
- Stunnel SSL: 443→143, 444→90, 777→143
- Python Proxy: 80, 8080, 8880 (conectan al puerto 143 por defecto)
- Squid: 3128, 8888
- BadVPN: 7300
- Hysteria UDP: Opción 9 del menú

USUARIO:
$USER_VPN / $PASS_VPN

SWAP: 2GB activado

DROPBEAR VERSIONS:
- Puerto 90: Dropbear 2020.81 (del sistema)
- Puerto 143: Dropbear 2016.74 (SSH-2.0-ByJuanitoProSniff)

STUNNEL:
- Puerto 443 → Dropbear 2016 (143)
- Puerto 444 → Dropbear 2020 (90)  
- Puerto 777 → Dropbear 2016 (143)

BANNERS: Reducidos y limpios
MENÚ: Colorido "MSY VPN SCRIPT"
PERSISTENCIA: Proxies se restauran tras reinicio
PANEL: vpn-panel (automático al login)

OPCIÓN 12: Ver versiones de Dropbear instaladas

VERIFICAR IDENTIFICADOR:
ssh -v -p 143 $USER_VPN@$IP
Buscar: "Remote protocol version 2.0, remote software version ByJuanitoProSniff"
INFOEOF

echo "Información guardada en /root/vpn-info.txt"
echo ""
read -p "¿Deseas abrir el panel ahora? (s/n): " open_menu
if [[ $open_menu == "s" || $open_menu == "S" ]]; then
    menu_principal
fi
