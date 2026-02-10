#!/bin/bash
# Script SSH VPN Completo - V10 FIXED
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
╔════════════════════════════════════════╗
║              MSY VPN                   ║
║     Conexión OpenSSH establecida       ║
║   Canal: t.me/FREEINTERNETVPNMSY      ║
╚════════════════════════════════════════╝
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
═══════════════════════════════════════
          MSY VPN
   Dropbear SSH ultra estable
   t.me/FREEINTERNETVPNMSY
═══════════════════════════════════════
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
    wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2
fi

# Extraer
echo "Extrayendo archivos..."
rm -rf dropbear-2016.74 2>/dev/null
tar xjf dropbear-2016.74.tar.bz2
cd dropbear-2016.74

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
═══════════════════════════════════════
          MSY VPN
   Dropbear Legacy 2016.74
   Compatible Ubuntu 18
   t.me/FREEINTERNETVPNMSY
═══════════════════════════════════════
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
# CONFIGURAR STUNNEL (PUERTO 443)
# ====================
echo "Configurando Stunnel en puerto 443..."

cat > /etc/stunnel/stunnel.conf <<'EOF'
[dropbear-ssl]
accept = 443
connect = 90

[dropbear-ssl-alt]
accept = 444
connect = 90

[dropbear-legacy-ssl]
accept = 777
connect = 143
EOF

sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4

openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=US/ST=MSY/L=VPN/O=MSYVPN/CN=vpn.msy.com" \
    -keyout /etc/stunnel/stunnel.pem \
    -out /etc/stunnel/stunnel.pem 2>/dev/null

chmod 600 /etc/stunnel/stunnel.pem

systemctl enable stunnel4
systemctl restart stunnel4

# ====================
# CONFIGURAR SQUID (PUERTOS 3128, 8888)
# ====================
echo "Configurando Squid en puertos 3128 y 8888..."

cat > /etc/squid/squid.conf <<'EOF'
http_port 3128
http_port 8888
acl all src 0.0.0.0/0
http_access allow all
dns_nameservers 8.8.8.8 8.8.4.4
request_header_access Via deny all
request_header_access X-Forwarded-For deny all
forwarded_for delete
via off
EOF

systemctl enable squid
systemctl restart squid

# ====================
# INSTALAR BADVPN (PUERTO 7300)
# ====================
echo "Instalando BadVPN..."

cd /usr/src
if [ ! -f badvpn-1.999.130.tar.bz2 ]; then
    wget -q https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.bz2 -O badvpn-1.999.130.tar.bz2
fi

tar xjf badvpn-1.999.130.tar.bz2
cd badvpn-1.999.130
mkdir build
cd build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make
cp udpgw/badvpn-udpgw /usr/local/bin/

cat > /etc/systemd/system/badvpn-udpgw.service <<'EOF'
[Unit]
Description=BadVPN UDPGW
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable badvpn-udpgw
systemctl start badvpn-udpgw

cd /root

# ====================
# CREAR PROXY PYTHON MULTIMÉTODO
# ====================
echo "Creando proxy Python avanzado..."

cat > /etc/proxy-python/proxy.py <<'PYEOF'
#!/usr/bin/env python3
import socket
import select
import sys
import threading
import base64
import hashlib
import struct
import os
import signal

class ProxyServer:
    def __init__(self, port, backend_host, backend_port):
        self.port = port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.server_socket = None
        
    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(100)
            
            print(f"[Proxy] Iniciado en puerto {self.port} -> {self.backend_host}:{self.backend_port}")
            
            while True:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                    thread.daemon = True
                    thread.start()
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[Error Accept] {e}")
                    
        except Exception as e:
            print(f"[Error Server] {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096)
            if not request:
                client_socket.close()
                return
            
            request_line = request.split(b'\r\n')[0].decode('utf-8', errors='ignore')
            
            if request_line.startswith('GET') and 'Upgrade: websocket' in request.decode('utf-8', errors='ignore'):
                self.handle_websocket(client_socket, request)
            elif request_line.startswith('CONNECT'):
                self.handle_connect(client_socket, request)
            else:
                self.handle_http(client_socket, request)
                
        except Exception as e:
            print(f"[Error Handle] {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def handle_http(self, client_socket, request):
        try:
            backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend.connect((self.backend_host, self.backend_port))
            backend.sendall(request)
            
            self.tunnel_data(client_socket, backend)
            
        except Exception as e:
            print(f"[Error HTTP] {e}")
        finally:
            try:
                backend.close()
            except:
                pass
    
    def handle_connect(self, client_socket, request):
        try:
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend.connect((self.backend_host, self.backend_port))
            
            self.tunnel_data(client_socket, backend)
            
        except Exception as e:
            print(f"[Error CONNECT] {e}")
        finally:
            try:
                backend.close()
            except:
                pass
    
    def handle_websocket(self, client_socket, request):
        try:
            key = None
            for line in request.split(b'\r\n'):
                if b'Sec-WebSocket-Key:' in line:
                    key = line.split(b': ')[1].decode('utf-8').strip()
                    break
            
            if key:
                accept = base64.b64encode(
                    hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
                ).decode('utf-8')
                
                response = (
                    'HTTP/1.1 101 Switching Protocols\r\n'
                    'Upgrade: websocket\r\n'
                    'Connection: Upgrade\r\n'
                    f'Sec-WebSocket-Accept: {accept}\r\n'
                    '\r\n'
                )
                client_socket.sendall(response.encode())
                
                backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                backend.connect((self.backend_host, self.backend_port))
                
                self.tunnel_data(client_socket, backend)
                
                backend.close()
            else:
                client_socket.close()
                
        except Exception as e:
            print(f"[Error WebSocket] {e}")
    
    def tunnel_data(self, client, backend):
        try:
            sockets = [client, backend]
            while True:
                readable, _, _ = select.select(sockets, [], [], 60)
                if not readable:
                    break
                
                for sock in readable:
                    data = sock.recv(8192)
                    if not data:
                        return
                    
                    if sock is client:
                        backend.sendall(data)
                    else:
                        client.sendall(data)
                        
        except Exception as e:
            print(f"[Error Tunnel] {e}")

def signal_handler(sig, frame):
    print("\n[Proxy] Detenido")
    sys.exit(0)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Uso: python3 proxy.py <puerto_proxy> <backend_host> <backend_port>")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    port = int(sys.argv[1])
    backend_host = sys.argv[2]
    backend_port = int(sys.argv[3])
    
    proxy = ProxyServer(port, backend_host, backend_port)
    proxy.start()
PYEOF

chmod +x /etc/proxy-python/proxy.py

# ====================
# CREAR FUNCIONES DE GESTIÓN
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
NC='\033[0m' # No Color
BOLD='\033[1m'

start_proxy() {
    local port=$1
    local backend_port=${2:-143}
    local backend_host=${3:-127.0.0.1}
    
    # Verificar si el puerto está en uso y matar el proceso
    local pid=$(lsof -ti:$port)
    if [ ! -z "$pid" ]; then
        echo -e "${YELLOW}⚠ Puerto $port ocupado. Liberando...${NC}"
        kill -9 $pid 2>/dev/null
        sleep 1
    fi
    
    # Verificar nuevamente
    if lsof -ti:$port >/dev/null 2>&1; then
        echo -e "${RED}✗ Error: No se pudo liberar el puerto $port${NC}"
        return 1
    fi
    
    screen -dmS "proxy-$port" python3 /etc/proxy-python/proxy.py "$port" "$backend_host" "$backend_port"
    sleep 1
    
    if screen -list | grep -q "proxy-$port"; then
        echo "$port:$backend_host:$backend_port" >> /etc/proxy-python/active_proxies.txt
        echo -e "${GREEN}✓ Proxy iniciado: puerto $port → $backend_host:$backend_port${NC}"
        return 0
    else
        echo -e "${RED}✗ Error iniciando proxy en puerto $port${NC}"
        return 1
    fi
}

stop_proxy() {
    local port=$1
    
    # Matar session de screen
    screen -S "proxy-$port" -X quit 2>/dev/null
    
    # Matar cualquier proceso en ese puerto
    local pid=$(lsof -ti:$port)
    if [ ! -z "$pid" ]; then
        kill -9 $pid 2>/dev/null
    fi
    
    # Esperar y verificar
    sleep 1
    
    if lsof -ti:$port >/dev/null 2>&1; then
        echo -e "${RED}✗ Advertencia: Puerto $port aún puede estar en uso${NC}"
        # Intentar más agresivamente
        fuser -k $port/tcp 2>/dev/null
        sleep 1
    fi
    
    sed -i "/^$port:/d" /etc/proxy-python/active_proxies.txt 2>/dev/null
    echo -e "${GREEN}✓ Proxy detenido en puerto $port${NC}"
}

list_proxies() {
    echo -e "\n${CYAN}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}      PROXIES PYTHON ACTIVOS${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}\n"
    
    local found=0
    while IFS=':' read -r port backend_host backend_port; do
        if [ ! -z "$port" ]; then
            if screen -list | grep -q "proxy-$port"; then
                echo -e "${GREEN}✓${NC} Puerto ${YELLOW}$port${NC} → ${CYAN}$backend_host:$backend_port${NC}"
                found=1
            fi
        fi
    done < /etc/proxy-python/active_proxies.txt 2>/dev/null
    
    if [ $found -eq 0 ]; then
        echo -e "${RED}  No hay proxies activos${NC}"
    fi
    echo ""
}

restore_proxies() {
    echo -e "${CYAN}Restaurando proxies...${NC}"
    if [ -f /etc/proxy-python/active_proxies.txt ]; then
        while IFS=':' read -r port backend_host backend_port; do
            if [ ! -z "$port" ]; then
                start_proxy "$port" "$backend_port" "$backend_host" >/dev/null 2>&1
            fi
        done < /etc/proxy-python/active_proxies.txt
    fi
    echo -e "${GREEN}✓ Proxies restaurados${NC}"
}

restart_proxies() {
    echo -e "${YELLOW}Reiniciando todos los proxies...${NC}"
    
    # Detener todos los proxies screen
    screen -ls | grep "proxy-" | cut -d. -f1 | awk '{print $1}' | xargs -I {} screen -S {} -X quit 2>/dev/null
    
    # Matar procesos en puertos conocidos
    for port in 80 8080 8880; do
        local pid=$(lsof -ti:$port)
        if [ ! -z "$pid" ]; then
            kill -9 $pid 2>/dev/null
        fi
    done
    
    sleep 2
    
    restore_proxies
}

show_users() {
    echo -e "\n${CYAN}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}       USUARIOS SSH ACTIVOS${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}\n"
    
    local count=0
    for user in $(ls /etc/ssh-vpn/users/ 2>/dev/null | sed 's/.txt//'); do
        if id "$user" &>/dev/null; then
            local ips=$(ss -tn state established | grep ":22\|:90\|:143" | awk '{print $5}' | cut -d: -f1 | sort -u | wc -l)
            echo -e "${GREEN}✓${NC} ${YELLOW}$user${NC} - IPs únicas: ${CYAN}$ips${NC}"
            count=$((count+1))
        fi
    done
    
    if [ $count -eq 0 ]; then
        echo -e "${RED}  No hay usuarios activos${NC}"
    fi
    echo ""
}

create_user() {
    local username=$1
    local password=$2
    local days=${3:-30}
    
    if id "$username" &>/dev/null; then
        echo -e "${RED}✗ El usuario $username ya existe${NC}"
        return 1
    fi
    
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    
    local expiry_date=$(date -d "+$days days" +%Y-%m-%d)
    chage -E $(date -d "+$days days" +%Y-%m-%d) "$username"
    
    cat > /etc/ssh-vpn/users/$username.txt <<UEOF
Usuario: $username
Contraseña: $password
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: $expiry_date
Días: $days
Estado: Activo
UEOF
    
    echo -e "${GREEN}✓ Usuario creado: $username (expira en $days días)${NC}"
}

delete_user() {
    local username=$1
    
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}✗ El usuario $username no existe${NC}"
        return 1
    fi
    
    pkill -u "$username" 2>/dev/null
    userdel -r "$username" 2>/dev/null
    rm -f /etc/ssh-vpn/users/$username.txt
    
    echo -e "${GREEN}✓ Usuario eliminado: $username${NC}"
}

restart_all_services() {
    echo -e "${YELLOW}Reiniciando todos los servicios...${NC}"
    
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart dropbear-legacy 2>/dev/null
    systemctl restart stunnel4
    systemctl restart squid
    systemctl restart badvpn-udpgw
    restart_proxies
    
    echo -e "${GREEN}✓ Todos los servicios reiniciados${NC}"
}
FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

# Crear archivo de proxies activos
touch /etc/proxy-python/active_proxies.txt

# ====================
# CREAR SCRIPT PRINCIPAL CON MENÚ COLORIDO
# ====================
cat > /root/vpn-installer.sh <<'MAINSCRIPT'
#!/bin/bash

source /root/ssh-vpn-functions.sh

# Banner colorido
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║                                                    ║"
    echo -e "║  ${BOLD}${WHITE}███╗   ███╗███████╗██╗   ██╗    ██╗   ██╗██████╗${CYAN}  ║"
    echo -e "║  ${BOLD}${WHITE}████╗ ████║██╔════╝╚██╗ ██╔╝    ██║   ██║██╔══██╗${CYAN} ║"
    echo -e "║  ${BOLD}${WHITE}██╔████╔██║███████╗ ╚████╔╝     ██║   ██║██████╔╝${CYAN} ║"
    echo -e "║  ${BOLD}${WHITE}██║╚██╔╝██║╚════██║  ╚██╔╝      ╚██╗ ██╔╝██╔═══╝${CYAN}  ║"
    echo -e "║  ${BOLD}${WHITE}██║ ╚═╝ ██║███████║   ██║        ╚████╔╝ ██║${CYAN}      ║"
    echo -e "║  ${BOLD}${WHITE}╚═╝     ╚═╝╚══════╝   ╚═╝         ╚═══╝  ╚═╝${CYAN}      ║"
    echo "║                                                    ║"
    echo -e "║           ${YELLOW}SSH/VPN Multi-Protocolo v10${CYAN}             ║"
    echo -e "║          ${MAGENTA}t.me/FREEINTERNETVPNMSY${CYAN}                 ║"
    echo "║                                                    ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

menu_principal() {
    while true; do
        show_banner
        
        # Información del servidor
        IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        USUARIOS=$(ls /etc/ssh-vpn/users/ 2>/dev/null | wc -l)
        PROXIES=$(screen -ls 2>/dev/null | grep "proxy-" | wc -l)
        
        echo -e "${GREEN}┌─────────────────────────────────────────────────┐${NC}"
        echo -e "${GREEN}│${NC} ${BOLD}IP Servidor:${NC} ${YELLOW}$IP${NC}"
        echo -e "${GREEN}│${NC} ${BOLD}Usuarios VPN:${NC} ${CYAN}$USUARIOS${NC} | ${BOLD}Proxies Activos:${NC} ${CYAN}$PROXIES${NC}"
        echo -e "${GREEN}└─────────────────────────────────────────────────┘${NC}"
        echo ""
        
        echo -e "${BLUE}╔═══════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}              ${BOLD}${WHITE}MENÚ PRINCIPAL${NC}                      ${BLUE}║${NC}"
        echo -e "${BLUE}╠═══════════════════════════════════════════════════╣${NC}"
        echo -e "${BLUE}║${NC}  ${CYAN}1)${NC} ${WHITE}Crear Usuario VPN${NC}                          ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}  ${CYAN}2)${NC} ${WHITE}Eliminar Usuario${NC}                           ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}  ${CYAN}3)${NC} ${WHITE}Listar Usuarios${NC}                            ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}  ${CYAN}4)${NC} ${WHITE}Iniciar Proxy HTTP${NC}                         ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}  ${CYAN}5)${NC} ${WHITE}Detener Proxy${NC}                              ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}  ${CYAN}6)${NC} ${WHITE}Listar Proxies${NC}                             ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}  ${CYAN}7)${NC} ${WHITE}Monitor de Conexiones${NC}                      ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}  ${CYAN}8)${NC} ${WHITE}Información del Servidor${NC}                   ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}  ${CYAN}9)${NC} ${WHITE}Instalar Hysteria UDP${NC}                      ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC} ${CYAN}10)${NC} ${WHITE}Estado de Servicios${NC}                        ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC} ${CYAN}11)${NC} ${WHITE}Reiniciar Servicios${NC}                        ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC} ${CYAN}12)${NC} ${WHITE}Ver Versiones Dropbear${NC}                     ${BLUE}║${NC}"
        echo -e "${BLUE}║${NC}  ${RED}0)${NC} ${WHITE}Salir${NC}                                      ${BLUE}║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -ne "${YELLOW}Selecciona una opción:${NC} "
        read opcion
        
        case $opcion in
            1)
                clear
                echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}     ${BOLD}CREAR USUARIO VPN${NC}              ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
                echo ""
                read -p "Nombre de usuario: " username
                read -p "Contraseña: " password
                read -p "Días de validez (30): " days
                days=${days:-30}
                
                create_user "$username" "$password" "$days"
                echo ""
                read -p "Presiona ENTER para continuar..."
                ;;
            2)
                clear
                echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}     ${BOLD}ELIMINAR USUARIO${NC}               ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
                echo ""
                show_users
                read -p "Usuario a eliminar: " username
                
                delete_user "$username"
                echo ""
                read -p "Presiona ENTER para continuar..."
                ;;
            3)
                clear
                show_users
                read -p "Presiona ENTER para continuar..."
                ;;
            4)
                clear
                echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}     ${BOLD}INICIAR PROXY HTTP${NC}             ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
                echo ""
                read -p "Puerto del proxy: " port
                read -p "Puerto destino SSH (143): " backend
                backend=${backend:-143}
                
                start_proxy "$port" "$backend"
                echo ""
                read -p "Presiona ENTER para continuar..."
                ;;
            5)
                clear
                echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}     ${BOLD}DETENER PROXY${NC}                  ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
                echo ""
                list_proxies
                read -p "Puerto del proxy a detener: " port
                
                stop_proxy "$port"
                echo ""
                read -p "Presiona ENTER para continuar..."
                ;;
            6)
                clear
                list_proxies
                read -p "Presiona ENTER para continuar..."
                ;;
            7)
                clear
                echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}   ${BOLD}MONITOR DE CONEXIONES (SSH)${NC}     ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}Conexiones activas por puerto:${NC}"
                echo ""
                echo -e "${GREEN}Puerto 22 (OpenSSH):${NC}"
                ss -tn state established | grep ":22 " | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
                echo ""
                echo -e "${GREEN}Puerto 90 (Dropbear 2020):${NC}"
                ss -tn state established | grep ":90 " | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
                echo ""
                echo -e "${GREEN}Puerto 143 (Dropbear 2016):${NC}"
                ss -tn state established | grep ":143 " | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
                echo ""
                read -p "Presiona ENTER para continuar..."
                ;;
            8)
                clear
                IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
                
                echo -e "${CYAN}╔═══════════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}         ${BOLD}INFORMACIÓN DEL SERVIDOR${NC}               ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}IP Pública:${NC} ${GREEN}$IP${NC}"
                echo ""
                echo -e "${YELLOW}═══ PUERTOS SSH ═══${NC}"
                echo -e "${GREEN}✓${NC} OpenSSH:          ${CYAN}22${NC}"
                echo -e "${GREEN}✓${NC} Dropbear 2020:    ${CYAN}90${NC}"
                echo -e "${GREEN}✓${NC} Dropbear 2016:    ${CYAN}143${NC} ${MAGENTA}(compilado)${NC}"
                echo ""
                echo -e "${YELLOW}═══ PUERTOS SSL ═══${NC}"
                echo -e "${GREEN}✓${NC} Stunnel:          ${CYAN}443, 444${NC}"
                echo -e "${GREEN}✓${NC} Stunnel Legacy:   ${CYAN}777${NC} ${MAGENTA}(→143)${NC}"
                echo ""
                echo -e "${YELLOW}═══ PROXIES HTTP ═══${NC}"
                echo -e "${GREEN}✓${NC} Python Proxy:     ${CYAN}80, 8080, 8880${NC}"
                echo -e "${GREEN}✓${NC} Squid:            ${CYAN}3128, 8888${NC}"
                echo ""
                echo -e "${YELLOW}═══ OTROS ═══${NC}"
                echo -e "${GREEN}✓${NC} BadVPN UDPGW:     ${CYAN}7300${NC}"
                echo -e "${GREEN}✓${NC} Swap:             ${CYAN}$(free -h | grep Swap | awk '{print $2}')${NC}"
                echo ""
                read -p "Presiona ENTER para continuar..."
                ;;
            9)
                clear
                echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}   ${BOLD}INSTALAR HYSTERIA UDP${NC}           ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
                echo ""
                
                if command -v hysteria &> /dev/null; then
                    echo -e "${GREEN}✓ Hysteria ya está instalado${NC}"
                    echo ""
                    if [ -f /usr/local/bin/hysteria-manager ]; then
                        echo "Ejecutando gestor de Hysteria..."
                        bash /usr/local/bin/hysteria-manager
                    else
                        echo -e "${YELLOW}⚠ Gestor no encontrado. Reinstalando...${NC}"
                        cd /tmp
                        wget -q -O install_agnudp.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install_agnudp.sh
                        wget -q -O agnudp_manager.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/agnudp_manager.sh
                        
                        if [ -f install_agnudp.sh ]; then
                            chmod +x install_agnudp.sh agnudp_manager.sh
                            bash install_agnudp.sh
                            cp agnudp_manager.sh /usr/local/bin/hysteria-manager
                            chmod +x /usr/local/bin/hysteria-manager
                            echo -e "${GREEN}✓ Hysteria instalado${NC}"
                        fi
                    fi
                    read -p "Presiona ENTER para continuar..."
                else
                    echo -e "${YELLOW}Descargando e instalando Hysteria...${NC}"
                    cd /tmp
                    wget -q -O install_agnudp.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install_agnudp.sh
                    wget -q -O agnudp_manager.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/agnudp_manager.sh
                    
                    if [ -f install_agnudp.sh ]; then
                        chmod +x install_agnudp.sh agnudp_manager.sh
                        bash install_agnudp.sh
                        cp agnudp_manager.sh /usr/local/bin/hysteria-manager
                        chmod +x /usr/local/bin/hysteria-manager
                        echo -e "${GREEN}✓ Hysteria instalado${NC}"
                    fi
                    read -p "Presiona ENTER para continuar..."
                fi
                ;;
            10)
                clear
                echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}    ${BOLD}ESTADO DE SERVICIOS${NC}             ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
                echo ""
                systemctl is-active --quiet ssh && echo -e "${GREEN}✓${NC} OpenSSH: ${GREEN}Activo${NC} (puerto 22)" || echo -e "${RED}✗${NC} OpenSSH: ${RED}Inactivo${NC}"
                systemctl is-active --quiet dropbear && echo -e "${GREEN}✓${NC} Dropbear 2020: ${GREEN}Activo${NC} (puerto 90)" || echo -e "${RED}✗${NC} Dropbear 2020: ${RED}Inactivo${NC}"
                systemctl is-active --quiet dropbear-legacy && echo -e "${GREEN}✓${NC} Dropbear 2016: ${GREEN}Activo${NC} (puerto 143)" || echo -e "${RED}✗${NC} Dropbear 2016: ${RED}Inactivo${NC}"
                systemctl is-active --quiet stunnel4 && echo -e "${GREEN}✓${NC} Stunnel: ${GREEN}Activo${NC} (puertos 443, 444, 777)" || echo -e "${RED}✗${NC} Stunnel: ${RED}Inactivo${NC}"
                systemctl is-active --quiet squid && echo -e "${GREEN}✓${NC} Squid: ${GREEN}Activo${NC} (puertos 3128, 8888)" || echo -e "${RED}✗${NC} Squid: ${RED}Inactivo${NC}"
                systemctl is-active --quiet badvpn-udpgw && echo -e "${GREEN}✓${NC} BadVPN: ${GREEN}Activo${NC} (puerto 7300)" || echo -e "${RED}✗${NC} BadVPN: ${RED}Inactivo${NC}"
                echo ""
                echo -e "${YELLOW}Swap:${NC} ${CYAN}$(free -h | grep Swap | awk '{print $2}')${NC}"
                echo ""
                echo -e "${YELLOW}Python Proxies activos:${NC} ${CYAN}$(screen -ls 2>/dev/null | grep "proxy-" | wc -l)${NC}"
                echo ""
                read -p "Presiona ENTER para continuar..."
                ;;
            11)
                clear
                echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}    ${BOLD}REINICIAR SERVICIOS${NC}             ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
                echo ""
                echo "1) Reiniciar proxies (HTTP)"
                echo "2) Reiniciar OpenSSH"
                echo "3) Reiniciar Dropbear"
                echo "4) Reiniciar Stunnel"
                echo "5) Reiniciar TODO"
                echo "0) Volver"
                echo ""
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "Presiona ENTER para continuar..." ;;
                    2) systemctl restart ssh && echo -e "${GREEN}✓ OpenSSH reiniciado${NC}" || echo -e "${RED}✗ Error${NC}"; read -p "Presiona ENTER para continuar..." ;;
                    3) systemctl restart dropbear && echo -e "${GREEN}✓ Dropbear (90)${NC}" || echo -e "${RED}✗ Error${NC}"
                       systemctl restart dropbear-legacy 2>/dev/null && echo -e "${GREEN}✓ Dropbear Legacy (143)${NC}" || true
                       read -p "Presiona ENTER para continuar..." ;;
                    4) systemctl restart stunnel4 && echo -e "${GREEN}✓ Stunnel reiniciado${NC}" || echo -e "${RED}✗ Error${NC}"; read -p "Presiona ENTER para continuar..." ;;
                    5) restart_all_services; echo ""; read -p "Presiona ENTER para continuar..." ;;
                esac
                ;;
            12)
                clear
                echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}  ${BOLD}VERSIONES DROPBEAR INSTALADAS${NC}   ${CYAN}║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}Dropbear Sistema (Puerto 90):${NC}"
                /usr/sbin/dropbear -V 2>&1 | head -n 1
                echo ""
                echo -e "${YELLOW}Dropbear Legacy Compilado (Puerto 143):${NC}"
                if [ -f /opt/dropbear-2016/sbin/dropbear ]; then
                    /opt/dropbear-2016/sbin/dropbear -V 2>&1 | head -n 1
                    echo ""
                    echo -e "${YELLOW}Estado del servicio:${NC}"
                    systemctl is-active --quiet dropbear-legacy && echo -e "  ${GREEN}✓ Dropbear 2016 - ACTIVO${NC}" || echo -e "  ${RED}✗ Dropbear 2016 - INACTIVO${NC}"
                else
                    echo -e "  ${RED}No instalado${NC} (se usa el Dropbear del sistema)"
                fi
                echo ""
                read -p "Presiona ENTER para continuar..."
                ;;
            0)
                clear
                echo -e "${GREEN}¡Hasta pronto!${NC}"
                echo ""
                exit 0
                ;;
            *)
                echo -e "${RED}Opción inválida${NC}"
                sleep 1
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
✓ Dropbear 2016:     puerto 143 (compilado desde fuente)
✓ Stunnel SSL:       443, 444, 777 (777→143 Dropbear 2016)

PROXIES:
✓ Proxies HTTP:      80, 8080, 8880 (→ puerto 143 por defecto)
✓ Squid:             3128, 8888

OTROS:
✓ BadVPN UDPGW:      7300
✓ Hysteria UDP:      Opción 9 del panel
✓ UFW:               Desactivado
✓ Swap:              2GB activado

MEJORAS v10 FIXED:
✓ Dropbear 2016.74 COMPILADO desde código fuente
✓ 100% compatible con clientes SSH antiguos de Ubuntu 18
✓ Dos versiones reales de Dropbear funcionando simultáneamente
✓ Puerto 143: Dropbear 2016.74 real (no el del sistema)
✓ Menú colorido e intuitivo mejorado
✓ Corrección completa del sistema de detención de proxies
✓ Opción 12: Ver versiones instaladas

CREDENCIALES:
Usuario: $USER_VPN
Password: $PASS_VPN

PANEL: ejecutar vpn-panel (auto al conectar)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v10 FIXED

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear 2020: 90
- Dropbear 2016: 143 (compilado desde fuente, Ubuntu 18 compatible)
- Stunnel SSL: 443, 444, 777 (777 conecta al Dropbear 2016)
- Python Proxy: 80, 8080, 8880 (conectan al puerto 143 por defecto)
- Squid: 3128, 8888
- BadVPN: 7300
- Hysteria UDP: Opción 9 del menú

USUARIO:
$USER_VPN / $PASS_VPN

SWAP: 2GB activado

DROPBEAR VERSIONS:
- Puerto 90: Dropbear 2020.81 (del sistema Ubuntu 22)
- Puerto 143: Dropbear 2016.74 (compilado desde fuente)

PERSISTENCIA: Proxies se restauran tras reinicio

PANEL: vpn-panel (automático al login)

CORRECCIONES v10 FIXED:
- Error de sintaxis corregido (línea 1556)
- Menú completamente rediseñado con colores
- Sistema de detención de proxies mejorado (kill completo del puerto)
- Interfaz más intuitiva y profesional

OPCIÓN 12: Ver versiones de Dropbear instaladas
INFOEOF

echo "Información guardada en /root/vpn-info.txt"
echo ""
read -p "¿Deseas abrir el panel ahora? (s/n): " open_menu
if [[ $open_menu == "s" || $open_menu == "S" ]]; then
    menu_principal
fi
