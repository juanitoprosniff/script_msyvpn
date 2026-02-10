#!/bin/bash
# Script SSH VPN Completo - V10 MEJORADO
# - OpenSSH: 22, Dropbear: 90, Dropbear 2016 (Ubuntu 18): 143
# - Dropbear 2016.74 compilado desde fuente
# - Proxy Python multi-método: HTTP, CONNECT, WebSocket
# - Proxies persistentes con systemd (auto-restore al reiniciar)
# - Contador usuarios real (IPs únicas por ss)
# - Swap 2GB, Hysteria UDP, BadVPN UDPGW
# - UFW desactivado
# - Canal: t.me/FREEINTERNETVPNMSY

clear
echo "================================================"
echo "   SSH VPN Server - Versión Final v10"
echo "   Dropbear 2020 + Dropbear 2016 + Swap 2GB"
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
systemctl stop dropbear-legacy 2>/dev/null
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
   Dropbear SSH 2020 ultra estable
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
# COMPILAR E INSTALAR DROPBEAR 2016.74 (PUERTO 143)
# Compatible con clientes SSH más antiguos de Ubuntu 18
# ====================
echo "===================================================="
echo "Compilando Dropbear 2016.74 desde fuente..."
echo "Esto puede tardar unos minutos..."
echo "===================================================="

cd /usr/src

# Descargar Dropbear 2016.74
if [ ! -f dropbear-2016.74.tar.bz2 ]; then
    wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2
fi

# Extraer
tar xjf dropbear-2016.74.tar.bz2
cd dropbear-2016.74

# Configurar con opciones mínimas y compatibilidad
./configure --prefix=/opt/dropbear-2016 \
    --disable-zlib \
    --disable-wtmp \
    --disable-lastlog

# Compilar
make -j$(nproc)

# Instalar en /opt/dropbear-2016
make install

# Verificar instalación
if [ ! -f /opt/dropbear-2016/sbin/dropbear ]; then
    echo "⚠ ERROR: No se pudo compilar Dropbear 2016"
    echo "Continuando sin Dropbear Legacy..."
else
    echo "✓ Dropbear 2016.74 compilado exitosamente"
    
    # Crear directorio para llaves
    mkdir -p /etc/dropbear-legacy
    
    # Generar llaves para Dropbear 2016
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

openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=US/ST=State/L=City/O=MSY-VPN/CN=MSY-VPN-Server" \
    -keyout /etc/stunnel/stunnel.pem \
    -out /etc/stunnel/stunnel.pem 2>/dev/null

chmod 600 /etc/stunnel/stunnel.pem

cat > /etc/stunnel/stunnel.conf <<'EOF'
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem

[dropbear-ssl]
accept = 443
connect = 127.0.0.1:90

[dropbear-ssl-alt]
accept = 444
connect = 127.0.0.1:90

[dropbear-legacy-ssl]
accept = 777
connect = 127.0.0.1:143
EOF

echo "ENABLED=1" > /etc/default/stunnel4
systemctl enable stunnel4
systemctl restart stunnel4

# Continuar con el resto del script original...
# (Copiando todo lo demás desde tu script original)

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

cd /root

# ====================
# CONFIGURAR SQUID PROXY (PUERTOS 3128, 8888)
# ====================
echo "Configurando Squid Proxy..."

cat > /etc/squid/squid.conf <<'EOF'
http_port 3128
http_port 8888

acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow localhost
http_access allow all

coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
EOF

systemctl enable squid
systemctl restart squid

# ====================
# PROXY PYTHON MULTI-MÉTODO CON WEBSOCKET
# ====================
echo "Instalando Proxy Python..."

cat > /etc/proxy-python/proxy-server.py <<'PYEOF'
#!/usr/bin/env python3
import socket
import select
import sys
import struct
import base64
import hashlib
from threading import Thread

BUFSIZE = 8192

class ProxyServer:
    def __init__(self, host='0.0.0.0', port=80):
        self.host = host
        self.port = port
        
    def handle_client(self, client_socket, addr):
        try:
            request = client_socket.recv(BUFSIZE)
            if not request:
                return
                
            first_line = request.split(b'\n')[0]
            
            # WebSocket upgrade detection
            if b'Upgrade: websocket' in request or b'upgrade: websocket' in request:
                self.handle_websocket(client_socket, request)
                return
            
            # CONNECT method (SSL/TLS tunnel)
            if first_line.startswith(b'CONNECT'):
                self.handle_connect(client_socket, request)
                return
            
            # HTTP proxy normal
            self.handle_http(client_socket, request)
            
        except Exception as e:
            pass
        finally:
            client_socket.close()
    
    def handle_websocket(self, client, request):
        try:
            headers = {}
            for line in request.split(b'\r\n')[1:]:
                if b': ' in line:
                    key, value = line.split(b': ', 1)
                    headers[key.lower()] = value
            
            ws_key = headers.get(b'sec-websocket-key', b'')
            
            # WebSocket handshake
            magic = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            accept_key = base64.b64encode(
                hashlib.sha1(ws_key + magic).digest()
            ).decode()
            
            response = (
                b'HTTP/1.1 101 Switching Protocols\r\n'
                b'Upgrade: websocket\r\n'
                b'Connection: Upgrade\r\n'
                f'Sec-WebSocket-Accept: {accept_key}\r\n'
                b'\r\n'
            )
            
            client.send(response)
            
            # Conectar al destino (ej. 127.0.0.1:22 o 127.0.0.1:90)
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect(('127.0.0.1', 22))  # SSH local
            
            # Tunnel bidireccional
            self.tunnel(client, remote)
            
        except:
            pass
    
    def handle_connect(self, client, request):
        try:
            # Extraer host:port del CONNECT
            first_line = request.split(b'\n')[0]
            url = first_line.split(b' ')[1]
            
            # Conectar al destino
            http_port_index = url.find(b':')
            if http_port_index == -1:
                host = url
                port = 80
            else:
                host = url[:http_port_index]
                port = int(url[http_port_index+1:])
            
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((host.decode(), port))
            
            # Responder OK
            client.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # Tunnel
            self.tunnel(client, remote)
            
        except:
            client.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
    
    def handle_http(self, client, request):
        try:
            # Parsear request
            first_line = request.split(b'\n')[0]
            url = first_line.split(b' ')[1]
            
            # Extraer host
            http_pos = url.find(b'://')
            if http_pos == -1:
                temp = url
            else:
                temp = url[(http_pos+3):]
            
            port_pos = temp.find(b':')
            path_pos = temp.find(b'/')
            
            if path_pos == -1:
                path_pos = len(temp)
            
            host = temp[:path_pos] if port_pos == -1 or port_pos > path_pos else temp[:port_pos]
            port = 80 if port_pos == -1 or port_pos > path_pos else int(temp[(port_pos+1):path_pos])
            path = b'/' if path_pos >= len(temp) else temp[path_pos:]
            
            # Conectar al destino
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((host.decode(), port))
            
            # Reconstruir request
            new_request = first_line.split(b' ')[0] + b' ' + path + b' ' + first_line.split(b' ')[2]
            new_request += b'\r\n' + b'\r\n'.join(request.split(b'\r\n')[1:])
            
            remote.send(new_request)
            
            # Relay
            self.tunnel(client, remote)
            
        except:
            pass
    
    def tunnel(self, client, remote):
        try:
            while True:
                r, w, e = select.select([client, remote], [], [], 3)
                if not r:
                    break
                
                if client in r:
                    data = client.recv(BUFSIZE)
                    if not data:
                        break
                    remote.send(data)
                
                if remote in r:
                    data = remote.recv(BUFSIZE)
                    if not data:
                        break
                    client.send(data)
        except:
            pass
        finally:
            client.close()
            remote.close()
    
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(200)
        
        print(f"[*] Proxy escuchando en {self.host}:{self.port}")
        
        while True:
            try:
                client, addr = server.accept()
                Thread(target=self.handle_client, args=(client, addr)).start()
            except KeyboardInterrupt:
                break
        
        server.close()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    proxy = ProxyServer(port=port)
    proxy.start()
PYEOF

chmod +x /etc/proxy-python/proxy-server.py

# ====================
# CREAR FUNCIONES SSH-VPN
# ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

crear_proxy() {
    local puerto=$1
    local nombre="proxy-${puerto}"
    
    # Detener si existe
    screen -S $nombre -X quit 2>/dev/null
    pkill -9 -f "proxy-server.py $puerto" 2>/dev/null
    
    # Crear servicio systemd
    cat > /etc/systemd/system/proxy-${puerto}.service <<PROXYEOF
[Unit]
Description=Python Proxy Multi-Método - Puerto ${puerto}
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/proxy-python
ExecStart=/usr/bin/python3 /etc/proxy-python/proxy-server.py ${puerto}
Restart=always
RestartSec=3
StandardOutput=append:/var/log/proxy-python/proxy-${puerto}.log
StandardError=append:/var/log/proxy-python/proxy-${puerto}.log

[Install]
WantedBy=multi-user.target
PROXYEOF
    
    systemctl daemon-reload
    systemctl enable proxy-${puerto}
    systemctl start proxy-${puerto}
    
    # Guardar en lista
    echo "${puerto}" >> /etc/ssh-vpn/proxies.conf
    sort -u /etc/ssh-vpn/proxies.conf -o /etc/ssh-vpn/proxies.conf
}

eliminar_proxy() {
    local puerto=$1
    
    systemctl stop proxy-${puerto} 2>/dev/null
    systemctl disable proxy-${puerto} 2>/dev/null
    rm -f /etc/systemd/system/proxy-${puerto}.service
    systemctl daemon-reload
    
    sed -i "/^${puerto}$/d" /etc/ssh-vpn/proxies.conf
}

listar_proxies() {
    echo "PROXIES ACTIVOS:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -f /etc/ssh-vpn/proxies.conf ]; then
        while read puerto; do
            if systemctl is-active --quiet proxy-${puerto}; then
                echo "✓ Puerto $puerto - ACTIVO"
            else
                echo "✗ Puerto $puerto - INACTIVO"
            fi
        done < /etc/ssh-vpn/proxies.conf
    else
        echo "No hay proxies configurados"
    fi
}

restore_proxies() {
    if [ -f /etc/ssh-vpn/proxies.conf ]; then
        echo "Restaurando proxies..."
        while read puerto; do
            systemctl start proxy-${puerto} 2>/dev/null
        done < /etc/ssh-vpn/proxies.conf
    fi
}

restart_proxies() {
    if [ -f /etc/ssh-vpn/proxies.conf ]; then
        echo "Reiniciando proxies..."
        while read puerto; do
            systemctl restart proxy-${puerto}
            echo "✓ Proxy puerto $puerto reiniciado"
        done < /etc/ssh-vpn/proxies.conf
    fi
}

restart_all_services() {
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

contar_usuarios() {
    # Contar usuarios conectados por IPs únicas
    ss -tn state established '( dport = :22 or dport = :90 or dport = :143 )' | \
    awk 'NR>1 {print $4}' | \
    cut -d: -f1 | \
    sort -u | \
    wc -l
}

listar_conectados() {
    echo "USUARIOS CONECTADOS (IPs únicas):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    ss -tn state established '( dport = :22 or dport = :90 or dport = :143 )' | \
    awk 'NR>1 {print $4}' | \
    cut -d: -f1 | \
    sort -u | \
    nl -w2 -s'. '
}
FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

# Crear archivo de proxies si no existe
touch /etc/ssh-vpn/proxies.conf

# Crear proxies iniciales
echo "Creando proxies iniciales (80, 8080, 8880)..."
source /root/ssh-vpn-functions.sh

crear_proxy 80
crear_proxy 8080
crear_proxy 8880

# ====================
# SCRIPT PANEL PRINCIPAL
# ====================
cat > /root/vpn-installer.sh <<'MAINSCRIPT'
#!/bin/bash

source /root/ssh-vpn-functions.sh

cor='\033[1;32m'
red='\033[1;31m'
yellow='\033[1;33m'
off='\033[0m'

menu_principal() {
    while true; do
        clear
        echo -e "${cor}╔═══════════════════════════════════════════════╗${off}"
        echo -e "${cor}║        MSY VPN - PANEL DE CONTROL v10        ║${off}"
        echo -e "${cor}╚═══════════════════════════════════════════════╝${off}"
        echo ""
        echo -e "IP: ${yellow}$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')${off}"
        echo -e "Usuarios conectados: ${yellow}$(contar_usuarios)${off}"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1) Crear usuario SSH"
        echo "2) Eliminar usuario"
        echo "3) Ver usuarios creados"
        echo "4) Cambiar contraseña"
        echo "5) Ver usuarios conectados"
        echo "6) Gestionar proxies HTTP"
        echo "7) Monitorear servicios"
        echo "8) Túneles SSL (Stunnel)"
        echo "9) Hysteria UDP Manager"
        echo "10) Estado de servicios"
        echo "11) Reiniciar servicios"
        echo "12) Ver versiones Dropbear"
        echo "0) Salir"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        read -p "Opción: " opcion
        
        case $opcion in
            1)
                clear
                echo "CREAR USUARIO SSH"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario: " username
                
                if id "$username" &>/dev/null; then
                    echo "⚠ El usuario ya existe"
                    read -p "ENTER..."
                    continue
                fi
                
                read -p "Contraseña: " password
                read -p "Días de validez (0=ilimitado): " dias
                
                useradd -m -s /bin/bash $username
                echo "$username:$password" | chpasswd
                
                if [ "$dias" -gt 0 ]; then
                    fecha_exp=$(date -d "+${dias} days" +%Y-%m-%d)
                    chage -E $fecha_exp $username
                else
                    fecha_exp="Ilimitado"
                fi
                
                cat > /etc/ssh-vpn/users/$username.txt <<USEREOF
Usuario: $username
Contraseña: $password
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: $fecha_exp
Estado: Activo
USEREOF
                
                echo ""
                echo "✓ Usuario $username creado exitosamente"
                echo "  Contraseña: $password"
                echo "  Expiración: $fecha_exp"
                read -p "ENTER..."
                ;;
            2)
                clear
                echo "ELIMINAR USUARIO"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Usuario a eliminar: " username
                
                if ! id "$username" &>/dev/null; then
                    echo "⚠ El usuario no existe"
                    read -p "ENTER..."
                    continue
                fi
                
                # Matar sesiones
                pkill -u $username
                
                # Eliminar usuario
                userdel -r $username 2>/dev/null
                rm -f /etc/ssh-vpn/users/$username.txt
                
                echo "✓ Usuario $username eliminado"
                read -p "ENTER..."
                ;;
            3)
                clear
                echo "USUARIOS CREADOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                
                if [ -z "$(ls -A /etc/ssh-vpn/users/ 2>/dev/null)" ]; then
                    echo "No hay usuarios creados"
                else
                    for user_file in /etc/ssh-vpn/users/*.txt; do
                        echo "────────────────────────────────────────────────"
                        cat $user_file
                    done
                fi
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER..."
                ;;
            4)
                clear
                echo "CAMBIAR CONTRASEÑA"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Usuario: " username
                
                if ! id "$username" &>/dev/null; then
                    echo "⚠ El usuario no existe"
                    read -p "ENTER..."
                    continue
                fi
                
                read -p "Nueva contraseña: " newpass
                echo "$username:$newpass" | chpasswd
                
                # Actualizar archivo
                if [ -f /etc/ssh-vpn/users/$username.txt ]; then
                    sed -i "s/Contraseña: .*/Contraseña: $newpass/" /etc/ssh-vpn/users/$username.txt
                fi
                
                echo "✓ Contraseña actualizada"
                read -p "ENTER..."
                ;;
            5)
                clear
                listar_conectados
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Total: $(contar_usuarios) usuarios"
                read -p "ENTER..."
                ;;
            6)
                while true; do
                    clear
                    echo "GESTIÓN DE PROXIES HTTP"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    listar_proxies
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo "1) Crear proxy"
                    echo "2) Eliminar proxy"
                    echo "3) Reiniciar proxies"
                    echo "0) Volver"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    read -p "Opción: " proxy_opt
                    
                    case $proxy_opt in
                        1)
                            read -p "Puerto para el proxy: " puerto
                            crear_proxy $puerto
                            echo "✓ Proxy creado en puerto $puerto"
                            sleep 2
                            ;;
                        2)
                            read -p "Puerto a eliminar: " puerto
                            eliminar_proxy $puerto
                            echo "✓ Proxy eliminado"
                            sleep 2
                            ;;
                        3)
                            restart_proxies
                            sleep 2
                            ;;
                        0)
                            break
                            ;;
                    esac
                done
                ;;
            7)
                clear
                echo "MONITOREO DE SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "OpenSSH (22):"
                netstat -tlnp | grep :22 || echo "  No activo"
                echo ""
                echo "Dropbear 2020 (90):"
                netstat -tlnp | grep :90 || echo "  No activo"
                echo ""
                echo "Dropbear 2016 (143):"
                netstat -tlnp | grep :143 || echo "  No activo"
                echo ""
                echo "Stunnel SSL (443, 444, 777):"
                netstat -tlnp | grep stunnel4 || echo "  No activo"
                echo ""
                echo "Squid (3128, 8888):"
                netstat -tlnp | grep squid || echo "  No activo"
                echo ""
                echo "Python Proxies:"
                netstat -tlnp | grep python3 | grep -E ':(80|8080|8880) ' || echo "  No activos"
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER..."
                ;;
            8)
                while true; do
                    clear
                    echo "TÚNELES SSL (STUNNEL)"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo "Configuración actual:"
                    cat /etc/stunnel/stunnel.conf | grep -E "\[|accept|connect"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo "1) Ver túneles"
                    echo "2) Crear túnel"
                    echo "3) Eliminar túnel"
                    echo "4) Reiniciar stunnel"
                    echo "0) Volver"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    read -p "Opción: " stunnel_opt
                    
                    case $stunnel_opt in
                        0)
                            break
                            ;;
                        1)
                            clear
                            cat /etc/stunnel/stunnel.conf
                            read -p "ENTER..."
                            ;;
                        2)
                            clear
                            echo "CREAR TÚNEL"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            read -p "Nombre del túnel: " tunnel_name
                            read -p "Puerto de escucha: " tunnel_port
                            read -p "Puerto de destino (ej: 22, 90, 143): " tunnel_dest
                            
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
                done
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
                systemctl is-active --quiet dropbear && echo "✓ Dropbear 2020: Activo (puerto 90)" || echo "✗ Dropbear 2020: Inactivo"
                systemctl is-active --quiet dropbear-legacy && echo "✓ Dropbear 2016: Activo (puerto 143)" || echo "✗ Dropbear 2016: Inactivo"
                systemctl is-active --quiet stunnel4 && echo "✓ Stunnel: Activo (puertos 443, 444, 777)" || echo "✗ Stunnel: Inactivo"
                systemctl is-active --quiet squid && echo "✓ Squid: Activo (puertos 3128, 8888)" || echo "✗ Squid: Inactivo"
                systemctl is-active --quiet badvpn-udpgw && echo "✓ BadVPN: Activo (puerto 7300)" || echo "✗ BadVPN: Inactivo"
                echo ""
                echo "Swap: $(free -h | grep Swap | awk '{print $2}')"
                echo ""
                echo "Python Proxies activos:"
                if [ -f /etc/ssh-vpn/proxies.conf ]; then
                    while read puerto; do
                        systemctl is-active --quiet proxy-${puerto} && echo "  ✓ Puerto $puerto" || echo "  ✗ Puerto $puerto"
                    done < /etc/ssh-vpn/proxies.conf
                fi
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER para continuar..."
                ;;
            11)
                clear
                echo "REINICIAR SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Reiniciar proxies (HTTP)"
                echo "2) Reiniciar OpenSSH"
                echo "3) Reiniciar Dropbear 2020"
                echo "4) Reiniciar Dropbear 2016"
                echo "5) Reiniciar Stunnel"
                echo "6) Reiniciar TODO"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "ENTER..." ;;
                    2) systemctl restart ssh && echo "✓ OpenSSH reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    3) systemctl restart dropbear && echo "✓ Dropbear 2020 reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    4) systemctl restart dropbear-legacy && echo "✓ Dropbear 2016 reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    5) systemctl restart stunnel4 && echo "✓ Stunnel reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    6) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
                ;;
            12)
                clear
                echo "VERSIONES DE DROPBEAR"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "Dropbear Sistema (Puerto 90):"
                /usr/sbin/dropbear -V 2>&1 | head -n 1
                echo ""
                echo "Dropbear Legacy (Puerto 143):"
                if [ -f /opt/dropbear-2016/sbin/dropbear ]; then
                    /opt/dropbear-2016/sbin/dropbear -V 2>&1 | head -n 1
                else
                    echo "  No instalado"
                fi
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "ENTER..."
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
✓ Dropbear 2016:     puerto 143 (Ubuntu 18 compatible)
✓ Stunnel SSL:       443, 444, 777

PROXIES:
✓ Proxies HTTP:      80, 8080, 8880
✓ Squid:             3128, 8888

OTROS:
✓ BadVPN UDPGW:      7300
✓ Hysteria UDP:      Opción 9 del panel
✓ UFW:               Desactivado
✓ Swap:              2GB activado

MEJORAS v10:
✓ Dropbear 2016.74 compilado desde fuente
✓ Compatible con clientes SSH de Ubuntu 18
✓ Dos versiones de Dropbear funcionando simultáneamente
✓ Opción 12: Ver versiones de Dropbear instaladas

CREDENCIALES:
Usuario: $USER_VPN
Password: $PASS_VPN

PANEL: ejecutar vpn-panel (auto al conectar)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v10

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear 2020: 90
- Dropbear 2016: 143 (Ubuntu 18 compatible)
- Stunnel SSL: 443, 444, 777
- Python Proxy: 80, 8080, 8880
- Squid: 3128, 8888
- BadVPN: 7300
- Hysteria UDP: Opción 9 del menú

USUARIO:
$USER_VPN / $PASS_VPN

SWAP: 2GB activado

DROPBEAR VERSIONS:
- Puerto 90: $(dropbear -V 2>&1 | head -n 1)
- Puerto 143: Dropbear v2016.74 (compilado desde fuente)

PERSISTENCIA: Proxies se restauran tras reinicio

PANEL: vpn-panel (automático al login)
INFOEOF

echo "Información guardada en /root/vpn-info.txt"
echo ""
read -p "¿Deseas abrir el panel ahora? (s/n): " open_menu
if [[ $open_menu == "s" || $open_menu == "S" ]]; then
    menu_principal
fi
