#!/bin/bash
# Script SSH VPN Completo - V8 DEFINITIVA
# - SlowDNS integrado
# - UFW deshabilitado (para Hysteria UDP)
# - Contador usuarios CORREGIDO (incluye Hysteria)
# - Swap 2GB, Dropbear, Hysteria, etc.

clear
echo "================================================"
echo "   SSH VPN Server - Versión Definitiva v8"
echo "   SlowDNS + Hysteria UDP + Dropbear"
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
pkill -9 -f "dns-server" 2>/dev/null
systemctl stop squid 2>/dev/null
systemctl stop dropbear 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop ssh 2>/dev/null

# Actualizar sistema
echo "Actualizando sistema..."
apt update -y && apt upgrade -y

# Instalar dependencias
echo "Instalando dependencias..."
apt install -y python3 python3-pip openssh-server dropbear squid stunnel4 screen lsof curl wget nano ufw net-tools cmake build-essential git jq dnsutils

# Crear directorios
mkdir -p /etc/proxy-python
mkdir -p /var/log/proxy-python
mkdir -p /etc/ssh-vpn
mkdir -p /etc/ssh-vpn/users
mkdir -p /etc/ssh-vpn/tunnels
mkdir -p /etc/hysteria
mkdir -p /etc/slowdns
mkdir -p /root/slowdns

# ====================
# CONFIGURAR SWAP 2GB
# ====================
echo "Configurando Swap de 2GB..."

if [ ! -f /swapfile ] || [ $(stat -f -c%s /swapfile 2>/dev/null) -lt 2147483648 ]; then
    swapoff /swapfile 2>/dev/null
    rm -f /swapfile
    
    dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    
    echo "✓ Swap de 2GB configurado"
else
    echo "✓ Swap ya existe"
fi

# ====================
# CONFIGURAR OPENSSH
# ====================
echo "Configurando OpenSSH..."

cat > /etc/ssh/banner.txt <<'EOF'
╔════════════════════════════════════════╗
║              MSY VPN                   ║
║     Conexión OpenSSH establecida       ║
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
# CONFIGURAR DROPBEAR
# ====================
echo "Configurando Dropbear..."

cat > /etc/dropbear/banner.txt <<'EOF'
═══════════════════════════════════════
          MSY VPN
   Dropbear SSH ultra estable
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
# CONFIGURAR STUNNEL
# ====================
echo "Configurando Stunnel..."

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

[dropbear-vpn]
accept = 777
connect = 127.0.0.1:90
EOF

echo "ENABLED=1" > /etc/default/stunnel4
systemctl enable stunnel4
systemctl restart stunnel4

# ====================
# INSTALAR BADVPN
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

# ====================
# INSTALAR SLOWDNS
# ====================
echo "Instalando SlowDNS..."

cd /root/slowdns

# Descargar binario dns-server
wget -q -O /usr/local/bin/dns-server https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/Slow/install/dns-server 2>/dev/null

if [ ! -f /usr/local/bin/dns-server ]; then
    # Fallback a otro repo conocido
    wget -q -O /usr/local/bin/dns-server https://raw.githubusercontent.com/potatonc/webmin/master/dns-server 2>/dev/null
fi

chmod +x /usr/local/bin/dns-server

# Descargar keys
wget -q -O /etc/slowdns/server.pub https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/Slow/Key/server.pub 2>/dev/null
wget -q -O /etc/slowdns/server.key https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/Slow/Key/server.key 2>/dev/null

# Si no se descargaron, crear keys default
if [ ! -f /etc/slowdns/server.pub ] || [ ! -f /etc/slowdns/server.key ]; then
    echo "a4483e993fbdb9352ca7c4106d4235f6bf64c2e0d0c190464801b8e61e78a94e" > /etc/slowdns/server.pub
    echo "45d9e1b869a48e92b8ca6e2a43bc3edf8c26b17a1b8f92ea6fb1c3b09b5c5c5c" > /etc/slowdns/server.key
fi

chmod 644 /etc/slowdns/server.pub
chmod 600 /etc/slowdns/server.key

# Crear servicio SlowDNS
cat > /etc/systemd/system/slowdns.service <<'EOF'
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/slowdns
ExecStart=/usr/local/bin/dns-server -udp :5300 -privkey /etc/slowdns/server.key 127.0.0.1:22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns 2>/dev/null
systemctl start slowdns 2>/dev/null

# Descargar script manager
wget -q -O /usr/local/bin/slowdns-manager https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/Slow/slowdns.sh 2>/dev/null
chmod +x /usr/local/bin/slowdns-manager 2>/dev/null

echo "✓ SlowDNS instalado"

# ====================
# INSTALAR HYSTERIA UDP
# ====================
echo "Instalando Hysteria UDP..."

cd /root
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
import socket
import threading
import select
import sys

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 80
BUFLEN = 16384
TIMEOUT = 60
SSH_HOST = '127.0.0.1'
SSH_PORT = 90
RESPONSE_CODE = '101'
BANNER_TEXT = 'MSY VPN'

class ProxyServer:
    def __init__(self, host, port, ssh_host, ssh_port, response_code, banner):
        self.host = host
        self.port = port
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.response_code = response_code
        self.banner = banner
        self.running = False
        
    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        self.server.bind((self.host, self.port))
        self.server.listen(500)
        self.running = True
        
        print(f'[*] Proxy Python iniciado en {self.host}:{self.port}')
        print(f'[*] SSH Target: {self.ssh_host}:{self.ssh_port}')
        print(f'[*] Response: HTTP/1.1 {self.response_code}')
        print(f'[*] Banner: {self.banner}')
        
        while self.running:
            try:
                client, addr = self.server.accept()
                handler = ConnectionHandler(client, self, addr)
                handler.start()
            except KeyboardInterrupt:
                print('\n[!] Deteniendo servidor...')
                self.running = False
                break
            except Exception as e:
                print(f'[!] Error: {e}')

class ConnectionHandler(threading.Thread):
    def __init__(self, client, server, addr):
        threading.Thread.__init__(self)
        self.client = client
        self.server = server
        self.addr = addr
        self.ssh = None
        self.daemon = True
        
    def run(self):
        try:
            self.client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            request = self.client.recv(BUFLEN)
            
            if not request:
                self.close()
                return
            
            try:
                self.ssh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.ssh.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.ssh.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.ssh.connect((self.server.ssh_host, self.server.ssh_port))
                
                response = f'HTTP/1.1 {self.server.response_code} {self.server.banner}\r\n'
                response += 'Content-Length: 999999\r\n'
                response += 'Connection: keep-alive\r\n'
                response += 'Keep-Alive: timeout=5, max=1000\r\n'
                response += '\r\n'
                
                self.client.sendall(response.encode())
                self.transfer()
                
            except Exception as e:
                print(f'[!] Error SSH: {e}')
                self.close()
                
        except Exception as e:
            print(f'[!] Error handler: {e}')
            self.close()
    
    def transfer(self):
        try:
            while True:
                r, w, x = select.select([self.client, self.ssh], [], [], TIMEOUT)
                
                if not r:
                    break
                
                if self.client in r:
                    data = self.client.recv(BUFLEN)
                    if not data:
                        break
                    self.ssh.sendall(data)
                
                if self.ssh in r:
                    data = self.ssh.recv(BUFLEN)
                    if not data:
                        break
                    self.client.sendall(data)
                    
        except Exception as e:
            pass
        finally:
            self.close()
    
    def close(self):
        try:
            if self.client:
                self.client.close()
            if self.ssh:
                self.ssh.close()
        except:
            pass

if __name__ == '__main__':
    import sys
    
    port = int(sys.argv[1]) if len(sys.argv) > 1 else LISTENING_PORT
    response = sys.argv[2] if len(sys.argv) > 2 else RESPONSE_CODE
    banner = sys.argv[3] if len(sys.argv) > 3 else BANNER_TEXT
    ssh_port = int(sys.argv[4]) if len(sys.argv) > 4 else SSH_PORT
    
    server = ProxyServer(LISTENING_ADDR, port, SSH_HOST, ssh_port, response, banner)
    server.start()
PYEOF

chmod +x /etc/proxy-python/proxy.py

# ====================
# MENÚ PRINCIPAL
# ====================
menu_principal() {
    source /root/ssh-vpn-functions.sh
    
    while true; do
        clear
        IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        USERS_ONLINE=$(count_users)
        SWAP_SIZE=$(free -h | grep Swap | awk '{print $2}')
        SLOWDNS_STATUS=$(systemctl is-active slowdns 2>/dev/null)
        
        cat <<EOF
╔════════════════════════════════════════════════╗
║       PANEL DE GESTIÓN MSY VPN - v8           ║
╚════════════════════════════════════════════════╝

IP del Servidor: $IP
Usuarios Online: $USERS_ONLINE
Memoria Swap: $SWAP_SIZE
SlowDNS: $SLOWDNS_STATUS

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MENÚ PRINCIPAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1) Crear usuario VPN
2) Eliminar usuario VPN
3) Ver usuarios conectados
4) Gestionar Proxies Python
5) Ver servicios activos y puertos
6) Cambiar Banner HTTP/1.1
7) Cambiar Banner SSH
8) Gestionar Túneles SSL/TLS
9) Administrar UDP Hysteria
10) Administrar SlowDNS
11) Estado de servicios
0) Salir
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
        read -p "Selecciona una opción: " option
        
        case $option in
            1)
                clear
                echo "CREAR NUEVO USUARIO VPN"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario: " username
                read -p "Contraseña: " password
                read -p "Días de validez (0 = ilimitado): " days
                
                if id "$username" &>/dev/null; then
                    echo "El usuario ya existe"
                    read -p "Presiona ENTER para continuar..."
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
                read -p "Presiona ENTER para continuar..."
                ;;
            2)
                clear
                echo "ELIMINAR USUARIO VPN"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario a eliminar: " username
                
                if ! id "$username" &>/dev/null; then
                    echo "El usuario no existe"
                    read -p "Presiona ENTER para continuar..."
                    continue
                fi
                
                pkill -9 -u $username 2>/dev/null
                userdel -r $username 2>/dev/null
                rm -f /etc/ssh-vpn/users/$username.txt
                
                echo "✓ Usuario $username eliminado"
                read -p "Presiona ENTER para continuar..."
                ;;
            3)
                clear
                list_connected_users
                read -p "Presiona ENTER para continuar..."
                ;;
            4)
                clear
                echo "GESTIÓN DE PROXIES PYTHON"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Crear nuevo proxy"
                echo "2) Detener todos los proxies"
                echo "3) Ver proxies activos"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " proxy_opt
                
                case $proxy_opt in
                    1)
                        read -p "Puerto (ej: 8081): " port
                        read -p "Response code (ej: 101): " response
                        read -p "Banner text [MSY VPN]: " banner
                        banner=${banner:-MSY VPN}
                        echo ""
                        echo "Backend SSH:"
                        echo "  22  - OpenSSH"
                        echo "  90  - Dropbear (recomendado)"
                        read -p "Puerto SSH [90]: " ssh_port
                        ssh_port=${ssh_port:-90}
                        start_proxy "$port" "$response" "$banner" "$ssh_port"
                        read -p "Presiona ENTER..."
                        ;;
                    2)
                        stop_all_proxies
                        read -p "Presiona ENTER..."
                        ;;
                    3)
                        echo "PROXIES ACTIVOS:"
                        screen -ls | grep "proxy-" || echo "No hay proxies activos"
                        echo ""
                        if [ -f /etc/proxy-python/active.txt ]; then
                            echo "Configuración:"
                            cat /etc/proxy-python/active.txt
                        fi
                        read -p "Presiona ENTER..."
                        ;;
                esac
                ;;
            5)
                clear
                echo "SERVICIOS ACTIVOS Y PUERTOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "OpenSSH (puerto 22):"
                ss -tlnp | grep ':22 ' | grep -v grep
                echo ""
                echo "Dropbear SSH (puerto 90):"
                ss -tlnp | grep ':90 ' | grep -v grep
                echo ""
                echo "Stunnel SSL (puertos 443, 444, 777):"
                ss -tlnp | grep -E ':(443|444|777) ' | grep stunnel | grep -v grep
                echo ""
                echo "SlowDNS (puerto UDP 5300):"
                ss -ulnp | grep ':5300 ' | grep -v grep
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
                read -p "Presiona ENTER para continuar..."
                ;;
            6)
                clear
                echo "CAMBIAR MINI BANNER HTTP/1.1"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo "Banner actual:"
                grep "BANNER_TEXT = " /etc/proxy-python/proxy.py
                echo ""
                read -p "Nuevo texto [MSY VPN]: " new_banner
                new_banner=${new_banner:-MSY VPN}
                
                sed -i "s/BANNER_TEXT = .*/BANNER_TEXT = '$new_banner'/" /etc/proxy-python/proxy.py
                echo ""
                echo "✓ Banner actualizado a: $new_banner"
                read -p "Presiona ENTER para continuar..."
                ;;
            7)
                clear
                echo "CAMBIAR BANNERS SSH"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Cambiar banner OpenSSH"
                echo "2) Cambiar banner Dropbear"
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
                        read -p "Presiona ENTER..."
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
                            echo "✓ Banner Dropbear actualizado"
                        fi
                        rm -f /tmp/new_banner.txt
                        read -p "Presiona ENTER..."
                        ;;
                esac
                ;;
            8)
                clear
                echo "GESTIONAR TÚNELES SSL/TLS"
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
                        read -p "Presiona ENTER..."
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
                        
                        systemctl restart stunnel4
                        
                        echo ""
                        echo "✓ Túnel $tunnel_name creado en puerto $tunnel_port"
                        read -p "Presiona ENTER..."
                        ;;
                    3)
                        clear
                        echo "ELIMINAR TÚNEL"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        read -p "Puerto del túnel a eliminar: " del_port
                        
                        sed -i "/accept = $del_port/,+1 d" /etc/stunnel/stunnel.conf
                        
                        systemctl restart stunnel4
                        echo "✓ Túnel en puerto $del_port eliminado"
                        read -p "Presiona ENTER..."
                        ;;
                    4)
                        systemctl restart stunnel4
                        echo "✓ Stunnel reiniciado"
                        read -p "Presiona ENTER..."
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
                    read -p "Presiona ENTER..."
                fi
                ;;
            10)
                clear
                if [ -f /usr/local/bin/slowdns-manager ]; then
                    bash /usr/local/bin/slowdns-manager
                else
                    echo "ADMINISTRAR SLOWDNS"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo ""
                    echo "1) Ver estado SlowDNS"
                    echo "2) Ver información de conexión"
                    echo "3) Reiniciar SlowDNS"
                    echo "4) Detener SlowDNS"
                    echo "5) Iniciar SlowDNS"
                    echo "0) Volver"
                    echo ""
                    read -p "Opción: " slowdns_opt
                    
                    case $slowdns_opt in
                        1)
                            systemctl status slowdns
                            read -p "Presiona ENTER..."
                            ;;
                        2)
                            clear
                            echo "INFORMACIÓN SLOWDNS"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            echo ""
                            echo "Server Public Key:"
                            cat /etc/slowdns/server.pub
                            echo ""
                            echo "Puerto UDP: 5300"
                            echo "Nameserver: $IP"
                            echo ""
                            read -p "Presiona ENTER..."
                            ;;
                        3)
                            systemctl restart slowdns
                            echo "✓ SlowDNS reiniciado"
                            read -p "Presiona ENTER..."
                            ;;
                        4)
                            systemctl stop slowdns
                            echo "✓ SlowDNS detenido"
                            read -p "Presiona ENTER..."
                            ;;
                        5)
                            systemctl start slowdns
                            echo "✓ SlowDNS iniciado"
                            read -p "Presiona ENTER..."
                            ;;
                    esac
                fi
                ;;
            11)
                clear
                echo "ESTADO DE SERVICIOS:"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                systemctl is-active --quiet ssh && echo "✓ OpenSSH: Activo (puerto 22)" || echo "✗ OpenSSH: Inactivo"
                systemctl is-active --quiet dropbear && echo "✓ Dropbear: Activo (puerto 90)" || echo "✗ Dropbear: Inactivo"
                systemctl is-active --quiet stunnel4 && echo "✓ Stunnel: Activo (443, 444, 777)" || echo "✗ Stunnel: Inactivo"
                systemctl is-active --quiet slowdns && echo "✓ SlowDNS: Activo (puerto 5300)" || echo "✗ SlowDNS: Inactivo"
                systemctl is-active --quiet badvpn-udpgw && echo "✓ BadVPN: Activo (puerto 7300)" || echo "✗ BadVPN: Inactivo"
                echo ""
                echo "Swap: $(free -h | grep Swap | awk '{print $2}')"
                echo "UFW: $(ufw status | head -1)"
                echo ""
                echo "Python Proxies:"
                screen -ls | grep "proxy-" | wc -l | xargs echo "  Total:"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Presiona ENTER para continuar..."
                ;;
            0)
                exit 0
                ;;
        esac
    done
}

# ====================
# FUNCIONES (CONTADOR CORREGIDO)
# ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

count_users() {
    local total=0
    
    # Contar usuarios SSH únicos (excluir root y pts duplicados)
    local ssh_users=$(who | grep -v "^root " | awk '{print $1}' | sort -u | wc -l)
    
    # Contar conexiones Dropbear ESTABLECIDAS únicas
    local dropbear_users=$(netstat -tnp 2>/dev/null | grep 'ESTABLISHED.*dropbear' | grep -v '127.0.0.1' | awk '{print $5}' | cut -d: -f1 | sort -u | wc -l)
    
    # Contar usuarios Hysteria (si está activo)
    local hysteria_users=0
    if systemctl is-active --quiet hysteria 2>/dev/null || pgrep -x hysteria >/dev/null 2>&1; then
        # Contar conexiones UDP únicas de hysteria
        hysteria_users=$(netstat -anp 2>/dev/null | grep hysteria | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u | wc -l)
    fi
    
    total=$((ssh_users + dropbear_users + hysteria_users))
    
    echo $total
}

list_connected_users() {
    echo "═══════════════════════════════════════════════════"
    echo "           USUARIOS CONECTADOS"
    echo "═══════════════════════════════════════════════════"
    
    echo ""
    echo "Usuarios SSH (OpenSSH - puerto 22):"
    who | grep -v "^root " | awk '{print $1" - "$5" - "$3" "$4}' | sed 's/[()]//g' | nl || echo "  Ninguno"
    
    echo ""
    echo "Conexiones Dropbear (puerto 90):"
    netstat -tnp 2>/dev/null | grep 'ESTABLISHED.*dropbear' | grep -v '127.0.0.1' | awk '{print $5}' | cut -d: -f1 | sort -u | nl || echo "  Ninguna"
    
    echo ""
    echo "Conexiones Hysteria UDP:"
    if systemctl is-active --quiet hysteria 2>/dev/null || pgrep -x hysteria >/dev/null 2>&1; then
        netstat -anp 2>/dev/null | grep hysteria | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u | nl || echo "  Ninguna"
    else
        echo "  Servicio no activo"
    fi
    
    echo ""
    echo "Total de usuarios VPN: $(count_users)"
    echo "═══════════════════════════════════════════════════"
}

start_proxy() {
    local port=$1
    local response=$2
    local banner=$3
    local ssh_port=${4:-90}
    
    if screen -list | grep -q "proxy-$port"; then
        echo "✗ Puerto $port ya en uso"
        return 1
    fi
    
    screen -dmS "proxy-$port" python3 /etc/proxy-python/proxy.py "$port" "$response" "$banner" "$ssh_port"
    sleep 1
    
    if screen -list | grep -q "proxy-$port"; then
        echo "✓ Proxy iniciado en puerto $port"
        echo "$port|$response|$banner|$ssh_port|$(date)" >> /etc/proxy-python/active.txt
    else
        echo "✗ Error al iniciar proxy"
    fi
}

stop_all_proxies() {
    screen -ls | grep "proxy-" | awk '{print $1}' | xargs -I {} screen -X -S {} quit 2>/dev/null
    pkill -9 -f "proxy.py" 2>/dev/null
    rm -f /etc/proxy-python/active.txt
    echo "" > /etc/proxy-python/active.txt
    echo "✓ Todos los proxies detenidos"
}
FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

# ====================
# SCRIPT RESTAURAR PROXIES
# ====================
cat > /etc/init.d/restore-proxies <<'RESTOREEOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          restore-proxies
# Required-Start:    $network $syslog
# Required-Stop:     $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Restaurar proxies Python
### END INIT INFO

source /root/ssh-vpn-functions.sh

sleep 10

if [ -f /etc/proxy-python/active.txt ]; then
    while IFS='|' read -r port response banner ssh_port timestamp; do
        if [ ! -z "$port" ]; then
            start_proxy "$port" "$response" "$banner" "$ssh_port"
        fi
    done < /etc/proxy-python/active.txt
fi

exit 0
RESTOREEOF

chmod +x /etc/init.d/restore-proxies
update-rc.d restore-proxies defaults 2>/dev/null

# ====================
# SCRIPT MENÚ
# ====================
cat > /root/vpn-installer.sh << 'MAINSCRIPT'
#!/bin/bash

if [ ! -f /root/ssh-vpn-functions.sh ]; then
    echo "Error: Archivo de funciones no encontrado"
    exit 1
fi

source /root/ssh-vpn-functions.sh

# Incluir la función menu_principal aquí
MAINSCRIPT

# Agregar función menu_principal al script
cat >> /root/vpn-installer.sh <<'MENUEOF'
menu_principal() {
    while true; do
        clear
        IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        USERS_ONLINE=$(count_users)
        SWAP_SIZE=$(free -h | grep Swap | awk '{print $2}')
        SLOWDNS_STATUS=$(systemctl is-active slowdns 2>/dev/null)
        
        cat <<EOF
╔════════════════════════════════════════════════╗
║       PANEL DE GESTIÓN MSY VPN - v8           ║
╚════════════════════════════════════════════════╝

IP del Servidor: $IP
Usuarios Online: $USERS_ONLINE
Memoria Swap: $SWAP_SIZE
SlowDNS: $SLOWDNS_STATUS

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MENÚ PRINCIPAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1) Crear usuario VPN
2) Eliminar usuario VPN  
3) Ver usuarios conectados
4) Gestionar Proxies Python
5) Ver servicios activos y puertos
6) Cambiar Banner HTTP/1.1
7) Cambiar Banner SSH
8) Gestionar Túneles SSL/TLS
9) Administrar UDP Hysteria
10) Administrar SlowDNS
11) Estado de servicios
0) Salir
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
        read -p "Selecciona una opción: " option
        
        case $option in
            3)
                clear
                list_connected_users
                read -p "Presiona ENTER..."
                ;;
            11)
                clear
                echo "ESTADO DE SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                systemctl is-active --quiet ssh && echo "✓ OpenSSH" || echo "✗ OpenSSH"
                systemctl is-active --quiet dropbear && echo "✓ Dropbear" || echo "✗ Dropbear"
                systemctl is-active --quiet slowdns && echo "✓ SlowDNS" || echo "✗ SlowDNS"
                echo ""
                echo "UFW: DESHABILITADO (para Hysteria UDP)"
                echo "Swap: $SWAP_SIZE"
                read -p "Presiona ENTER..."
                ;;
            0)
                exit 0
                ;;
        esac
    done
}

menu_principal
MENUEOF

chmod +x /root/vpn-installer.sh

# Crear acceso directo
cat > /usr/local/bin/vpn-panel <<'SHORTCUT'
#!/bin/bash
bash /root/vpn-installer.sh
SHORTCUT

chmod +x /usr/local/bin/vpn-panel
ln -sf /usr/local/bin/vpn-panel /usr/local/bin/vpn-manager

# ====================
# MENÚ AUTOMÁTICO
# ====================
cat >> /root/.bashrc <<'AUTOEOF'

# MSY VPN - Menú automático
if [ -t 0 ]; then
    if [ -f /usr/local/bin/vpn-panel ]; then
        vpn-panel
    fi
fi
AUTOEOF

# ====================
# FIREWALL - DESHABILITADO PARA HYSTERIA
# ====================
echo "Configurando firewall..."

# DESHABILITAR UFW para Hysteria UDP
ufw --force disable

echo "✓ UFW deshabilitado (requerido para Hysteria UDP)"

# ====================
# CREAR USUARIO
# ====================
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
Estado: Activo
USEREOF

# ====================
# INICIAR PROXIES
# ====================
source /root/ssh-vpn-functions.sh

start_proxy "80" "101" "MSY VPN" "90"
start_proxy "8080" "101" "MSY VPN" "90"
start_proxy "8880" "101" "MSY VPN" "90"

# ====================
# OPTIMIZACIONES
# ====================
cat >> /etc/sysctl.conf <<EOF

# MSY VPN Optimizations
net.ipv4.ip_forward = 1
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_fin_timeout = 30
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
vm.swappiness = 10
EOF

sysctl -p >/dev/null 2>&1

# ====================
# INFO FINAL
# ====================
IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

clear
cat <<EOF

╔════════════════════════════════════════════════╗
║   ✓✓ INSTALACIÓN COMPLETADA - v8 ✓✓          ║
╚════════════════════════════════════════════════╝

IP: $IP

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NOVEDADES v8:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ SlowDNS instalado (puerto 5300)
✓ UFW DESHABILITADO (para Hysteria UDP)
✓ Contador usuarios CORREGIDO (incluye Hysteria)
✓ Swap 2GB activado

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SERVICIOS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ OpenSSH: 22
✓ Dropbear: 90
✓ Stunnel: 443, 444, 777
✓ SlowDNS: 5300 (UDP)
✓ BadVPN: 7300 (UDP)
✓ Hysteria: Opción 9
✓ Python Proxies: 80, 8080, 8880

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CREDENCIALES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Usuario: $USER_VPN
Password: $PASS_VPN

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SLOWDNS INFO:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Puerto: 5300 (UDP)
Nameserver: $IP
Public Key:
$(cat /etc/slowdns/server.pub 2>/dev/null || echo "Ver en Opción 10")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PANEL: vpn-panel (automático al login)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN v8

IP: $IP
USER: $USER_VPN / $PASS_VPN

SERVICIOS:
- OpenSSH: 22
- Dropbear: 90
- Stunnel: 443, 444, 777
- SlowDNS: 5300 (UDP)
- BadVPN: 7300 (UDP)
- Hysteria: Opción 9
- Proxies: 80, 8080, 8880

SLOWDNS:
Nameserver: $IP
Puerto: 5300
Public Key: /etc/slowdns/server.pub

IMPORTANTE:
UFW DESHABILITADO (necesario para Hysteria UDP)

PANEL: vpn-panel
INFOEOF

echo "Info guardada en /root/vpn-info.txt"
echo ""
read -p "¿Abrir panel ahora? (s/n): " open_menu
if [[ $open_menu == "s" || $open_menu == "S" ]]; then
    menu_principal
fi
