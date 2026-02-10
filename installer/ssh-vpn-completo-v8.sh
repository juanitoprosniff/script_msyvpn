#!/bin/bash
# Script SSH VPN Completo - V7 FINAL
# - OpenSSH: puerto 22, Dropbear: puerto 90
# - Swap 2GB automático
# - Hysteria UDP Manager integrado
# - Contador usuarios corregido (sin root)
# - Puertos persistentes tras reinicio

clear
echo "================================================"
echo "   SSH VPN Server - Versión Final v7"
echo "   Dropbear + Hysteria UDP + Swap 2GB"
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
apt install -y python3 python3-pip openssh-server dropbear squid stunnel4 screen lsof curl wget nano ufw net-tools cmake build-essential git jq

# Crear directorios
mkdir -p /etc/proxy-python
mkdir -p /var/log/proxy-python
mkdir -p /etc/ssh-vpn
mkdir -p /etc/ssh-vpn/users
mkdir -p /etc/ssh-vpn/tunnels
mkdir -p /etc/hysteria

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

[dropbear-vpn]
accept = 777
connect = 127.0.0.1:90
EOF

echo "ENABLED=1" > /etc/default/stunnel4
systemctl enable stunnel4
systemctl restart stunnel4

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
# CREAR MENÚ PRINCIPAL
# ====================
menu_principal() {
    source /root/ssh-vpn-functions.sh
    
    while true; do
        clear
        IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        USERS_ONLINE=$(count_users)
        SWAP_SIZE=$(free -h | grep Swap | awk '{print $2}')
        
        cat <<EOF
╔══════════════════════════════════════╗
║     MSY VPN Panel - v8              ║
╚══════════════════════════════════════╝
IP: $IP  |  Online: $USERS_ONLINE  |  Swap: $SWAP_SIZE

 1) Crear usuario          2) Eliminar usuario
 3) Ver conectados         4) Proxies Python
 5) Ver puertos            6) Banner HTTP proxy
 7) Banner SSH             8) Túneles SSL/TLS
 9) Hysteria UDP          10) Estado servicios
11) Reiniciar servicios    0) Salir
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
                        read -p "ENTER..."
                        ;;
                    2)
                        stop_all_proxies
                        read -p "ENTER..."
                        ;;
                    3)
                        echo "PROXIES ACTIVOS:"
                        screen -ls | grep "proxy-" || echo "No hay proxies activos"
                        echo ""
                        if [ -f /etc/proxy-python/active.txt ]; then
                            echo "Configuración:"
                            cat /etc/proxy-python/active.txt
                        fi
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
                echo "Dropbear SSH (puerto 90):"
                ss -tlnp | grep ':90 ' | grep -v grep
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
                read -p "Nuevo texto [MSY VPN]: " new_banner
                new_banner=${new_banner:-MSY VPN}
                
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
                            echo "✓ Banner Dropbear actualizado"
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
                systemctl is-active --quiet squid && echo "✓ Squid: Activo (puertos 3128, 8888)" || echo "✗ Squid: Inactivo"
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
                    3) systemctl restart dropbear && echo "✓ Dropbear reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    4) systemctl restart stunnel4 && echo "✓ Stunnel reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    5) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
                ;;
            0)
                exit 0
                ;;
        esac
    done
}

# ====================
# GUARDAR FUNCIONES (FIX CONTADOR)
# ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

count_users() {
    # Contar IPs únicas conectadas a puertos SSH (22 y 90), excluyendo localhost
    local ips_ssh=$(ss -tnp state established '( dport = :22 or sport = :22 )' 2>/dev/null \
        | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -v '127\.0\.0\.1' | grep -v '^$' | sort -u)
    local ips_drop=$(ss -tnp state established '( dport = :90 or sport = :90 )' 2>/dev/null \
        | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -v '127\.0\.0\.1' | grep -v '^$' | sort -u)
    # Combinar, eliminar duplicados y contar
    local total=$(echo -e "${ips_ssh}\n${ips_drop}" | grep -v '^$' | sort -u | wc -l)
    echo $total
}

list_connected_users() {
    echo "═══════════════════════════════════════"
    echo "        USUARIOS CONECTADOS"
    echo "═══════════════════════════════════════"
    
    echo ""
    echo "▸ OpenSSH (puerto 22):"
    local ips22=$(ss -tnp state established '( sport = :22 )' 2>/dev/null \
        | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -v '127\.0\.0\.1' | grep -v '^$' | sort -u)
    if [ -z "$ips22" ]; then
        echo "  Ninguna"
    else
        local n=1
        while IFS= read -r ip; do
            local user=$(who | awk '{print $1, $NF}' | sed 's/[()]//g' | awk -v ip="$ip" '$2==ip{print $1}' | head -1)
            [ -z "$user" ] && user="?"
            echo "  $n) $user @ $ip"
            n=$((n+1))
        done <<< "$ips22"
    fi
    
    echo ""
    echo "▸ Dropbear (puerto 90):"
    local ips90=$(ss -tnp state established '( sport = :90 )' 2>/dev/null \
        | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -v '127\.0\.0\.1' | grep -v '^$' | sort -u)
    if [ -z "$ips90" ]; then
        echo "  Ninguna"
    else
        local n=1
        while IFS= read -r ip; do
            echo "  $n) $ip"
            n=$((n+1))
        done <<< "$ips90"
    fi
    
    echo ""
    echo "  Total usuarios: $(count_users)"
    echo "═══════════════════════════════════════"
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
        echo "  Response: HTTP/1.1 $response $banner"
        echo "  Backend: puerto $ssh_port"
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

restart_proxies() {
    echo "Reiniciando proxies..."
    stop_all_proxies
    sleep 1
    if [ -f /etc/proxy-python/saved.txt ]; then
        cp /etc/proxy-python/saved.txt /etc/proxy-python/active.txt
    fi
    # Restaurar proxies por defecto si no hay configuración guardada
    if [ ! -s /etc/proxy-python/active.txt ]; then
        start_proxy "80"   "101" "MSY VPN" "90"
        start_proxy "8080" "101" "MSY VPN" "90"
        start_proxy "8880" "101" "MSY VPN" "90"
    else
        while IFS='|' read -r port response banner ssh_port timestamp; do
            [ -z "$port" ] && continue
            start_proxy "$port" "$response" "$banner" "$ssh_port"
        done < /etc/proxy-python/active.txt
    fi
    echo "✓ Proxies reiniciados"
}

restart_all_services() {
    echo "Reiniciando todos los servicios..."
    systemctl restart ssh       && echo "✓ OpenSSH reiniciado"  || echo "✗ OpenSSH: error"
    systemctl restart dropbear  && echo "✓ Dropbear reiniciado" || echo "✗ Dropbear: error"
    systemctl restart stunnel4  && echo "✓ Stunnel reiniciado"  || echo "✗ Stunnel: error"
    systemctl restart squid     && echo "✓ Squid reiniciado"    || echo "✗ Squid: error"
    restart_proxies
    echo "✓ Todos los servicios reiniciados"
}
FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

# ====================
# CREAR SCRIPT PARA RESTAURAR PROXIES AL REINICIAR
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
# Description:       Restaura los proxies Python activos después de reiniciar
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
# CREAR SCRIPT MENÚ
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
        IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        USERS_ONLINE=$(count_users)
        SWAP_SIZE=$(free -h | grep Swap | awk '{print $2}')
        
        cat <<EOF
╔══════════════════════════════════════╗
║     MSY VPN Panel - v8              ║
╚══════════════════════════════════════╝
IP: $IP  |  Online: $USERS_ONLINE  |  Swap: $SWAP_SIZE

 1) Crear usuario          2) Eliminar usuario
 3) Ver conectados         4) Proxies Python
 5) Ver puertos            6) Banner HTTP proxy
 7) Banner SSH             8) Túneles SSL/TLS
 9) Hysteria UDP          10) Estado servicios
11) Reiniciar servicios    0) Salir
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
                        read -p "ENTER..."
                        ;;
                    2)
                        stop_all_proxies
                        read -p "ENTER..."
                        ;;
                    3)
                        echo "PROXIES ACTIVOS:"
                        screen -ls | grep "proxy-" || echo "No hay proxies activos"
                        echo ""
                        if [ -f /etc/proxy-python/active.txt ]; then
                            echo "Configuración:"
                            cat /etc/proxy-python/active.txt
                        fi
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
                echo "Dropbear SSH (puerto 90):"
                ss -tlnp | grep ':90 ' | grep -v grep
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
                read -p "Nuevo texto [MSY VPN]: " new_banner
                new_banner=${new_banner:-MSY VPN}
                
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
                            echo "✓ Banner Dropbear actualizado"
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
                systemctl is-active --quiet squid && echo "✓ Squid: Activo (puertos 3128, 8888)" || echo "✗ Squid: Inactivo"
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
                    3) systemctl restart dropbear && echo "✓ Dropbear reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    4) systemctl restart stunnel4 && echo "✓ Stunnel reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    5) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
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

start_proxy "80" "101" "MSY VPN" "90"
start_proxy "8080" "101" "MSY VPN" "90"
start_proxy "8880" "101" "MSY VPN" "90"

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
║   ✓ INSTALACIÓN COMPLETADA - v8     ║
╚══════════════════════════════════════╝

IP: $IP

SERVICIOS:
✓ OpenSSH:      puerto 22
✓ Dropbear:     puerto 90
✓ Stunnel SSL:  443, 444, 777
✓ Proxies HTTP: 80, 8080, 8880
✓ BadVPN UDPGW: 7300
✓ Hysteria UDP: Opción 9 del panel
✓ UFW:          Desactivado

MEJORAS v8:
✓ Contador de usuarios corregido (IPs únicas)
✓ Opción 11: Reiniciar servicios/proxies
✓ Vista de conectados limpia (sin IPs duplicadas)
✓ UFW desactivado por defecto

CREDENCIALES:
Usuario: $USER_VPN
Password: $PASS_VPN

PANEL: ejecutar vpn-panel (auto al conectar)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v8

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear: 90
- Stunnel SSL: 443, 444, 777
- Python Proxy: 80, 8080, 8880
- BadVPN: 7300
- Hysteria UDP: Opción 9 del menú

USUARIO:
$USER_VPN / $PASS_VPN

SWAP: 2GB activado

PERSISTENCIA: Proxies se restauran tras reinicio

PANEL: vpn-panel (automático al login)
INFOEOF

echo "Información guardada en /root/vpn-info.txt"
echo ""
read -p "¿Deseas abrir el panel ahora? (s/n): " open_menu
if [[ $open_menu == "s" || $open_menu == "S" ]]; then
    menu_principal
fi
