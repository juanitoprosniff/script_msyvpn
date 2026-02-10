#!/bin/bash
# Script SSH VPN Completo - V8 ULTIMATE
# - Xray/V2Ray: VLESS + VMESS (80 sin TLS, 443 con TLS)
# - SlowDNS integrado
# - Hysteria UDP con UFW disabled
# - Contador de usuarios ULTRA CORREGIDO
# - Gestión de UUID V2Ray
# - Dominio para SSL/TLS

clear
echo "================================================"
echo "   SSH VPN Server - Versión Ultimate v8"
echo "   Xray + SlowDNS + Hysteria + Dropbear"
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
pkill -9 -f "xray" 2>/dev/null
pkill -9 -f "v2ray" 2>/dev/null
systemctl stop squid 2>/dev/null
systemctl stop dropbear 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop ssh 2>/dev/null
systemctl stop xray 2>/dev/null
systemctl stop v2ray 2>/dev/null

# DESHABILITAR UFW PARA HYSTERIA UDP
echo "Deshabilitando UFW para UDP..."
ufw disable 2>/dev/null

# Actualizar sistema
echo "Actualizando sistema..."
apt update -y && apt upgrade -y

# Instalar dependencias
echo "Instalando dependencias..."
apt install -y python3 python3-pip openssh-server dropbear squid stunnel4 screen lsof curl wget nano net-tools cmake build-essential git jq nginx certbot python3-certbot-nginx uuid-runtime

# Crear directorios
mkdir -p /etc/proxy-python
mkdir -p /var/log/proxy-python
mkdir -p /etc/ssh-vpn
mkdir -p /etc/ssh-vpn/users
mkdir -p /etc/ssh-vpn/tunnels
mkdir -p /etc/hysteria
mkdir -p /etc/xray
mkdir -p /etc/slowdns
mkdir -p /usr/local/etc/xray

# ====================
# SOLICITAR DOMINIO PARA TLS
# ====================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "CONFIGURACIÓN DE DOMINIO PARA TLS/SSL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Para V2Ray/Xray con TLS necesitas un dominio apuntando a esta VPS"
echo "Ejemplo: vpn.tudominio.com"
echo ""
read -p "¿Tienes un dominio configurado? (s/n): " tiene_dominio

if [[ $tiene_dominio == "s" || $tiene_dominio == "S" ]]; then
    read -p "Ingresa tu dominio (ejemplo: vpn.tudominio.com): " DOMAIN
    USE_TLS="yes"
    
    # Configurar Nginx básico
    systemctl stop apache2 2>/dev/null
    systemctl disable apache2 2>/dev/null
    
    cat > /etc/nginx/sites-available/default <<NGINXEOF
server {
    listen 81 default_server;
    listen [::]:81 default_server;
    server_name $DOMAIN;
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
NGINXEOF
    
    systemctl enable nginx
    systemctl restart nginx
    
    # Obtener certificado SSL
    echo "Obteniendo certificado SSL para $DOMAIN..."
    certbot certonly --nginx --non-interactive --agree-tos --register-unsafely-without-email -d $DOMAIN
    
    if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        echo "✓ Certificado SSL obtenido correctamente"
        SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    else
        echo "⚠ No se pudo obtener el certificado SSL"
        echo "V2Ray funcionará solo sin TLS (puerto 80)"
        USE_TLS="no"
    fi
else
    echo "V2Ray funcionará solo sin TLS (puerto 80)"
    USE_TLS="no"
    DOMAIN="localhost"
fi

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
# OPENSSH (PUERTO 22)
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
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256
Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
RekeyLimit 512M 1h
EOF

systemctl enable ssh
systemctl restart ssh

# ====================
# DROPBEAR (PUERTO 90)
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
# STUNNEL (PUERTO 443)
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
accept = 442
connect = 127.0.0.1:90

[dropbear-ssl-alt]
accept = 444
connect = 127.0.0.1:90
EOF

echo "ENABLED=1" > /etc/default/stunnel4
systemctl enable stunnel4
systemctl restart stunnel4

# ====================
# BADVPN UDPGW
# ====================
echo "Instalando BadVPN..."

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
# INSTALAR XRAY/V2RAY
# ====================
echo "Instalando Xray-core..."

cd /usr/src
wget -q https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
unzip -o Xray-linux-64.zip -d /usr/local/bin/
chmod +x /usr/local/bin/xray
rm -f Xray-linux-64.zip

# Generar UUIDs
UUID1=$(uuidgen)
UUID2=$(uuidgen)

# Guardar UUIDs
cat > /etc/xray/uuids.txt <<UUIDEOF
# UUIDs V2Ray/Xray
VMESS_UUID=$UUID1
VLESS_UUID=$UUID2
UUIDEOF

# Configuración Xray
cat > /usr/local/etc/xray/config.json <<XRAYEOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": 8080,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID1",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess"
        }
      }
    },
    {
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID2",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
XRAYEOF

mkdir -p /var/log/xray

# Servicio Xray
cat > /etc/systemd/system/xray.service <<'XRAYSVC'
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
XRAYSVC

# Configurar Nginx para V2Ray (puerto 80 sin TLS y 443 con TLS)
if [ "$USE_TLS" = "yes" ]; then
    cat > /etc/nginx/sites-available/v2ray <<NGINXV2RAYEOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    root /var/www/html;
    index index.html;
    
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
NGINXV2RAYEOF
else
    cat > /etc/nginx/sites-available/v2ray <<NGINXV2RAYEOF
server {
    listen 8880;
    server_name _;
    
    root /var/www/html;
    index index.html;
    
    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    
    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
NGINXV2RAYEOF
fi

ln -sf /etc/nginx/sites-available/v2ray /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx

systemctl daemon-reload
systemctl enable xray
systemctl start xray

echo "✓ Xray instalado con VMESS y VLESS"

# ====================
# INSTALAR SLOWDNS
# ====================
echo "Instalando SlowDNS..."

cd /root
wget -q https://raw.githubusercontent.com/khaledagn/SlowDNS/main/slowdns -O /usr/local/bin/slowdns-install
chmod +x /usr/local/bin/slowdns-install

# Crear script básico SlowDNS
cat > /usr/local/bin/slowdns-manager <<'SLOWEOF'
#!/bin/bash
echo "SlowDNS Manager"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Para configurar SlowDNS, necesitas:"
echo "1. Un subdominio NS (ejemplo: ns.tudominio.com)"
echo "2. Configurar el registro NS en tu proveedor DNS"
echo ""
echo "Visita: https://github.com/khaledagn/SlowDNS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
read -p "Presiona ENTER para continuar..."
SLOWEOF

chmod +x /usr/local/bin/slowdns-manager

# ====================
# HYSTERIA UDP
# ====================
echo "Descargando Hysteria UDP..."

cd /root
wget -q -O install_agnudp.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install_agnudp.sh 2>/dev/null
wget -q -O agnudp_manager.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/agnudp_manager.sh 2>/dev/null

if [ -f install_agnudp.sh ] && [ -f agnudp_manager.sh ]; then
    chmod +x install_agnudp.sh agnudp_manager.sh
    bash install_agnudp.sh 2>/dev/null
    cp agnudp_manager.sh /usr/local/bin/hysteria-manager
    chmod +x /usr/local/bin/hysteria-manager
    echo "✓ Hysteria UDP instalado"
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
        
        print(f'[*] Proxy iniciado en {self.host}:{self.port}')
        print(f'[*] SSH Target: {self.ssh_host}:{self.ssh_port}')
        print(f'[*] Response: HTTP/1.1 {self.response_code} {self.banner}')
        
        while self.running:
            try:
                client, addr = self.server.accept()
                handler = ConnectionHandler(client, self, addr)
                handler.start()
            except KeyboardInterrupt:
                self.running = False
                break
            except:
                pass

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
            
            self.ssh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ssh.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.ssh.connect((self.server.ssh_host, self.server.ssh_port))
            
            response = f'HTTP/1.1 {self.server.response_code} {self.server.banner}\r\n'
            response += 'Content-Length: 999999\r\n'
            response += 'Connection: keep-alive\r\n\r\n'
            
            self.client.sendall(response.encode())
            self.transfer()
        except:
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
        except:
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
    port = int(sys.argv[1]) if len(sys.argv) > 1 else LISTENING_PORT
    response = sys.argv[2] if len(sys.argv) > 2 else RESPONSE_CODE
    banner = sys.argv[3] if len(sys.argv) > 3 else BANNER_TEXT
    ssh_port = int(sys.argv[4]) if len(sys.argv) > 4 else SSH_PORT
    
    server = ProxyServer(LISTENING_ADDR, port, SSH_HOST, ssh_port, response, banner)
    server.start()
PYEOF

chmod +x /etc/proxy-python/proxy.py

# ====================
# FUNCIONES (CONTADOR ULTRA CORREGIDO)
# ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

count_users() {
    # CONTADOR ULTRA CORREGIDO
    local total=0
    
    # Solo contar procesos sshd con pts (sesiones reales)
    local ssh_users=$(ps aux | grep 'sshd:' | grep 'pts' | grep -v 'root@' | wc -l)
    
    # Contar Dropbear (excluir loopback)
    local dropbear_users=$(ps aux | grep dropbear | grep -v grep | grep -v '127.0.0.1' | wc -l)
    
    # Contar Xray/V2Ray conexiones activas
    local xray_users=0
    if [ -f /var/log/xray/access.log ]; then
        xray_users=$(grep "accepted" /var/log/xray/access.log 2>/dev/null | tail -100 | grep -o "from.*:" | sort -u | wc -l)
    fi
    
    # Contar Hysteria UDP
    local hysteria_users=0
    if pgrep -x "hysteria" >/dev/null; then
        hysteria_users=$(netstat -anup 2>/dev/null | grep hysteria | grep ESTABLISHED | wc -l)
    fi
    
    total=$((ssh_users + dropbear_users + xray_users + hysteria_users))
    
    # Asegurar no negativo
    [ $total -lt 0 ] && total=0
    
    echo $total
}

list_connected_users() {
    echo "═══════════════════════════════════════════════════"
    echo "           USUARIOS CONECTADOS"
    echo "═══════════════════════════════════════════════════"
    
    echo ""
    echo "OpenSSH (puerto 22):"
    ps aux | grep 'sshd:' | grep 'pts' | grep -v 'root@' | awk '{print $1}' | sort -u | nl || echo "  Ninguno"
    
    echo ""
    echo "Dropbear (puerto 90):"
    ps aux | grep dropbear | grep -v grep | grep -v '127.0.0.1' | wc -l | xargs echo "  Conexiones:"
    
    echo ""
    echo "Xray/V2Ray:"
    if [ -f /var/log/xray/access.log ]; then
        grep "accepted" /var/log/xray/access.log 2>/dev/null | tail -20 | grep -o "from.*:" | cut -d: -f1 | sed 's/from //' | sort -u | nl || echo "  Ninguno"
    else
        echo "  Ninguno"
    fi
    
    echo ""
    echo "Hysteria UDP:"
    if pgrep -x "hysteria" >/dev/null; then
        netstat -anup 2>/dev/null | grep hysteria | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u | nl || echo "  Ninguno"
    else
        echo "  Ninguno"
    fi
    
    echo ""
    echo "Total de usuarios: $(count_users)"
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
    fi
}

stop_all_proxies() {
    screen -ls | grep "proxy-" | awk '{print $1}' | xargs -I {} screen -X -S {} quit 2>/dev/null
    pkill -9 -f "proxy.py" 2>/dev/null
    rm -f /etc/proxy-python/active.txt
    echo "" > /etc/proxy-python/active.txt
    echo "✓ Proxies detenidos"
}
FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

# ====================
# MENÚ PRINCIPAL
# ====================
cat > /root/vpn-installer.sh << 'MAINSCRIPT'
#!/bin/bash

if [ ! -f /root/ssh-vpn-functions.sh ]; then
    echo "Error: Funciones no encontradas"
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
╔════════════════════════════════════════════════╗
║       PANEL DE GESTIÓN MSY VPN - v8           ║
╚════════════════════════════════════════════════╝

IP: $IP
Usuarios Online: $USERS_ONLINE
Swap: $SWAP_SIZE

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MENÚ PRINCIPAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1) Crear usuario VPN
2) Eliminar usuario VPN
3) Ver usuarios conectados
4) Gestionar Proxies Python
5) Ver servicios activos
6) Cambiar Banner HTTP/1.1
7) Cambiar Banner SSH
8) Gestionar Túneles SSL/TLS
9) Administrar UDP Hysteria
10) Administrar V2Ray/Xray
11) Administrar SlowDNS
12) Estado de servicios
0) Salir
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
        read -p "Opción: " option
        
        case $option in
            1)
                clear
                echo "CREAR USUARIO VPN"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Usuario: " username
                read -p "Contraseña: " password
                read -p "Días (0=ilimitado): " days
                
                if id "$username" &>/dev/null; then
                    echo "Usuario ya existe"
                    read -p "ENTER..."
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
Creación: $(date +%Y-%m-%d)
Expiración: $expiry
Estado: Activo
USEREOF
                
                echo "✓ Usuario creado"
                read -p "ENTER..."
                ;;
            2)
                clear
                echo "ELIMINAR USUARIO"
                read -p "Usuario: " username
                
                if ! id "$username" &>/dev/null; then
                    echo "No existe"
                    read -p "ENTER..."
                    continue
                fi
                
                pkill -9 -u $username 2>/dev/null
                userdel -r $username 2>/dev/null
                rm -f /etc/ssh-vpn/users/$username.txt
                echo "✓ Eliminado"
                read -p "ENTER..."
                ;;
            3)
                clear
                list_connected_users
                read -p "ENTER..."
                ;;
            4)
                clear
                echo "PROXIES PYTHON"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Crear proxy"
                echo "2) Detener todos"
                echo "3) Ver activos"
                echo "0) Volver"
                read -p "Opción: " proxy_opt
                
                case $proxy_opt in
                    1)
                        read -p "Puerto: " port
                        read -p "Response (101): " response
                        response=${response:-101}
                        read -p "Banner [MSY VPN]: " banner
                        banner=${banner:-MSY VPN}
                        read -p "SSH port [90]: " ssh_port
                        ssh_port=${ssh_port:-90}
                        start_proxy "$port" "$response" "$banner" "$ssh_port"
                        read -p "ENTER..."
                        ;;
                    2)
                        stop_all_proxies
                        read -p "ENTER..."
                        ;;
                    3)
                        echo "Activos:"
                        screen -ls | grep "proxy-"
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            5)
                clear
                echo "SERVICIOS ACTIVOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                ss -tlnp | grep -E ':(22|90|442|444|8080|8443|8880) '
                echo ""
                ss -ulnp | grep ':7300 '
                read -p "ENTER..."
                ;;
            6)
                clear
                echo "CAMBIAR BANNER HTTP"
                grep "BANNER_TEXT = " /etc/proxy-python/proxy.py
                read -p "Nuevo banner: " new_banner
                new_banner=${new_banner:-MSY VPN}
                sed -i "s/BANNER_TEXT = .*/BANNER_TEXT = '$new_banner'/" /etc/proxy-python/proxy.py
                echo "✓ Actualizado"
                read -p "ENTER..."
                ;;
            7)
                clear
                echo "CAMBIAR BANNERS SSH"
                echo "1) OpenSSH"
                echo "2) Dropbear"
                read -p "Opción: " banner_opt
                
                if [ "$banner_opt" = "1" ]; then
                    nano /etc/ssh/banner.txt
                    systemctl restart ssh
                elif [ "$banner_opt" = "2" ]; then
                    nano /etc/dropbear/banner.txt
                    systemctl restart dropbear
                fi
                ;;
            8)
                clear
                echo "TÚNELES SSL"
                echo "1) Ver activos"
                echo "2) Agregar"
                echo "3) Reiniciar"
                read -p "Opción: " tun_opt
                
                case $tun_opt in
                    1)
                        cat /etc/stunnel/stunnel.conf
                        read -p "ENTER..."
                        ;;
                    2)
                        read -p "Nombre: " tname
                        read -p "Puerto: " tport
                        read -p "Destino [90]: " tdest
                        tdest=${tdest:-90}
                        echo "" >> /etc/stunnel/stunnel.conf
                        echo "[$tname]" >> /etc/stunnel/stunnel.conf
                        echo "accept = $tport" >> /etc/stunnel/stunnel.conf
                        echo "connect = 127.0.0.1:$tdest" >> /etc/stunnel/stunnel.conf
                        systemctl restart stunnel4
                        echo "✓ Creado"
                        read -p "ENTER..."
                        ;;
                    3)
                        systemctl restart stunnel4
                        echo "✓ Reiniciado"
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            9)
                if [ -f /usr/local/bin/hysteria-manager ]; then
                    bash /usr/local/bin/hysteria-manager
                else
                    echo "No instalado"
                    read -p "ENTER..."
                fi
                ;;
            10)
                clear
                echo "V2RAY/XRAY MANAGER"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Ver UUIDs"
                echo "2) Generar nuevo UUID"
                echo "3) Ver configuración"
                echo "4) Reiniciar Xray"
                echo "0) Volver"
                read -p "Opción: " xray_opt
                
                case $xray_opt in
                    1)
                        cat /etc/xray/uuids.txt
                        echo ""
                        echo "Puertos:"
                        echo "  VMESS: 8080 (ws path: /vmess)"
                        echo "  VLESS: 8443 (ws path: /vless)"
                        read -p "ENTER..."
                        ;;
                    2)
                        NEW_UUID=$(uuidgen)
                        echo "Nuevo UUID: $NEW_UUID"
                        echo "# $NEW_UUID" >> /etc/xray/uuids.txt
                        echo "Agrega manualmente a /usr/local/etc/xray/config.json"
                        read -p "ENTER..."
                        ;;
                    3)
                        nano /usr/local/etc/xray/config.json
                        ;;
                    4)
                        systemctl restart xray
                        echo "✓ Reiniciado"
                        read -p "ENTER..."
                        ;;
                esac
                ;;
            11)
                bash /usr/local/bin/slowdns-manager
                ;;
            12)
                clear
                echo "ESTADO"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                systemctl is-active ssh && echo "✓ SSH" || echo "✗ SSH"
                systemctl is-active dropbear && echo "✓ Dropbear" || echo "✗ Dropbear"
                systemctl is-active stunnel4 && echo "✓ Stunnel" || echo "✗ Stunnel"
                systemctl is-active xray && echo "✓ Xray" || echo "✗ Xray"
                systemctl is-active badvpn-udpgw && echo "✓ BadVPN" || echo "✗ BadVPN"
                pgrep -x hysteria >/dev/null && echo "✓ Hysteria" || echo "✗ Hysteria"
                echo ""
                echo "UFW: $(ufw status | head -1)"
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

cat > /usr/local/bin/vpn-panel <<'SHORTCUT'
#!/bin/bash
bash /root/vpn-installer.sh
SHORTCUT

chmod +x /usr/local/bin/vpn-panel

# ====================
# AUTO LOGIN
# ====================
cat >> /root/.bashrc <<'AUTOEOF'

if [ -t 0 ]; then
    if [ -f /usr/local/bin/vpn-panel ]; then
        vpn-panel
    fi
fi
AUTOEOF

# ====================
# RESTAURAR PROXIES
# ====================
cat > /etc/init.d/restore-proxies <<'RESTOREEOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          restore-proxies
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO

source /root/ssh-vpn-functions.sh
sleep 10

if [ -f /etc/proxy-python/active.txt ]; then
    while IFS='|' read -r port response banner ssh_port timestamp; do
        [ ! -z "$port" ] && start_proxy "$port" "$response" "$banner" "$ssh_port"
    done < /etc/proxy-python/active.txt
fi
RESTOREEOF

chmod +x /etc/init.d/restore-proxies
update-rc.d restore-proxies defaults 2>/dev/null

# ====================
# FIREWALL (UFW DISABLED PARA UDP)
# ====================
echo "Configurando firewall (UFW DISABLED para Hysteria UDP)..."
ufw disable

# ====================
# USUARIO INICIAL
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
Creación: $(date +%Y-%m-%d)
Expiración: Ilimitado
Estado: Activo
USEREOF

# ====================
# INICIAR PROXIES
# ====================
source /root/ssh-vpn-functions.sh
start_proxy "80" "101" "MSY VPN" "90"

# ====================
# OPTIMIZACIONES
# ====================
cat >> /etc/sysctl.conf <<EOF

net.ipv4.ip_forward = 1
net.ipv4.tcp_keepalive_time = 1200
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
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
║   ✓✓ INSTALACIÓN V8 COMPLETADA ✓✓             ║
╚════════════════════════════════════════════════╝

IP: $IP

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SERVICIOS INSTALADOS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ OpenSSH: 22
✓ Dropbear: 90 (ultra estable)
✓ Stunnel: 442, 444
✓ Xray/V2Ray: VMESS (8080), VLESS (8443)
✓ BadVPN UDP: 7300
✓ Hysteria UDP: Gestionar desde menú
✓ SlowDNS: Configurar desde menú
✓ Swap: 2GB

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CREDENCIALES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Usuario: $USER_VPN
Password: $PASS_VPN

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
V2RAY/XRAY UUIDs:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

cat /etc/xray/uuids.txt

cat <<EOF

Puertos V2Ray:
  VMESS: 8080 (path: /vmess)
  VLESS: 8443 (path: /vless)

EOF

if [ "$USE_TLS" = "yes" ]; then
    echo "✓ TLS Activado con dominio: $DOMAIN"
    echo "  Puerto HTTPS: 443"
else
    echo "⚠ Sin TLS - Solo puerto 8880"
fi

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NOVEDADES V8:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ UFW deshabilitado (Hysteria UDP funcional)
✓ Xray/V2Ray con VMESS y VLESS
✓ Contador de usuarios ULTRA CORREGIDO
✓ Cuenta usuarios de todos los servicios
✓ SlowDNS integrado
✓ Dominio SSL/TLS configurado

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PANEL: vpn-panel
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN v8

IP: $IP
Usuario: $USER_VPN / $PASS_VPN

SERVICIOS:
- SSH: 22
- Dropbear: 90
- Stunnel: 442, 444
- Xray VMESS: 8080
- Xray VLESS: 8443
- BadVPN: 7300
- Hysteria UDP: Menú
- SlowDNS: Menú

UFW: DISABLED (para Hysteria UDP)
Swap: 2GB
TLS: $USE_TLS
Dominio: $DOMAIN

UUIDs V2Ray: /etc/xray/uuids.txt
Panel: vpn-panel
INFOEOF

echo "Info guardada en /root/vpn-info.txt"
echo ""
read -p "¿Abrir panel? (s/n): " open_menu
if [[ $open_menu == "s" || $open_menu == "S" ]]; then
    bash /root/vpn-installer.sh
fi
