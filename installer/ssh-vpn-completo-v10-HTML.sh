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
t.me/FREEINTERNETVPNMSY
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

# Configurar con opciones de compatibilidad
echo "Configurando compilación..."

# Modificar la versión SSH antes de compilar
echo "Modificando identificador SSH a 'SSH-2.0-ByJuanitoProSniff'..."
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
connect = 127.0.0.1:143

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
# NOTA: El banner soporta HTML para apps como HTTP Injector, HTTP Custom, etc.
# Ejemplo: <span style="background-color: #000000;"><span style="color:#eeff01;">TEXTO</span></span>

cat > /etc/proxy-python/proxy.py <<'PYEOF'
#!/usr/bin/env python3
"""
MSY VPN Proxy - Multi-metodo compatible
Soporta: HTTP CONNECT, HTTP GET/POST, WebSocket Upgrade, payload directo
Banner con HTML styling para apps SSH cliente modernas
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
    """Genera respuesta WebSocket Upgrade valida"""
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

            # --- WebSocket Upgrade ---
            if 'Upgrade: websocket' in head or 'upgrade: websocket' in head:
                m = re.search(r'Sec-WebSocket-Key:\s*(\S+)', head, re.I)
                if m:
                    self.client.sendall(ws_handshake_response(m.group(1)).encode())
                    return
                # fallback
                self.client.sendall(
                    f"HTTP/1.1 101 {banner}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".encode()
                )
                return

            # --- CONNECT method ---
            if head.startswith('CONNECT '):
                self.client.sendall(
                    f"HTTP/1.1 200 {banner}\r\n"
                    f"X-Channel: {channel}\r\n"
                    f"Connection: keep-alive\r\n\r\n".encode()
                )
                return

            # --- HTTP GET / POST / etc ---
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

            # --- Payload directo / sin cabecera HTTP ---
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
        print(f"[*] MSY VPN Proxy :{self.cfg['port']} → :{self.cfg['ssh_port']} | {self.cfg['banner']}")
        print(f"[*] Canal: {CHANNEL}")
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
                    3) systemctl restart dropbear && echo "✓ Dropbear (90)" || echo "✗ Error"
                       systemctl restart dropbear-legacy 2>/dev/null && echo "✓ Dropbear Legacy (143)" || true
                       read -p "ENTER..." ;;
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
    systemctl restart squid     && echo "✓ Squid"    || echo "✗ Squid: error"
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
}
echo "✓ Servicio de restauración de proxies configurado (systemd)"


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
        
        echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC}  \033[40m\033[1;33mMSY VPN SCRIPT\033[0m                   ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
        echo -e "${GREEN}IP:${NC} ${YELLOW}$IP${NC}  │  ${GREEN}Online:${NC} ${YELLOW}$USERS_ONLINE${NC}  │  ${GREEN}Swap:${NC} ${YELLOW}$SWAP_SIZE${NC}"
        echo ""
        echo -e "${BLUE} 1)${NC} Crear usuario          ${BLUE} 2)${NC} Eliminar usuario"
        echo -e "${BLUE} 3)${NC} Ver conectados         ${BLUE} 4)${NC} Proxies Python"
        echo -e "${BLUE} 5)${NC} Ver puertos            ${BLUE} 6)${NC} Banner HTTP proxy"
        echo -e "${BLUE} 7)${NC} Banner SSH             ${BLUE} 8)${NC} Túneles SSL/TLS"
        echo -e "${BLUE} 9)${NC} Hysteria UDP          ${BLUE}10)${NC} Estado servicios"
        echo -e "${BLUE}11)${NC} Reiniciar servicios   ${BLUE}12)${NC} Ver versiones Dropbear"
        echo -e "${RED} 0)${NC} Salir"
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
${CYAN}╔══════════════════════════════════════╗${NC}
${CYAN}║${NC}   ${GREEN}✓ INSTALACIÓN COMPLETADA - v10${NC}    ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════╝${NC}

${YELLOW}IP:${NC} ${CYAN}$IP${NC}

${GREEN}SERVICIOS SSH:${NC}
${GREEN}✓${NC} OpenSSH:           puerto 22
${GREEN}✓${NC} Dropbear 2020:     puerto 90
${GREEN}✓${NC} Dropbear 2016:     puerto 143 (SSH-2.0-ByJuanitoProSniff)
${GREEN}✓${NC} Stunnel SSL:       443→143, 444→90, 777→143

${GREEN}PROXIES:${NC}
${GREEN}✓${NC} Proxies HTTP:      80, 8080, 8880 (→ puerto 143 por defecto)
${GREEN}✓${NC} Squid:             3128, 8888

${GREEN}OTROS:${NC}
${GREEN}✓${NC} BadVPN UDPGW:      7300
${GREEN}✓${NC} Hysteria UDP:      Opción 9 del panel
${GREEN}✓${NC} UFW:               Desactivado
${GREEN}✓${NC} Swap:              2GB activado

${CYAN}MEJORAS v10 CUSTOM:${NC}
${GREEN}✓${NC} Dropbear 2016.74 con identificador SSH-2.0-ByJuanitoProSniff
${GREEN}✓${NC} Puerto 443 Stunnel → Dropbear 2016 (puerto 143)
${GREEN}✓${NC} Banners SSH reducidos y limpios
${GREEN}✓${NC} Menú colorido \"MSY VPN SCRIPT\"
${GREEN}✓${NC} Sistema de detención de proxies mejorado
${GREEN}✓${NC} Opción 12: Ver versiones instaladas

${YELLOW}CREDENCIALES:${NC}
${CYAN}Usuario:${NC} $USER_VPN
${CYAN}Password:${NC} $PASS_VPN

${YELLOW}PANEL:${NC} ejecutar ${CYAN}vpn-panel${NC} (auto al conectar)
${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
"

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v10 CUSTOM

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear 2020: 90
- Dropbear 2016: 143 (SSH-2.0-ByJunitoProSniff)
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
- Puerto 143: Dropbear 2016.74 (SSH-2.0-ByJunitoProSniff)

STUNNEL:
- Puerto 443 → Dropbear 2016 (143)
- Puerto 444 → Dropbear 2020 (90)  
- Puerto 777 → Dropbear 2016 (143)

BANNERS: Reducidos y limpios
MENÚ: Colorido "MSY VPN SCRIPT"
PERSISTENCIA: Proxies se restauran tras reinicio
PANEL: vpn-panel (automático al login)

OPCIÓN 12: Ver versiones de Dropbear instaladas
INFOEOF

echo "Información guardada en /root/vpn-info.txt"
echo ""
read -p "¿Deseas abrir el panel ahora? (s/n): " open_menu
if [[ $open_menu == "s" || $open_menu == "S" ]]; then
    menu_principal
fi
