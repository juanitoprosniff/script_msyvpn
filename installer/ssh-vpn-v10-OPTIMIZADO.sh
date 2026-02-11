#!/bin/bash
# SSH VPN Server v10 - Optimizado
# Canal: t.me/FREEINTERNETVPNMSY

clear
echo "========================================"
echo "   SSH VPN Server v10 - Instalando"
echo "========================================"

[[ $EUID -ne 0 ]] && { echo "Ejecutar como root"; exit 1; }

# Detener servicios
pkill -9 -f "proxy-python" 2>/dev/null
pkill -9 -f "badvpn-udpgw" 2>/dev/null
systemctl stop squid dropbear stunnel4 ssh 2>/dev/null

# Actualizar e instalar
apt update -y && apt upgrade -y
apt install -y python3 openssh-server dropbear squid stunnel4 screen lsof curl wget nano net-tools cmake build-essential git jq zlib1g-dev

# Crear directorios
mkdir -p /etc/{proxy-python,ssh-vpn/{users,tunnels},hysteria,dropbear-legacy,stunnel} /opt/dropbear-2016 /var/log/proxy-python

# ==================== SWAP 2GB ====================
echo "Configurando Swap 2GB..."
if [ ! -f /swapfile ] || [ $(stat -f -c%s /swapfile 2>/dev/null) -lt 2147483648 ]; then
    swapoff /swapfile 2>/dev/null; rm -f /swapfile
    dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "vm.swappiness=10" >> /etc/sysctl.conf; sysctl -p >/dev/null 2>&1
fi

# ==================== OPENSSH ====================
cat > /etc/ssh/banner.txt <<'EOF'
t.me/FREEINTERNETVPNMSY
EOF

cat > /etc/ssh/sshd_config <<'EOF'
Port 22
ListenAddress 0.0.0.0
Banner /etc/ssh/banner.txt
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
UsePAM yes
X11Forwarding yes
ClientAliveInterval 120
ClientAliveCountMax 3
MaxStartups 100:30:200
MaxSessions 100
EOF

systemctl enable ssh && systemctl restart ssh

# ==================== DROPBEAR 90 ====================
cat > /etc/dropbear/banner.txt <<'EOF'
t.me/FREEINTERNETVPNMSY
EOF

cat > /etc/default/dropbear <<'EOF'
NO_START=0
DROPBEAR_PORT=90
DROPBEAR_EXTRA_ARGS="-w -b /etc/dropbear/banner.txt -K 60 -I 300"
DROPBEAR_RECEIVE_WINDOW=65536
EOF

systemctl enable dropbear && systemctl restart dropbear

# ==================== DROPBEAR 2016 (143) ====================
echo "Compilando Dropbear 2016.74..."
cd /usr/src
if [ ! -f dropbear-2016.74.tar.bz2 ]; then
    wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2
fi
rm -rf dropbear-2016.74; tar xjf dropbear-2016.74.tar.bz2; cd dropbear-2016.74

# Modificar identificador SSH
[ -f sysoptions.h ] && sed -i 's|^#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' sysoptions.h
[ -f default_options.h ] && sed -i 's/#define LOCAL_IDENT "SSH-2.0-dropbear_" DROPBEAR_VERSION/#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"/' default_options.h

./configure --prefix=/opt/dropbear-2016 --disable-zlib --disable-wtmp --disable-lastlog
make -j$(nproc) PROGRAMS="dropbear dropbearkey" && make install PROGRAMS="dropbear dropbearkey"

if [ -f /opt/dropbear-2016/sbin/dropbear ]; then
    mkdir -p /etc/dropbear-legacy
    [ ! -f /etc/dropbear-legacy/dropbear_rsa_host_key ] && /opt/dropbear-2016/bin/dropbearkey -t rsa -f /etc/dropbear-legacy/dropbear_rsa_host_key -s 2048
    [ ! -f /etc/dropbear-legacy/dropbear_dss_host_key ] && /opt/dropbear-2016/bin/dropbearkey -t dss -f /etc/dropbear-legacy/dropbear_dss_host_key
    
    echo "t.me/FREEINTERNETVPNMSY" > /etc/dropbear-legacy/banner.txt
    
    cat > /etc/systemd/system/dropbear-legacy.service <<'EOF'
[Unit]
Description=Dropbear SSH 2016 - Puerto 143
After=network.target

[Service]
Type=simple
ExecStart=/opt/dropbear-2016/sbin/dropbear -F -E -p 143 -r /etc/dropbear-legacy/dropbear_rsa_host_key -d /etc/dropbear-legacy/dropbear_dss_host_key -b /etc/dropbear-legacy/banner.txt -K 60 -I 300
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable dropbear-legacy && systemctl start dropbear-legacy
fi
cd /root

# ==================== STUNNEL ====================
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=US/ST=State/L=City/O=MSY/CN=MSY-Server" \
    -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem 2>/dev/null
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
systemctl enable stunnel4 && systemctl restart stunnel4

# ==================== BADVPN ====================
cd /usr/src
git clone https://github.com/ambrop72/badvpn.git 2>/dev/null || (cd badvpn && git pull)
cd badvpn; mkdir -p build; cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc) && make install

cat > /etc/systemd/system/badvpn-udpgw.service <<'EOF'
[Unit]
Description=BadVPN UDPGW
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload && systemctl enable badvpn-udpgw && systemctl start badvpn-udpgw
cd /root

# ==================== HYSTERIA ====================
wget -q -O install_agnudp.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install_agnudp.sh 2>/dev/null
wget -q -O agnudp_manager.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/agnudp_manager.sh 2>/dev/null
if [ -f install_agnudp.sh ]; then
    chmod +x install_agnudp.sh agnudp_manager.sh
    bash install_agnudp.sh 2>/dev/null
    cp agnudp_manager.sh /usr/local/bin/hysteria-manager
    chmod +x /usr/local/bin/hysteria-manager
fi

# ==================== PROXY PYTHON ====================
cat > /etc/proxy-python/proxy.py <<'PYEOF'
#!/usr/bin/env python3
import socket, threading, select, sys, re, base64, hashlib

BUFLEN = 65536
TIMEOUT = 120
BANNER = '\033[1;31mMSY VPN\033[0m'
CHANNEL = 't.me/FREEINTERNETVPNMSY'

def ws_handshake(key):
    magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    accept = base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()
    return f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"

class Handler(threading.Thread):
    def __init__(self, client, cfg, addr):
        super().__init__(daemon=True)
        self.client = client
        self.cfg = cfg
        self.ssh = None
    
    def run(self):
        try:
            data = self.client.recv(BUFLEN)
            if not data: return
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.cfg['ssh_host'], self.cfg['ssh_port']))
            self.ssh = s
            self._respond(data)
            self._tunnel()
        except: pass
        finally: self._close()
    
    def _respond(self, data):
        try:
            head = data[:4096].decode('utf-8', errors='ignore')
            if 'Upgrade: websocket' in head or 'upgrade: websocket' in head:
                m = re.search(r'Sec-WebSocket-Key:\s*(\S+)', head, re.I)
                self.client.sendall((ws_handshake(m.group(1)) if m else f"HTTP/1.1 101 {BANNER}\r\n\r\n").encode())
            elif head.startswith('CONNECT '):
                self.client.sendall(f"HTTP/1.1 200 {BANNER}\r\nConnection: keep-alive\r\n\r\n".encode())
            else:
                self.client.sendall(f"HTTP/1.1 {self.cfg['code']} {BANNER}\r\nContent-Length: 999999\r\nConnection: keep-alive\r\n\r\n".encode())
        except: pass
    
    def _tunnel(self):
        try:
            while True:
                r, _, _ = select.select([self.client, self.ssh], [], [], TIMEOUT)
                if not r: break
                for s in r:
                    d = s.recv(BUFLEN)
                    if not d: return
                    (self.ssh if s is self.client else self.client).sendall(d)
        except: pass
    
    def _close(self):
        for s in (self.client, self.ssh):
            try: s.close() if s else None
            except: pass

class Proxy:
    def __init__(self, host, port, ssh_host, ssh_port, code, banner):
        self.cfg = {'host': host, 'port': port, 'ssh_host': ssh_host, 'ssh_port': ssh_port, 'code': code, 'banner': banner}
    
    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.cfg['host'], self.cfg['port']))
        srv.listen(1000)
        print(f"[*] Proxy :{self.cfg['port']} → :{self.cfg['ssh_port']}")
        while True:
            try:
                c, a = srv.accept()
                Handler(c, self.cfg, a).start()
            except: pass

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    code = sys.argv[2] if len(sys.argv) > 2 else '101'
    banner = sys.argv[3] if len(sys.argv) > 3 else BANNER
    ssh_port = int(sys.argv[4]) if len(sys.argv) > 4 else 143
    Proxy('0.0.0.0', port, '127.0.0.1', ssh_port, code, banner).start()
PYEOF

chmod +x /etc/proxy-python/proxy.py

# ==================== SQUID ====================
cat > /etc/squid/squid.conf <<'EOF'
http_port 3128
http_port 8888
acl all src 0.0.0.0/0
http_access allow all
forwarded_for delete
via off
cache deny all
EOF

systemctl enable squid && systemctl restart squid

# ==================== FUNCIONES ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

count_users() {
    local ips=$(ss -tnp state established '( dport = :22 or sport = :22 or dport = :90 or sport = :90 )' 2>/dev/null \
        | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -v '127\.0\.0\.1' | sort -u | wc -l)
    echo $ips
}

list_connected_users() {
    echo "USUARIOS CONECTADOS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "OpenSSH (22):"
    ss -tnp state established '( sport = :22 )' 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -v '127\.0\.0\.1' | sort -u | nl
    echo ""
    echo "Dropbear (90, 143):"
    ss -tnp state established '( sport = :90 or sport = :143 )' 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -v '127\.0\.0\.1' | sort -u | nl
    echo ""
    echo "Total: $(count_users)"
}

start_proxy() {
    local port=$1 response=$2 banner=$3 ssh_port=${4:-143} save=${5:-1}
    screen -list | grep -q "proxy-$port" && { echo "Puerto $port en uso"; return 1; }
    screen -dmS "proxy-$port" python3 /etc/proxy-python/proxy.py "$port" "$response" "$banner" "$ssh_port"
    sleep 1
    screen -list | grep -q "proxy-$port" && {
        echo "✓ Proxy :$port → SSH:$ssh_port"
        [ "$save" = "1" ] && { sed -i "/^${port}|/d" /etc/proxy-python/proxies.conf 2>/dev/null; echo "${port}|${response}|${banner}|${ssh_port}" >> /etc/proxy-python/proxies.conf; }
    } || echo "✗ Error en puerto $port"
}

stop_proxy() {
    local port=$1
    screen -X -S "proxy-$port" quit 2>/dev/null
    pkill -f "proxy.py $port " 2>/dev/null
    kill -9 $(lsof -ti:$port 2>/dev/null) 2>/dev/null
    sed -i "/^${port}|/d" /etc/proxy-python/proxies.conf 2>/dev/null
    echo "✓ Proxy :$port detenido"
}

stop_all_proxies() {
    screen -ls | grep "proxy-" | awk '{print $1}' | xargs -I {} screen -X -S {} quit 2>/dev/null
    pkill -9 -f "proxy.py" 2>/dev/null
    echo "✓ Proxies detenidos"
}

restore_proxies() {
    local conf=/etc/proxy-python/proxies.conf
    if [ ! -f "$conf" ]; then
        echo "80|101|MSY VPN|143" > "$conf"
        echo "8080|101|MSY VPN|143" >> "$conf"
        echo "8880|101|MSY VPN|143" >> "$conf"
    fi
    while IFS='|' read -r port response banner ssh_port; do
        [ -z "$port" ] && continue
        screen -list | grep -q "proxy-$port" || start_proxy "$port" "$response" "$banner" "$ssh_port" "0"
    done < "$conf"
}

restart_proxies() {
    stop_all_proxies; sleep 1; restore_proxies
}

restart_all_services() {
    systemctl restart ssh dropbear dropbear-legacy stunnel4 squid 2>/dev/null
    restart_proxies
    echo "✓ Servicios reiniciados"
}
FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

# ==================== SERVICIO RESTAURAR PROXIES ====================
cat > /etc/systemd/system/restore-proxies.service <<'EOF'
[Unit]
Description=MSY VPN - Restaurar Proxies
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 5
ExecStart=/bin/bash -c 'source /root/ssh-vpn-functions.sh && restore_proxies'

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload && systemctl enable restore-proxies
[ ! -f /etc/proxy-python/proxies.conf ] && {
    echo "80|101|MSY VPN|143" > /etc/proxy-python/proxies.conf
    echo "8080|101|MSY VPN|143" >> /etc/proxy-python/proxies.conf
    echo "8880|101|MSY VPN|143" >> /etc/proxy-python/proxies.conf
}

# ==================== MENÚ PRINCIPAL ====================
cat > /root/vpn-installer.sh <<'MAINSCRIPT'
#!/bin/bash
source /root/ssh-vpn-functions.sh 2>/dev/null || { echo "Error: Funciones no encontradas"; exit 1; }

menu_principal() {
    while true; do
        clear
        IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        USERS=$(count_users)
        SWAP=$(free -h | grep Swap | awk '{print $2}')
        
        echo -e "${BLUE}╔════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}  ${BOLD}MSY VPN SCRIPT${NC}                 ${BLUE}║${NC}"
        echo -e "${BLUE}╚════════════════════════════════════╝${NC}"
        echo -e "${GREEN}IP:${NC} $IP │ ${GREEN}Online:${NC} $USERS │ ${GREEN}Swap:${NC} $SWAP"
        echo ""
        echo -e " ${CYAN}1)${NC} Crear usuario       ${CYAN}2)${NC} Eliminar usuario"
        echo -e " ${CYAN}3)${NC} Ver conectados      ${CYAN}4)${NC} Proxies Python"
        echo -e " ${CYAN}5)${NC} Ver puertos         ${CYAN}6)${NC} Banner proxy"
        echo -e " ${CYAN}7)${NC} Banner SSH          ${CYAN}8)${NC} Túneles SSL"
        echo -e " ${CYAN}9)${NC} Hysteria UDP       ${CYAN}10)${NC} Estado servicios"
        echo -e "${CYAN}11)${NC} Reiniciar           ${CYAN}12)${NC} Versiones Dropbear"
        echo -e " ${RED}0)${NC} Salir"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        read -p "Opción: " opt
        
        case $opt in
            1) clear; echo "CREAR USUARIO"
               read -p "Usuario: " user; read -p "Contraseña: " pass; read -p "Días (0=ilimitado): " days
               id "$user" &>/dev/null && { echo "Usuario existe"; read -p "ENTER..."; continue; }
               useradd -m -s /bin/bash $user; echo "$user:$pass" | chpasswd
               [ "$days" -gt 0 ] && { exp=$(date -d "+$days days" +%Y-%m-%d); chage -E $exp $user; } || exp="Ilimitado"
               cat > /etc/ssh-vpn/users/$user.txt <<EOF
Usuario: $user
Contraseña: $pass
Creación: $(date +%Y-%m-%d)
Expiración: $exp
EOF
               echo "✓ Usuario creado"; read -p "ENTER..." ;;
            2) clear; read -p "Usuario a eliminar: " user
               id "$user" &>/dev/null || { echo "No existe"; read -p "ENTER..."; continue; }
               pkill -9 -u $user 2>/dev/null; userdel -r $user 2>/dev/null
               rm -f /etc/ssh-vpn/users/$user.txt; echo "✓ Eliminado"; read -p "ENTER..." ;;
            3) clear; list_connected_users; read -p "ENTER..." ;;
            4) clear; echo "PROXIES PYTHON"
               echo "1) Nuevo  2) Detener todos  3) Ver activos  4) Detener uno  0) Volver"
               read -p "Opción: " popt
               case $popt in
                   1) read -p "Puerto: " port; read -p "Code [101]: " code; code=${code:-101}
                      read -p "Banner [MSY VPN]: " banner; banner=${banner:-MSY VPN}
                      echo "SSH: 1)22  2)90  3)143  4)Otro"; read -p "[3]: " be; 
                      case ${be:-3} in 1) sp=22;; 2) sp=90;; 3) sp=143;; 4) read -p "Puerto: " sp;; *) sp=143;; esac
                      start_proxy "$port" "$code" "$banner" "$sp"; read -p "ENTER..." ;;
                   2) stop_all_proxies; read -p "ENTER..." ;;
                   3) echo "ACTIVOS:"; screen -ls | grep "proxy-" | sed 's/.*proxy-/  :/' | sed 's/\t.*//'
                      echo ""; cat /etc/proxy-python/proxies.conf 2>/dev/null; read -p "ENTER..." ;;
                   4) screen -ls | grep "proxy-"; read -p "Puerto: " dp; stop_proxy "$dp"; read -p "ENTER..." ;;
               esac ;;
            5) clear; echo "PUERTOS ACTIVOS"; ss -tlnp | grep -E ':(22|90|143|443|444|777|3128|8888|80|8080|8880) '; read -p "ENTER..." ;;
            6) clear; grep "BANNER = " /etc/proxy-python/proxy.py
               read -p "Nuevo banner: " nb; [ -n "$nb" ] && sed -i "s/BANNER = .*/BANNER = '$nb'/" /etc/proxy-python/proxy.py
               echo "✓ Actualizado. Reinicia proxies"; read -p "ENTER..." ;;
            7) clear; echo "BANNERS SSH: 1)OpenSSH  2)Dropbear  3)Legacy  0)Volver"; read -p "Opción: " bopt
               case $bopt in
                   1) cat /etc/ssh/banner.txt; echo ""; read -p "Nuevo (FIN termina): " -r nb
                      > /tmp/b.txt; while read -r line; do [ "$line" = "FIN" ] && break; echo "$line" >> /tmp/b.txt; done
                      [ -s /tmp/b.txt ] && { cp /tmp/b.txt /etc/ssh/banner.txt; systemctl restart ssh; }; rm /tmp/b.txt; read -p "ENTER..." ;;
                   2|3) [ "$bopt" = "2" ] && f=/etc/dropbear/banner.txt || f=/etc/dropbear-legacy/banner.txt
                      cat $f 2>/dev/null; echo ""; > /tmp/b.txt
                      while read -r line; do [ "$line" = "FIN" ] && break; echo "$line" >> /tmp/b.txt; done
                      [ -s /tmp/b.txt ] && { cp /tmp/b.txt $f; systemctl restart dropbear dropbear-legacy; }; rm /tmp/b.txt; read -p "ENTER..." ;;
               esac ;;
            8) clear; echo "TÚNELES SSL: 1)Ver  2)Agregar  3)Eliminar  4)Reiniciar  0)Volver"; read -p "Opción: " topt
               case $topt in
                   1) cat /etc/stunnel/stunnel.conf | grep -E '\[|accept|connect'; ss -tlnp | grep stunnel; read -p "ENTER..." ;;
                   2) read -p "Nombre: " tn; read -p "Puerto escucha: " tp; read -p "Puerto destino [90]: " td; td=${td:-90}
                      echo -e "\n[$tn]\naccept = $tp\nconnect = 127.0.0.1:$td" >> /etc/stunnel/stunnel.conf
                      systemctl restart stunnel4; echo "✓ Túnel creado"; read -p "ENTER..." ;;
                   3) read -p "Puerto a eliminar: " dp; sed -i "/accept = $dp/,+1 d" /etc/stunnel/stunnel.conf
                      systemctl restart stunnel4; echo "✓ Eliminado"; read -p "ENTER..." ;;
                   4) systemctl restart stunnel4; echo "✓ Reiniciado"; read -p "ENTER..." ;;
               esac ;;
            9) [ -f /usr/local/bin/hysteria-manager ] && bash /usr/local/bin/hysteria-manager || echo "No instalado"; read -p "ENTER..." ;;
            10) clear; echo -e "${CYAN}ESTADO SERVICIOS${NC}\n"
                systemctl is-active --quiet ssh && echo -e "${GREEN}✓ SSH (22)${NC}" || echo -e "${RED}✗ SSH${NC}"
                systemctl is-active --quiet dropbear && echo -e "${GREEN}✓ Dropbear (90)${NC}" || echo -e "${RED}✗ Dropbear${NC}"
                systemctl is-active --quiet dropbear-legacy && echo -e "${GREEN}✓ Dropbear 2016 (143)${NC}" || echo -e "${RED}✗ Legacy${NC}"
                systemctl is-active --quiet stunnel4 && echo -e "${GREEN}✓ Stunnel (443,444,777)${NC}" || echo -e "${RED}✗ Stunnel${NC}"
                systemctl is-active --quiet squid && echo -e "${GREEN}✓ Squid (3128,8888)${NC}" || echo -e "${RED}✗ Squid${NC}"
                systemctl is-active --quiet badvpn-udpgw && echo -e "${GREEN}✓ BadVPN (7300)${NC}" || echo -e "${RED}✗ BadVPN${NC}"
                echo -e "\nProxies: $(screen -ls | grep -c proxy-)"; read -p "ENTER..." ;;
            11) clear; echo "1)Proxies  2)SSH  3)Dropbear  4)Stunnel  5)TODO  0)Volver"; read -p "Opción: " ropt
                case $ropt in
                    1) restart_proxies ;;
                    2) systemctl restart ssh; echo "✓ SSH" ;;
                    3) systemctl restart dropbear dropbear-legacy; echo "✓ Dropbear" ;;
                    4) systemctl restart stunnel4; echo "✓ Stunnel" ;;
                    5) restart_all_services ;;
                esac; read -p "ENTER..." ;;
            12) clear; echo "VERSIONES DROPBEAR"
                echo "Sistema (90):"; /usr/sbin/dropbear -V 2>&1 | head -1
                echo ""; echo "Legacy (143):"
                [ -f /opt/dropbear-2016/sbin/dropbear ] && /opt/dropbear-2016/sbin/dropbear -V 2>&1 | head -1 || echo "No instalado"
                read -p "ENTER..." ;;
            0) exit 0 ;;
        esac
    done
}

menu_principal
MAINSCRIPT

chmod +x /root/vpn-installer.sh

cat > /usr/local/bin/vpn-panel <<'EOF'
#!/bin/bash
bash /root/vpn-installer.sh
EOF
chmod +x /usr/local/bin/vpn-panel

# Auto-inicio
cat >> /root/.bashrc <<'EOF'

# MSY VPN Auto
[ -t 0 ] && [ -f /usr/local/bin/vpn-panel ] && vpn-panel
EOF

# Firewall
ufw --force disable

# Usuario inicial
USER_VPN="vpnuser"
PASS_VPN="msy$(openssl rand -hex 4)"
id "$USER_VPN" &>/dev/null && userdel -r $USER_VPN 2>/dev/null
useradd -m -s /bin/bash $USER_VPN
echo "$USER_VPN:$PASS_VPN" | chpasswd
cat > /etc/ssh-vpn/users/$USER_VPN.txt <<EOF
Usuario: $USER_VPN
Contraseña: $PASS_VPN
Creación: $(date +%Y-%m-%d)
Expiración: Ilimitado
EOF

# Iniciar proxies
source /root/ssh-vpn-functions.sh && restore_proxies

# Optimizaciones
cat >> /etc/sysctl.conf <<EOF
net.ipv4.ip_forward=1
net.ipv4.tcp_keepalive_time=1200
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl -p >/dev/null 2>&1

# Fin
IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
clear
echo -e "
\033[1;34m╔════════════════════════════════════╗\033[0m
\033[1;34m║\033[0m   \033[1;32m✓ INSTALACIÓN COMPLETA\033[0m        \033[1;34m║\033[0m
\033[1;34m╚════════════════════════════════════╝\033[0m

\033[1;33mIP:\033[0m $IP

\033[1;32mSERVICIOS:\033[0m
✓ SSH: 22
✓ Dropbear: 90, 143
✓ SSL: 443, 444, 777
✓ Proxies: 80, 8080, 8880
✓ Squid: 3128, 8888
✓ BadVPN: 7300

\033[1;33mUSUARIO:\033[0m $USER_VPN
\033[1;33mPASS:\033[0m $PASS_VPN

\033[1;36mPANEL: vpn-panel\033[0m
"

read -p "Abrir panel? (s/n): " open
[[ $open == "s" ]] && bash /root/vpn-installer.sh
