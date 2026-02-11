#!/bin/bash
# Script SSH VPN Completo - V10 SSL MEJORADO
# - OpenSSH: 22, Dropbear: 90, Dropbear Legacy 2016 (Ubuntu 18): 143
# - Dropbear 2016.74 COMPILADO DESDE FUENTE
# - Proxy Python multi-método: HTTP, CONNECT, WebSocket
# - SSL/TLS MEJORADO: Acepta payloads, proxies y remote payloads
# - Proxies persistentes con systemd (auto-restore al reiniciar)
# - Contador usuarios real (IPs únicas por ss)
# - Swap 2GB, Hysteria UDP, BadVPN UDPGW
# - UFW desactivado
# - Canal: t.me/FREEINTERNETVPNMSY

clear
echo "================================================"
echo "   SSH VPN Server - Versión Final v10"
echo "   SSL/TLS MEJORADO + Dropbear + Hysteria"
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
pkill -9 -f "ssl-proxy" 2>/dev/null
systemctl stop squid 2>/dev/null
systemctl stop dropbear 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop ssh 2>/dev/null
systemctl stop nginx 2>/dev/null

# Actualizar sistema
echo "Actualizando sistema..."
apt update -y && apt upgrade -y

# Instalar dependencias
echo "Instalando dependencias..."
apt install -y python3 python3-pip openssh-server dropbear squid stunnel4 screen lsof curl wget nano ufw net-tools cmake build-essential git jq zlib1g-dev nginx openssl

# Crear directorios
mkdir -p /etc/proxy-python
mkdir -p /var/log/proxy-python
mkdir -p /etc/ssh-vpn
mkdir -p /etc/ssh-vpn/users
mkdir -p /etc/ssh-vpn/tunnels
mkdir -p /etc/hysteria
mkdir -p /etc/dropbear-legacy
mkdir -p /opt/dropbear-2016
mkdir -p /etc/ssl-proxy
mkdir -p /var/log/ssl-proxy

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
    wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2
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
# PROXY SSL PYTHON MEJORADO - ACEPTA PAYLOADS Y PROXIES
# ====================
echo "Creando proxy SSL mejorado con soporte para payloads..."

cat > /etc/ssl-proxy/ssl-proxy.py <<'SSLPROXY'
#!/usr/bin/env python3
"""
SSL/TLS Proxy Mejorado - Soporta payloads HTTP, CONNECT, WebSocket y remote payloads
Compatible con HTTP Custom y métodos avanzados de conexión
"""

import socket
import select
import threading
import ssl
import re
import sys
from datetime import datetime

class SSLProxyServer:
    def __init__(self, listen_port, backend_host, backend_port, cert_file, key_file):
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.cert_file = cert_file
        self.key_file = key_file
        self.buffer_size = 8192
        
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}", flush=True)
        
    def create_ssl_context(self):
        """Crear contexto SSL flexible que acepta cualquier tipo de conexión"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_file, self.key_file)
        
        # Configuración permisiva para aceptar todo tipo de conexiones
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Soportar TLS 1.0, 1.1, 1.2, 1.3
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Opciones de compatibilidad
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_ALL
        
        # Cifrados compatibles y seguros
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        return context
    
    def parse_http_request(self, data):
        """Detectar y parsear diferentes tipos de requests HTTP"""
        try:
            data_str = data.decode('utf-8', errors='ignore')
            
            # Método CONNECT (proxy)
            if data_str.startswith('CONNECT'):
                match = re.match(r'CONNECT\s+([^\s:]+):?(\d+)?\s+HTTP', data_str)
                if match:
                    return 'CONNECT', match.group(1), match.group(2) or '443'
            
            # Método HTTP normal (GET, POST, etc) con payload
            if any(data_str.startswith(method) for method in ['GET', 'POST', 'PUT', 'HEAD', 'DELETE', 'OPTIONS']):
                # Extraer Host del header
                host_match = re.search(r'Host:\s*([^\r\n]+)', data_str, re.IGNORECASE)
                if host_match:
                    host = host_match.group(1).strip()
                    return 'HTTP', host, None
                    
            # WebSocket upgrade
            if 'Upgrade: websocket' in data_str or 'upgrade: websocket' in data_str:
                host_match = re.search(r'Host:\s*([^\r\n]+)', data_str, re.IGNORECASE)
                if host_match:
                    host = host_match.group(1).strip()
                    return 'WEBSOCKET', host, None
                    
        except Exception as e:
            self.log(f"Error parsing request: {e}")
            
        return None, None, None
    
    def handle_client(self, client_socket, client_address):
        """Manejar conexión del cliente con soporte para payloads"""
        ssl_socket = None
        backend_socket = None
        
        try:
            # Envolver socket con SSL
            context = self.create_ssl_context()
            ssl_socket = context.wrap_socket(client_socket, server_side=True)
            
            self.log(f"Nueva conexión SSL desde {client_address[0]}:{client_address[1]}")
            
            # Leer primer paquete del cliente
            first_data = ssl_socket.recv(self.buffer_size)
            
            if not first_data:
                self.log("Conexión cerrada sin datos")
                return
            
            # Detectar tipo de request
            request_type, host, port = self.parse_http_request(first_data)
            
            if request_type:
                self.log(f"Request tipo: {request_type} | Host: {host}")
                
                # Para CONNECT, enviar respuesta 200 OK
                if request_type == 'CONNECT':
                    ssl_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    self.log("Respuesta CONNECT 200 OK enviada")
                    
                # Para HTTP/WebSocket con payload, enviar respuesta exitosa
                elif request_type in ['HTTP', 'WEBSOCKET']:
                    # Enviar respuesta HTTP 200 OK
                    response = b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n'
                    ssl_socket.sendall(response)
                    self.log(f"Respuesta {request_type} 200 OK enviada")
            
            # Conectar al backend SSH
            backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_socket.settimeout(10)
            backend_socket.connect((self.backend_host, self.backend_port))
            self.log(f"Conectado al backend {self.backend_host}:{self.backend_port}")
            
            # Si no es CONNECT, enviar los datos iniciales al backend
            if request_type != 'CONNECT':
                # Para HTTP/WebSocket, NO enviamos el payload HTTP al SSH
                # Solo hacemos el túnel transparente
                pass
            
            # Iniciar túnel bidireccional
            self.tunnel_traffic(ssl_socket, backend_socket)
            
        except ssl.SSLError as e:
            self.log(f"Error SSL: {e}")
        except socket.timeout:
            self.log("Timeout en conexión")
        except Exception as e:
            self.log(f"Error manejando cliente: {e}")
        finally:
            if ssl_socket:
                try:
                    ssl_socket.close()
                except:
                    pass
            if backend_socket:
                try:
                    backend_socket.close()
                except:
                    pass
            self.log(f"Conexión cerrada: {client_address[0]}:{client_address[1]}")
    
    def tunnel_traffic(self, client_sock, backend_sock):
        """Túnel bidireccional de tráfico"""
        client_sock.setblocking(False)
        backend_sock.setblocking(False)
        
        while True:
            try:
                readable, _, exceptional = select.select(
                    [client_sock, backend_sock], [], 
                    [client_sock, backend_sock], 
                    60.0
                )
                
                if exceptional:
                    break
                
                if not readable:
                    # Timeout - mantener conexión viva
                    continue
                
                # Cliente -> Backend
                if client_sock in readable:
                    data = client_sock.recv(self.buffer_size)
                    if not data:
                        break
                    backend_sock.sendall(data)
                
                # Backend -> Cliente
                if backend_sock in readable:
                    data = backend_sock.recv(self.buffer_size)
                    if not data:
                        break
                    client_sock.sendall(data)
                    
            except (ssl.SSLError, socket.error, BrokenPipeError) as e:
                self.log(f"Error en túnel: {e}")
                break
            except Exception as e:
                self.log(f"Error inesperado: {e}")
                break
    
    def start(self):
        """Iniciar servidor SSL"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind(('0.0.0.0', self.listen_port))
            server_socket.listen(100)
            self.log(f"SSL Proxy escuchando en puerto {self.listen_port}")
            self.log(f"Backend: {self.backend_host}:{self.backend_port}")
            self.log("Soporta: HTTP payloads, CONNECT, WebSocket, Remote Payloads")
            
            while True:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
        except KeyboardInterrupt:
            self.log("Deteniendo servidor...")
        except Exception as e:
            self.log(f"Error en servidor: {e}")
        finally:
            server_socket.close()

if __name__ == '__main__':
    if len(sys.argv) < 6:
        print("Uso: ssl-proxy.py <puerto_listen> <backend_host> <backend_port> <cert_file> <key_file>")
        sys.exit(1)
    
    listen_port = int(sys.argv[1])
    backend_host = sys.argv[2]
    backend_port = int(sys.argv[3])
    cert_file = sys.argv[4]
    key_file = sys.argv[5]
    
    proxy = SSLProxyServer(listen_port, backend_host, backend_port, cert_file, key_file)
    proxy.start()
SSLPROXY

chmod +x /etc/ssl-proxy/ssl-proxy.py

# ====================
# GENERAR CERTIFICADOS SSL AUTOFIRMADOS
# ====================
echo "Generando certificados SSL..."

openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=US/ST=State/L=City/O=MSY VPN/CN=msyvpn.online" \
    -keyout /etc/ssl-proxy/ssl-proxy.key \
    -out /etc/ssl-proxy/ssl-proxy.crt

chmod 600 /etc/ssl-proxy/ssl-proxy.key
chmod 644 /etc/ssl-proxy/ssl-proxy.crt

echo "✓ Certificados SSL generados"

# ====================
# CREAR SERVICIOS SYSTEMD PARA SSL PROXY
# ====================
echo "Creando servicios SSL proxy..."

# Puerto 443 -> Dropbear 143
cat > /etc/systemd/system/ssl-proxy-443.service <<'SSLSVC443'
[Unit]
Description=SSL Proxy Puerto 443 -> Dropbear 143
After=network.target dropbear-legacy.service
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/ssl-proxy
ExecStart=/usr/bin/python3 /etc/ssl-proxy/ssl-proxy.py 443 127.0.0.1 143 /etc/ssl-proxy/ssl-proxy.crt /etc/ssl-proxy/ssl-proxy.key
Restart=always
RestartSec=3
StandardOutput=append:/var/log/ssl-proxy/443.log
StandardError=append:/var/log/ssl-proxy/443.log

[Install]
WantedBy=multi-user.target
SSLSVC443

# Puerto 444 -> Dropbear 90
cat > /etc/systemd/system/ssl-proxy-444.service <<'SSLSVC444'
[Unit]
Description=SSL Proxy Puerto 444 -> Dropbear 90
After=network.target dropbear.service
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/ssl-proxy
ExecStart=/usr/bin/python3 /etc/ssl-proxy/ssl-proxy.py 444 127.0.0.1 90 /etc/ssl-proxy/ssl-proxy.crt /etc/ssl-proxy/ssl-proxy.key
Restart=always
RestartSec=3
StandardOutput=append:/var/log/ssl-proxy/444.log
StandardError=append:/var/log/ssl-proxy/444.log

[Install]
WantedBy=multi-user.target
SSLSVC444

# Puerto 777 -> Dropbear 143
cat > /etc/systemd/system/ssl-proxy-777.service <<'SSLSVC777'
[Unit]
Description=SSL Proxy Puerto 777 -> Dropbear 143
After=network.target dropbear-legacy.service
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/ssl-proxy
ExecStart=/usr/bin/python3 /etc/ssl-proxy/ssl-proxy.py 777 127.0.0.1 143 /etc/ssl-proxy/ssl-proxy.crt /etc/ssl-proxy/ssl-proxy.key
Restart=always
RestartSec=3
StandardOutput=append:/var/log/ssl-proxy/777.log
StandardError=append:/var/log/ssl-proxy/777.log

[Install]
WantedBy=multi-user.target
SSLSVC777

# Detener y deshabilitar Stunnel (será reemplazado por nuestro proxy)
systemctl stop stunnel4 2>/dev/null
systemctl disable stunnel4 2>/dev/null

# Habilitar e iniciar servicios SSL proxy
systemctl daemon-reload
systemctl enable ssl-proxy-443
systemctl enable ssl-proxy-444
systemctl enable ssl-proxy-777

systemctl start ssl-proxy-443
systemctl start ssl-proxy-444
systemctl start ssl-proxy-777

echo "✓ SSL Proxies iniciados en puertos 443, 444, 777"

# ====================
# SQUID PROXY (PUERTOS 3128, 8888)
# ====================
echo "Configurando Squid..."

cat > /etc/squid/squid.conf <<'SQUIDCONF'
http_port 3128
http_port 8888

acl all src 0.0.0.0/0
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
http_access allow all

forwarded_for delete
via off
follow_x_forwarded_for deny all
request_header_access X-Forwarded-For deny all

cache deny all
SQUIDCONF

systemctl enable squid
systemctl restart squid

# ====================
# PROXY PYTHON MULTI-MÉTODO (PUERTOS 80, 8080, 8880)
# ====================
echo "Creando proxy Python multi-método..."

cat > /etc/proxy-python/proxy.py <<'PYTHONPROXY'
#!/usr/bin/env python3
"""
Proxy Python Multi-Método con auto-detección
Soporta: HTTP, CONNECT, WebSocket
"""

import socket
import select
import threading
import re
from datetime import datetime

class MultiMethodProxy:
    def __init__(self, listen_port, backend_host, backend_port):
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.buffer_size = 8192
        
    def log(self, msg):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)
        
    def detect_method(self, data):
        """Auto-detectar método de conexión"""
        try:
            data_str = data.decode('utf-8', errors='ignore')
            
            if data_str.startswith('CONNECT'):
                return 'CONNECT'
            elif 'Upgrade: websocket' in data_str or 'upgrade: websocket' in data_str:
                return 'WEBSOCKET'
            elif any(data_str.startswith(m) for m in ['GET', 'POST', 'HEAD', 'PUT']):
                return 'HTTP'
        except:
            pass
        return 'UNKNOWN'
    
    def handle_client(self, client_sock, addr):
        backend_sock = None
        try:
            # Leer request inicial
            first_data = client_sock.recv(self.buffer_size)
            if not first_data:
                return
                
            method = self.detect_method(first_data)
            self.log(f"{addr[0]}:{addr[1]} -> Método: {method}")
            
            # Conectar al backend
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_sock.connect((self.backend_host, self.backend_port))
            
            # Responder según método
            if method == 'CONNECT':
                client_sock.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            elif method in ['HTTP', 'WEBSOCKET']:
                client_sock.sendall(b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n')
            
            # Túnel bidireccional
            self.tunnel(client_sock, backend_sock)
            
        except Exception as e:
            self.log(f"Error: {e}")
        finally:
            if backend_sock:
                backend_sock.close()
            client_sock.close()
    
    def tunnel(self, client, backend):
        """Túnel de datos bidireccional"""
        client.setblocking(False)
        backend.setblocking(False)
        
        while True:
            try:
                r, _, x = select.select([client, backend], [], [client, backend], 60)
                
                if x:
                    break
                    
                if client in r:
                    data = client.recv(self.buffer_size)
                    if not data:
                        break
                    backend.sendall(data)
                    
                if backend in r:
                    data = backend.recv(self.buffer_size)
                    if not data:
                        break
                    client.sendall(data)
                    
            except:
                break
    
    def start(self):
        """Iniciar proxy"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.listen_port))
        sock.listen(100)
        
        self.log(f"Proxy escuchando en :{self.listen_port} -> {self.backend_host}:{self.backend_port}")
        
        while True:
            client, addr = sock.accept()
            threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 4:
        print("Uso: proxy.py <puerto_listen> <backend_host> <backend_port>")
        sys.exit(1)
        
    proxy = MultiMethodProxy(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]))
    proxy.start()
PYTHONPROXY

chmod +x /etc/proxy-python/proxy.py

# Crear servicios para proxies Python
for port in 80 8080 8880; do
    cat > /etc/systemd/system/proxy-python-${port}.service <<PYPROXYSVC
[Unit]
Description=Python Proxy Puerto ${port}
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/proxy-python/proxy.py ${port} 127.0.0.1 143
Restart=always
StandardOutput=append:/var/log/proxy-python/${port}.log
StandardError=append:/var/log/proxy-python/${port}.log

[Install]
WantedBy=multi-user.target
PYPROXYSVC

    systemctl enable proxy-python-${port}
    systemctl start proxy-python-${port}
done

echo "✓ Proxies Python iniciados en puertos 80, 8080, 8880"

# ====================
# BADVPN UDPGW
# ====================
echo "Configurando BadVPN UDPGW..."

cd /usr/src
if [ ! -d badvpn ]; then
    git clone https://github.com/ambrop72/badvpn.git
fi

cd badvpn
mkdir -p build
cd build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)
cp udpgw/badvpn-udpgw /usr/local/bin/

cat > /etc/systemd/system/badvpn-udpgw.service <<'BADVPNSVC'
[Unit]
Description=BadVPN UDPGW
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always

[Install]
WantedBy=multi-user.target
BADVPNSVC

systemctl daemon-reload
systemctl enable badvpn-udpgw
systemctl start badvpn-udpgw

cd /root

# ====================
# CREAR FUNCIONES Y MENÚ PRINCIPAL
# ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

# Funciones del sistema VPN

crear_usuario() {
    echo "CREAR NUEVO USUARIO"
    read -p "Nombre de usuario: " username
    read -p "Contraseña: " password
    read -p "Días de validez (0 = ilimitado): " days
    
    if id "$username" &>/dev/null; then
        echo "❌ El usuario ya existe"
        return 1
    fi
    
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    
    if [ "$days" -gt 0 ]; then
        exp_date=$(date -d "+$days days" +%Y-%m-%d)
        chage -E $(date -d "+$days days" +%Y-%m-%d) "$username"
    else
        exp_date="Ilimitado"
    fi
    
    cat > /etc/ssh-vpn/users/$username.txt <<EOF
Usuario: $username
Contraseña: $password
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: $exp_date
Estado: Activo
EOF
    
    echo "✓ Usuario creado exitosamente"
}

listar_usuarios() {
    echo "USUARIOS REGISTRADOS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    for userfile in /etc/ssh-vpn/users/*.txt; do
        if [ -f "$userfile" ]; then
            cat "$userfile"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        fi
    done
}

usuarios_conectados() {
    echo "USUARIOS CONECTADOS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Contar IPs únicas
    total=$(ss -tnp | grep -E ':(22|90|143|443|444|777)' | awk '{print $5}' | cut -d: -f1 | sort -u | wc -l)
    echo "Total de IPs únicas conectadas: $total"
    echo ""
    
    ss -tnp | grep -E ':(22|90|143|443|444|777)' | awk '{print $5}' | cut -d: -f1 | sort -u
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

eliminar_usuario() {
    read -p "Usuario a eliminar: " username
    
    if ! id "$username" &>/dev/null; then
        echo "❌ El usuario no existe"
        return 1
    fi
    
    # Matar sesiones activas
    pkill -u "$username"
    
    # Eliminar usuario
    userdel -r "$username" 2>/dev/null
    rm -f /etc/ssh-vpn/users/$username.txt
    
    echo "✓ Usuario eliminado"
}

restart_proxies() {
    echo "Reiniciando proxies Python..."
    systemctl restart proxy-python-80
    systemctl restart proxy-python-8080
    systemctl restart proxy-python-8880
    echo "✓ Proxies reiniciados"
}

restart_ssl_proxies() {
    echo "Reiniciando SSL proxies..."
    systemctl restart ssl-proxy-443
    systemctl restart ssl-proxy-444
    systemctl restart ssl-proxy-777
    echo "✓ SSL Proxies reiniciados"
}

restart_all_services() {
    echo "Reiniciando todos los servicios..."
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart dropbear-legacy
    systemctl restart ssl-proxy-443
    systemctl restart ssl-proxy-444
    systemctl restart ssl-proxy-777
    systemctl restart proxy-python-80
    systemctl restart proxy-python-8080
    systemctl restart proxy-python-8880
    systemctl restart squid
    systemctl restart badvpn-udpgw
    echo "✓ Todos los servicios reiniciados"
}

test_ssl_connection() {
    echo "PRUEBA DE CONEXIÓN SSL"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    read -p "Puerto SSL a probar (443/444/777): " ssl_port
    
    echo "Probando conexión SSL en puerto $ssl_port..."
    timeout 3 openssl s_client -connect 127.0.0.1:$ssl_port -quiet </dev/null 2>&1 | head -5
    
    echo ""
    echo "Log del proxy:"
    tail -20 /var/log/ssl-proxy/${ssl_port}.log
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

monitor_ssl_logs() {
    echo "LOGS EN TIEMPO REAL - SSL PROXY"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    read -p "Puerto SSL (443/444/777): " ssl_port
    
    echo "Monitoreando puerto $ssl_port (Ctrl+C para salir)..."
    tail -f /var/log/ssl-proxy/${ssl_port}.log
}
FUNCEOF

chmod +x /root/ssh-vpn-functions.sh

# Crear script principal con menú
cat > /root/vpn-installer.sh <<'MAINSCRIPT'
#!/bin/bash

source /root/ssh-vpn-functions.sh

GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

menu_principal() {
    while true; do
        clear
        echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC}   ${GREEN}MSY VPN SCRIPT - SSL MEJORADO${NC}    ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}1)${NC} Crear usuario VPN"
        echo -e "${YELLOW}2)${NC} Listar usuarios"
        echo -e "${YELLOW}3)${NC} Usuarios conectados"
        echo -e "${YELLOW}4)${NC} Eliminar usuario"
        echo -e "${YELLOW}5)${NC} Monitor conexiones (tiempo real)"
        echo -e "${YELLOW}6)${NC} Test SSL (diagnóstico)"
        echo -e "${YELLOW}7)${NC} Ver logs SSL"
        echo -e "${YELLOW}8)${NC} Información del sistema"
        echo -e "${YELLOW}9)${NC} Configurar Hysteria UDP"
        echo -e "${YELLOW}10)${NC} Estado servicios"
        echo -e "${YELLOW}11)${NC} Reiniciar servicios"
        echo -e "${YELLOW}12)${NC} Ver versiones Dropbear"
        echo -e "${YELLOW}0)${NC} Salir"
        echo ""
        read -p "Seleccione opción: " option
        
        case $option in
            1)
                clear
                crear_usuario
                read -p "ENTER para continuar..."
                ;;
            2)
                clear
                listar_usuarios
                read -p "ENTER para continuar..."
                ;;
            3)
                clear
                usuarios_conectados
                read -p "ENTER para continuar..."
                ;;
            4)
                clear
                eliminar_usuario
                read -p "ENTER para continuar..."
                ;;
            5)
                clear
                echo "Monitoreando conexiones (Ctrl+C para salir)..."
                watch -n 2 "ss -tnp | grep -E ':(22|90|143|443|444|777)' | awk '{print \$5}' | cut -d: -f1 | sort -u"
                ;;
            6)
                clear
                test_ssl_connection
                read -p "ENTER para continuar..."
                ;;
            7)
                clear
                monitor_ssl_logs
                ;;
            8)
                clear
                echo -e "${CYAN}INFORMACIÓN DEL SISTEMA${NC}"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${YELLOW}IP:${NC} ${GREEN}$(curl -s ifconfig.me)${NC}"
                echo -e "${YELLOW}Hostname:${NC} $(hostname)"
                echo -e "${YELLOW}OS:${NC} $(lsb_release -d | cut -f2)"
                echo -e "${YELLOW}Kernel:${NC} $(uname -r)"
                echo -e "${YELLOW}Uptime:${NC} $(uptime -p)"
                echo -e "${YELLOW}RAM:${NC} $(free -h | grep Mem | awk '{print $3"/"$2}')"
                echo -e "${YELLOW}Swap:${NC} $(free -h | grep Swap | awk '{print $3"/"$2}')"
                echo ""
                echo -e "${YELLOW}Puertos abiertos:${NC}"
                ss -tuln | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -n | uniq
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                read -p "ENTER para continuar..."
                ;;
            9)
                clear
                echo "CONFIGURAR HYSTERIA UDP"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Próximamente..."
                read -p "ENTER..."
                ;;
            10)
                clear
                echo -e "${CYAN}ESTADO DE SERVICIOS${NC}"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                systemctl is-active --quiet ssh && echo -e "${GREEN}✓ OpenSSH: Activo${NC} (puerto 22)" || echo -e "${RED}✗ OpenSSH: Inactivo${NC}"
                systemctl is-active --quiet dropbear && echo -e "${GREEN}✓ Dropbear 2020: Activo${NC} (puerto 90)" || echo -e "${RED}✗ Dropbear 2020: Inactivo${NC}"
                systemctl is-active --quiet dropbear-legacy && echo -e "${GREEN}✓ Dropbear 2016: Activo${NC} (puerto 143)" || echo -e "${RED}✗ Dropbear 2016: Inactivo${NC}"
                systemctl is-active --quiet ssl-proxy-443 && echo -e "${GREEN}✓ SSL Proxy 443: Activo${NC}" || echo -e "${RED}✗ SSL Proxy 443: Inactivo${NC}"
                systemctl is-active --quiet ssl-proxy-444 && echo -e "${GREEN}✓ SSL Proxy 444: Activo${NC}" || echo -e "${RED}✗ SSL Proxy 444: Inactivo${NC}"
                systemctl is-active --quiet ssl-proxy-777 && echo -e "${GREEN}✓ SSL Proxy 777: Activo${NC}" || echo -e "${RED}✗ SSL Proxy 777: Inactivo${NC}"
                systemctl is-active --quiet squid && echo -e "${GREEN}✓ Squid: Activo${NC} (puertos 3128, 8888)" || echo -e "${RED}✗ Squid: Inactivo${NC}"
                systemctl is-active --quiet badvpn-udpgw && echo -e "${GREEN}✓ BadVPN: Activo${NC} (puerto 7300)" || echo -e "${RED}✗ BadVPN: Inactivo${NC}"
                systemctl is-active --quiet proxy-python-80 && echo -e "${GREEN}✓ Proxy 80: Activo${NC}" || echo -e "${RED}✗ Proxy 80: Inactivo${NC}"
                systemctl is-active --quiet proxy-python-8080 && echo -e "${GREEN}✓ Proxy 8080: Activo${NC}" || echo -e "${RED}✗ Proxy 8080: Inactivo${NC}"
                systemctl is-active --quiet proxy-python-8880 && echo -e "${GREEN}✓ Proxy 8880: Activo${NC}" || echo -e "${RED}✗ Proxy 8880: Inactivo${NC}"
                echo ""
                echo -e "${YELLOW}Swap:${NC} ${CYAN}$(free -h | grep Swap | awk '{print $2}')${NC}"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                read -p "ENTER para continuar..."
                ;;
            11)
                clear
                echo "REINICIAR SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Reiniciar proxies HTTP"
                echo "2) Reiniciar SSL proxies"
                echo "3) Reiniciar OpenSSH"
                echo "4) Reiniciar Dropbear"
                echo "5) Reiniciar TODO"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "ENTER..." ;;
                    2) restart_ssl_proxies; echo ""; read -p "ENTER..." ;;
                    3) systemctl restart ssh && echo "✓ OpenSSH reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    4) systemctl restart dropbear && echo "✓ Dropbear (90)" || echo "✗ Error"
                       systemctl restart dropbear-legacy 2>/dev/null && echo "✓ Dropbear Legacy (143)" || true
                       read -p "ENTER..." ;;
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
                    echo "  No instalado"
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
${CYAN}╔══════════════════════════════════════════════════╗${NC}
${CYAN}║${NC}   ${GREEN}✓ INSTALACIÓN COMPLETADA - v10 SSL MEJORADO${NC}  ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════════════════╝${NC}

${YELLOW}IP:${NC} ${CYAN}$IP${NC}

${GREEN}SERVICIOS SSH:${NC}
${GREEN}✓${NC} OpenSSH:           puerto 22
${GREEN}✓${NC} Dropbear 2020:     puerto 90
${GREEN}✓${NC} Dropbear 2016:     puerto 143 (SSH-2.0-ByJuanitoProSniff)

${GREEN}SSL/TLS MEJORADO (Soporta payloads y proxies):${NC}
${GREEN}✓${NC} SSL Proxy 443:     443→143 (Acepta HTTP payloads, CONNECT, WebSocket)
${GREEN}✓${NC} SSL Proxy 444:     444→90  (Acepta HTTP payloads, CONNECT, WebSocket)
${GREEN}✓${NC} SSL Proxy 777:     777→143 (Acepta HTTP payloads, CONNECT, WebSocket)

${GREEN}PROXIES HTTP:${NC}
${GREEN}✓${NC} Python Proxy:      80, 8080, 8880 (→ puerto 143)
${GREEN}✓${NC} Squid:             3128, 8888

${GREEN}OTROS:${NC}
${GREEN}✓${NC} BadVPN UDPGW:      7300
${GREEN}✓${NC} UFW:               Desactivado
${GREEN}✓${NC} Swap:              2GB activado

${CYAN}MEJORAS SSL/TLS v10:${NC}
${GREEN}✓${NC} Soporte para HTTP payloads (GET / HTTP/1.1[crlf]Host: ...)
${GREEN}✓${NC} Soporte para método CONNECT con proxy
${GREEN}✓${NC} Soporte para WebSocket upgrade
${GREEN}✓${NC} Soporte para SSL + Remote Payload
${GREEN}✓${NC} Compatible con HTTP Custom y apps similares
${GREEN}✓${NC} TLS 1.0, 1.1, 1.2, 1.3 soportados
${GREEN}✓${NC} Cifrados optimizados y compatibles

${YELLOW}CREDENCIALES:${NC}
${CYAN}Usuario:${NC} $USER_VPN
${CYAN}Password:${NC} $PASS_VPN

${YELLOW}PANEL:${NC} ejecutar ${CYAN}vpn-panel${NC} (auto al conectar)

${CYAN}CONFIGURACIÓN HTTP CUSTOM:${NC}
${YELLOW}Método:${NC} SSL/TLS
${YELLOW}Puerto:${NC} 443, 444 o 777
${YELLOW}SNI:${NC} tu-dominio.com
${YELLOW}Payload:${NC} GET / HTTP/1.1[crlf]Host: tu-dominio.com[crlf]Upgrade: websocket[crlf][crlf]
${YELLOW}Proxy:${NC} Opcional (ads.ruangguru.com u otro)

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
"

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v10 - SSL/TLS MEJORADO

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear 2020: 90
- Dropbear 2016: 143 (SSH-2.0-ByJuanitoProSniff)
- SSL Proxy 443: 443→143 (Soporta payloads, CONNECT, WebSocket)
- SSL Proxy 444: 444→90  (Soporta payloads, CONNECT, WebSocket)
- SSL Proxy 777: 777→143 (Soporta payloads, CONNECT, WebSocket)
- Python Proxy: 80, 8080, 8880 (→143)
- Squid: 3128, 8888
- BadVPN: 7300

USUARIO:
$USER_VPN / $PASS_VPN

SWAP: 2GB activado

SSL/TLS MEJORADO:
- Acepta HTTP payloads personalizados
- Acepta método CONNECT con proxy intermedio
- Acepta WebSocket upgrade
- Acepta SSL + Remote Payload
- Compatible con HTTP Custom
- TLS 1.0/1.1/1.2/1.3

CONFIGURACIÓN HTTP CUSTOM:
Método: SSL/TLS
Puerto: 443, 444 o 777
SNI: tu-dominio.com
Payload: GET / HTTP/1.1[crlf]Host: tu-dominio.com[crlf]Upgrade: websocket[crlf][crlf]
Proxy: Opcional

PANEL: vpn-panel (automático al login)
INFOEOF

echo "Información guardada en /root/vpn-info.txt"
echo ""
read -p "¿Deseas abrir el panel ahora? (s/n): " open_menu
if [[ $open_menu == "s" || $open_menu == "S" ]]; then
    bash /root/vpn-installer.sh
fi
