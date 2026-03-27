#!/bin/bash
# mod_ssl.sh - MSY VPN
# SSL/TLS: Stunnel puertos 443, 444, 777

# ====================
# STUNNEL (PUERTOS 443, 444, 777)
# ====================
echo "Configurando Stunnel SSL..."

# Generar certificado
cat > /tmp/openssl-stunnel.cnf <<'SSLCONF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[dn]
C=US
ST=California
L=Los Angeles
O=MSY-VPN
CN=*

[v3_ca]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth

[alt_names]
DNS.1 = *
DNS.2 = *.msyvpn.com
DNS.3 = localhost
IP.1 = 127.0.0.1
SSLCONF

openssl req -new -x509 -days 3650 -nodes \
    -config /tmp/openssl-stunnel.cnf \
    -keyout /etc/stunnel/stunnel.key \
    -out /etc/stunnel/stunnel.crt >/dev/null 2>&1

cat /etc/stunnel/stunnel.crt /etc/stunnel/stunnel.key > /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.pem /etc/stunnel/stunnel.key
chmod 644 /etc/stunnel/stunnel.crt
rm -f /tmp/openssl-stunnel.cnf

cat > /etc/stunnel/stunnel.conf <<'EOF'
; STUNNEL SSL/TLS - MSY VPN

foreground = no
pid = /var/run/stunnel4/stunnel.pid
output = /dev/null

socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1

TIMEOUTclose = 1
TIMEOUTidle = 86400
TIMEOUTbusy = 300
TIMEOUTconnect = 30

sslVersion = all
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1
options = CIPHER_SERVER_PREFERENCE

ciphers = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384:HIGH:!aNULL:!eNULL:!EXPORT:!MD5:!RC4

[dropbear-ssl-443]
client = no
accept = 0.0.0.0:443
connect = 127.0.0.1:143
cert = /etc/stunnel/stunnel.pem
verify = 0
TIMEOUTidle = 86400

[openssh-ssl-444]
client = no
accept = 0.0.0.0:444
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
verify = 0
TIMEOUTidle = 86400

[dropbear-ssl-777]
client = no
accept = 0.0.0.0:777
connect = 127.0.0.1:143
cert = /etc/stunnel/stunnel.pem
verify = 0
TIMEOUTidle = 86400
EOF

echo "ENABLED=1" > /etc/default/stunnel4
echo 'FILES="/etc/stunnel/*.conf"' >> /etc/default/stunnel4

mkdir -p /var/run/stunnel4 /var/log/stunnel4
chown -R stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null || chown -R nobody:nogroup /var/run/stunnel4
chmod 755 /var/run/stunnel4

systemctl daemon-reload
systemctl enable stunnel4 >/dev/null 2>&1
systemctl restart stunnel4
sleep 2

if systemctl is-active --quiet stunnel4; then
    echo "✓ Stunnel activo (443, 444, 777)"
else
    echo "⚠ Stunnel con problemas - revisar configuración"
fi
