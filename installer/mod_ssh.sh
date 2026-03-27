#!/bin/bash
# mod_ssh.sh - MSY VPN
# Protocolos SSH: OpenSSH puerto 22 + Dropbear 2016.74 puerto 143

# ====================
# OPENSSH (PUERTO 22)
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
EOF

systemctl enable ssh >/dev/null 2>&1
systemctl restart ssh
echo "✓ OpenSSH activo en puerto 22"

# ====================
# COMPILAR DROPBEAR 2016.74 - PUERTO 143
# ====================
echo "=========================================="
echo "Compilando Dropbear 2016.74 desde fuente..."
echo "Arquitectura: $ARCH"
echo "=========================================="
cd /usr/src

if [ ! -f dropbear-2016.74.tar.bz2 ]; then
    echo "Descargando Dropbear 2016.74..."
    wget -q https://github.com/juanitoprosniff/script_msyvpn/raw/refs/heads/main/installer/dropbear-2016.74.tar.bz2
fi

echo "Extrayendo..."
rm -rf dropbear-2016.74 2>/dev/null
tar xjf dropbear-2016.74.tar.bz2
cd dropbear-2016.74

# Modificar identificador SSH
if [ -f sysoptions.h ]; then
    sed -i 's|^#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' sysoptions.h 2>/dev/null || true
elif [ -f default_options.h ]; then
    sed -i 's/#define LOCAL_IDENT "SSH-2.0-dropbear_" DROPBEAR_VERSION/#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"/' default_options.h 2>/dev/null || true
fi

./configure --prefix=/opt/dropbear-2016 \
    --disable-zlib \
    --disable-wtmp \
    --disable-lastlog \
    >/dev/null 2>&1

echo "Compilando... (2-3 minutos)"
make -j$(nproc) PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1
make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1

if [ ! -f /opt/dropbear-2016/sbin/dropbear ]; then
    echo "⚠ ERROR: No se pudo compilar Dropbear 2016"
else
    echo "✓ Dropbear 2016.74 compilado"

    # Generar llaves
    if [ ! -f /etc/dropbear-legacy/dropbear_rsa_host_key ]; then
        /opt/dropbear-2016/bin/dropbearkey -t rsa -f /etc/dropbear-legacy/dropbear_rsa_host_key -s 2048 >/dev/null 2>&1
    fi
    if [ ! -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ]; then
        /opt/dropbear-2016/bin/dropbearkey -t ecdsa -f /etc/dropbear-legacy/dropbear_ecdsa_host_key >/dev/null 2>&1
    fi

    # Banner
    cat > /etc/dropbear-legacy/banner.txt <<'EOF'
t.me/FREEINTERNETVPNMSY
EOF

    # Servicio systemd
    cat > /etc/systemd/system/dropbear-legacy.service <<'DBEOF'
[Unit]
Description=Dropbear SSH Legacy 2016.74 - Puerto 143
After=network.target

[Service]
Type=simple
ExecStart=/opt/dropbear-2016/sbin/dropbear -F -E -p 143 \
    -r /etc/dropbear-legacy/dropbear_rsa_host_key \
    -r /etc/dropbear-legacy/dropbear_ecdsa_host_key \
    -b /etc/dropbear-legacy/banner.txt \
    -K 60 -I 300
Restart=always
RestartSec=3
KillMode=process
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
DBEOF

    systemctl daemon-reload
    systemctl enable dropbear-legacy >/dev/null 2>&1
    systemctl start dropbear-legacy
    sleep 2
    echo "✓ Dropbear 2016 activo en puerto 143"
fi

cd /root

# ====================
# USUARIO INICIAL
# ====================
echo "Creando usuario VPN inicial..."
USER_VPN="vpnuser"
PASS_VPN="msy$(openssl rand -hex 4)"

if id "$USER_VPN" &>/dev/null; then
    userdel -r "$USER_VPN" 2>/dev/null
fi

useradd -m -s /bin/bash "$USER_VPN"
echo "$USER_VPN:$PASS_VPN" | chpasswd

cat > /etc/ssh-vpn/users/$USER_VPN.txt <<USEREOF
Usuario: $USER_VPN
Contraseña: $PASS_VPN
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: Ilimitado
Estado: Activo
USEREOF

echo "✓ Usuario inicial: $USER_VPN / $PASS_VPN"

# Exportar para uso posterior (resumen final)
export USER_VPN PASS_VPN
