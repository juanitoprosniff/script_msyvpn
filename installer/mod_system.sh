#!/bin/bash
# mod_system.sh - MSY VPN
# Sistema: dependencias, swap, optimizaciones, usuario inicial

# Detener servicios previos
pkill -9 -f "proxy-python" 2>/dev/null
pkill -9 -f "badvpn-udpgw" 2>/dev/null
systemctl stop dropbear-legacy 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop ssh 2>/dev/null

# Detectar arquitectura
ARCH=$(uname -m)
OS_VER=$(lsb_release -rs 2>/dev/null || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null || echo "unknown")
echo "Sistema detectado: Ubuntu $OS_VER | Arquitectura: $ARCH"

# Actualizar sistema
echo "Actualizando sistema..."
apt-get update -y -q
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -q

# Instalar dependencias
echo "Instalando dependencias..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    python3 openssh-server stunnel4 screen lsof curl wget nano \
    net-tools cmake build-essential git zlib1g-dev

# Crear directorios
mkdir -p /etc/proxy-python
mkdir -p /etc/ssh-vpn/users
mkdir -p /etc/dropbear-legacy
mkdir -p /opt/dropbear-2016

# ====================
# CONFIGURAR SWAP 2GB
# ====================
echo "Configurando Swap de 2GB..."

if [ ! -f /swapfile ]; then
    dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile

    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi

    sysctl -w vm.swappiness=11 >/dev/null 2>&1
    if ! grep -q 'vm.swappiness' /etc/sysctl.conf; then
        echo "vm.swappiness=11" >> /etc/sysctl.conf
    fi
    echo "✓ Swap de 2GB configurado"
else
    echo "✓ Swap ya existe"
fi

# ====================
# FIREWALL - DESACTIVADO
# ====================
ufw --force disable >/dev/null 2>&1
echo "✓ UFW desactivado"

# ====================
# OPTIMIZACIONES SISTEMA
# ====================
for param in "net.ipv4.ip_forward" "net.ipv4.tcp_keepalive_time" "net.ipv4.tcp_fin_timeout" \
             "net.ipv4.tcp_tw_reuse" "net.core.rmem_max" "net.core.wmem_max" \
             "net.ipv4.tcp_congestion_control"; do
    grep -q "^${param}" /etc/sysctl.conf && \
        sed -i "s|^${param}.*|${param} = $(echo $param | grep -q 'ip_forward' && echo 1 || echo '')|" /etc/sysctl.conf 2>/dev/null || true
done

cat >> /etc/sysctl.conf <<'EOF'

# MSY VPN Optimizaciones
net.ipv4.ip_forward = 1
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl -p >/dev/null 2>&1
echo "✓ Optimizaciones de red aplicadas"
