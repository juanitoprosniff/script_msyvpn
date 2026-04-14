#!/bin/bash
# mod_system.sh - MSY VPN v106
# Sistema: dependencias, swap, optimizaciones, usuario inicial
# FIXES v106:
#   - sysctl: evita duplicados en /etc/sysctl.conf (usaba append sin verificar)
#   - BBR: verifica si el kernel lo soporta (Ubuntu 20+ lo tiene, 18 no)
#   - fuser: agregar como dependencia obligatoria (faltaba en Ubuntu 24/25 minimal)
#   - socat: agregar como dependencia (requerido por wrappers Dropbear)
#   - OS_VER: detección robusta en Ubuntu 24/25 (lsb_release puede no estar)

# ============================================================
# DETENER SERVICIOS PREVIOS
# ============================================================
pkill -9 -f "proxy-python" 2>/dev/null
pkill -9 -f "badvpn-udpgw" 2>/dev/null
systemctl stop dropbear-legacy 2>/dev/null
systemctl stop stunnel4 2>/dev/null
systemctl stop ssh 2>/dev/null

# ============================================================
# DETECCIÓN DE ENTORNO ROBUSTA
# ============================================================
# lsb_release puede faltar en Ubuntu 24/25 minimal
if command -v lsb_release >/dev/null 2>&1; then
    OS_VER=$(lsb_release -rs 2>/dev/null)
else
    OS_VER=$(grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null \
          || grep -oP '(?<=VERSION_ID=)[^\s]+' /etc/os-release 2>/dev/null \
          || echo "0")
fi
OS_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
ARCH=$(uname -m)
KERNEL=$(uname -r)
echo "Sistema detectado: Ubuntu $OS_VER | Arquitectura: $ARCH | Kernel: $KERNEL"

# ============================================================
# ACTUALIZAR SISTEMA
# ============================================================
echo "Actualizando sistema..."
apt-get update -y -q
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -q

# ============================================================
# INSTALAR DEPENDENCIAS
# Notas:
#   - psmisc: incluye fuser/killall (falta en Ubuntu 24/25 minimal)
#   - socat: requerido por wrappers Dropbear (msy-wrap-*.sh)
#   - lsb-release: puede faltar en Ubuntu 24/25 minimal
# ============================================================
echo "Instalando dependencias..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    python3 openssh-server stunnel4 screen lsof curl wget nano \
    net-tools cmake build-essential git zlib1g-dev \
    socat psmisc lsb-release

echo "✓ Dependencias OK"

# ============================================================
# CREAR DIRECTORIOS
# ============================================================
mkdir -p /etc/proxy-python
mkdir -p /etc/ssh-vpn/users
mkdir -p /etc/dropbear-legacy
mkdir -p /opt/dropbear-2016
mkdir -p /opt/dropbear-bins

# ============================================================
# CONFIGURAR SWAP 2GB
# ============================================================
echo "Configurando Swap de 2GB..."

if [ ! -f /swapfile ]; then
    dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile

    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    echo "✓ Swap de 2GB configurado"
else
    echo "✓ Swap ya existe"
fi

# ============================================================
# FIREWALL - DESACTIVADO
# ============================================================
ufw --force disable >/dev/null 2>&1
echo "✓ UFW desactivado"

# ============================================================
# OPTIMIZACIONES DE RED
# FIX: verificar cada parámetro antes de agregar para evitar
# duplicados si el script se corre más de una vez.
# FIX: BBR solo si el kernel lo soporta (Ubuntu 18 kernel 4.x no lo tiene)
# ============================================================
echo "Aplicando optimizaciones de red..."

# Verificar soporte BBR
CONGESTION="cubic"
if modprobe tcp_bbr 2>/dev/null; then
    CONGESTION="bbr"
    echo "  BBR: disponible (kernel $KERNEL)"
else
    echo "  BBR: no disponible en kernel $KERNEL — usando cubic"
fi

# Función para setear parámetro sysctl sin duplicar
_sysctl_set() {
    local key="$1"
    local val="$2"
    # Eliminar líneas previas con esa clave (evitar duplicados)
    sed -i "/^${key}/d" /etc/sysctl.conf 2>/dev/null
    echo "${key} = ${val}" >> /etc/sysctl.conf
}

_sysctl_set "net.ipv4.ip_forward"            "1"
_sysctl_set "net.ipv4.tcp_keepalive_time"    "1200"
_sysctl_set "net.ipv4.tcp_keepalive_intvl"   "30"
_sysctl_set "net.ipv4.tcp_keepalive_probes"  "5"
_sysctl_set "net.ipv4.tcp_fin_timeout"       "30"
_sysctl_set "net.ipv4.tcp_tw_reuse"          "1"
_sysctl_set "net.core.rmem_max"              "134217728"
_sysctl_set "net.core.wmem_max"              "134217728"
_sysctl_set "net.ipv4.tcp_congestion_control" "$CONGESTION"
_sysctl_set "vm.swappiness"                  "11"

sysctl -p >/dev/null 2>&1
echo "✓ Optimizaciones de red aplicadas (congestion: $CONGESTION)"
