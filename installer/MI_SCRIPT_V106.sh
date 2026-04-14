#!/bin/bash
# Script MSY By JuanitoProSniff
# Canal: t.me/FREEINTERNETVPNMSY
# Version: 106 - Correcciones completas

clear
echo "=========================================="
echo "   Instalando Script MSY VPN v106"
echo "=========================================="
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

# Detectar OS antes de descargar
OS_VER=$(lsb_release -rs 2>/dev/null \
    || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null \
    || echo "0")
OS_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
echo "Sistema detectado: Ubuntu $OS_VER"

# Verificar Ubuntu 20+ (soporte garantizado)
if [ "$OS_MAJOR" -lt 20 ] 2>/dev/null; then
    echo -e "${yellow}⚠ Ubuntu $OS_VER detectado. El script está optimizado para Ubuntu 20/22/24/25.${off}"
    echo -e "${yellow}  Ubuntu 18 puede funcionar pero con funciones limitadas.${off}"
    read -p "¿Continuar de todas formas? (s/n): " continuar
    [[ "$continuar" != "s" && "$continuar" != "S" ]] && exit 1
fi

# Instalar lsb-release si falta (Ubuntu 24/25 minimal)
if ! command -v lsb_release >/dev/null 2>&1; then
    apt-get install -y -q lsb-release 2>/dev/null
fi

# URL base del repositorio
BASE_URL="https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer"

# Descargar módulos
echo "Descargando módulos v106..."
for modulo in mod_system.sh mod_ssh.sh mod_ssl.sh mod_proxies.sh mod_tools.sh mod_menu.sh; do
    wget -q -O /tmp/$modulo "$BASE_URL/$modulo"
    if [ ! -f /tmp/$modulo ]; then
        echo "ERROR: No se pudo descargar $modulo"
        exit 1
    fi
    chmod +x /tmp/$modulo
done
echo "✓ Módulos descargados"

# Ejecutar módulos en orden
echo ""
echo "--- SISTEMA ---"
source /tmp/mod_system.sh

echo ""
echo "--- SSH ---"
source /tmp/mod_ssh.sh

echo ""
echo "--- SSL/STUNNEL + SNI + REMOTE PROXY ---"
source /tmp/mod_ssl.sh

echo ""
echo "--- PROXIES ---"
source /tmp/mod_proxies.sh

echo ""
echo "--- HERRAMIENTAS ---"
source /tmp/mod_tools.sh

echo ""
echo "--- MENÚ ---"
source /tmp/mod_menu.sh

# Limpiar módulos temporales
rm -f /tmp/mod_system.sh /tmp/mod_ssh.sh /tmp/mod_ssl.sh \
      /tmp/mod_proxies.sh /tmp/mod_tools.sh /tmp/mod_menu.sh \
      /tmp/stunnel_extra_functions.sh
