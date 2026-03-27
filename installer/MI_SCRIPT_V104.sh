#!/bin/bash
# Script MSY By JuanitoProSniff
# Canal: t.me/FREEINTERNETVPNMSY
# Version: 104 - Minimalista

clear
echo "=========================================="
echo "   Instalando Script MSY VPN"
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

# URL base del repositorio
BASE_URL="https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer"

# Descargar módulos
echo "Descargando módulos..."
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
echo "--- SSL/STUNNEL ---"
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
rm -f /tmp/mod_system.sh /tmp/mod_ssh.sh /tmp/mod_ssl.sh /tmp/mod_proxies.sh /tmp/mod_tools.sh /tmp/mod_menu.sh
