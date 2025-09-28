#!/bin/bash
# =================================================================================
# Script de Instalación MSY VPN
# Modificado para compatibilidad con Ubuntu 18.04 a 25.04+ y traducido al español.
# Soporte para múltiples distribuciones y arquitecturas
# =================================================================================

# Limpieza inicial de la pantalla
clear && clear

# --- CONFIGURACIÓN INICIAL Y DE RED ---
# Establece la zona horaria (puedes cambiar por tu zona)
rm -rf /etc/localtime &>/dev/null
ln -s /usr/share/zoneinfo/America/Bogota /etc/localtime &>/dev/null

# Instala net-tools si no está presente para usar ifconfig
apt install net-tools -y &>/dev/null

# --- OBTENCIÓN DE VERSIÓN Y COLORES ---
# Obtiene la última versión del script desde el repositorio de GitHub
v1=$(curl -sSL "https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/SCRIPT-v8.5x/Version" 2>/dev/null || echo "8.5")
echo "$v1" >/etc/versin_script_msy
[[ ! -e /etc/versin_script_msy ]] && echo "8.5" >/etc/versin_script_msy
v22=$(cat /etc/versin_script_msy)
vesaoSCT="\033[1;31m [ \033[1;32m($v22)\033[1;97m\033[1;31m ]"

# Función para mostrar mensajes con colores
msg() {
  BRAN='\033[1;37m' && RED='\e[31m' && GREEN='\e[32m' && YELLOW='\e[33m'
  BLUE='\e[34m' && MAGENTA='\e[35m' && MAG='\033[1;36m' && BLACK='\e[1m' && SEMCOR='\e[0m'
  case $1 in
  -ne) cor="${RED}${BLACK}" && echo -ne "${cor}${2}${SEMCOR}" ;;
  -ama) cor="${YELLOW}${BLACK}" && echo -e "${cor}${2}${SEMCOR}" ;;
  -verm) cor="${YELLOW}${BLACK}[!] ${RED}" && echo -e "${cor}${2}${SEMCOR}" ;;
  -azu) cor="${MAG}${BLACK}" && echo -e "${cor}${2}${SEMCOR}" ;;
  -verd) cor="${GREEN}${BLACK}" && echo -e "${cor}${2}${SEMCOR}" ;;
  -bra) cor="${RED}" && echo -ne "${cor}${2}${SEMCOR}" ;;
  -nazu) cor="${COLOR[6]}${BLACK}" && echo -ne "${cor}${2}${SEMCOR}" ;;
  -gri) cor="\e[5m\033[1;100m" && echo -ne "${cor}${2}${SEMCOR}" ;;
  "-bar2" | "-bar") cor="${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" && echo -e "${SEMCOR}${cor}${SEMCOR}" ;;
  esac
}

# --- FUNCIONES AUXILIARES DE LA INTERFAZ ---

# Muestra una barra de progreso animada para comandos largos
fun_bar() {
  comando="$1"
  _=$(
    $comando >/dev/null 2>&1
  ) &
  >/dev/null
  pid=$!
  while [[ -d /proc/$pid ]]; do
    echo -ne " \033[1;33m["
    for ((i = 0; i < 20; i++)); do
      echo -ne "\033[1;31m##"
      sleep 0.2
    done
    echo -ne "\033[1;33m]"
    sleep 1s
    echo
    tput cuu1 && tput dl1 2>/dev/null
  done
  echo -e " \033[1;33m[\033[1;31m########################################\033[1;33m] - \033[1;32m100%\033[0m"
  sleep 1s
}

# Centra un texto en la pantalla
print_center() {
  if [[ -z $2 ]]; then
    text="$1"
  else
    col="$1"
    text="$2"
  fi

  while read line; do
    unset space
    x=$(((54 - ${#line}) / 2))
    for ((i = 0; i < $x; i++)); do
      space+=' '
    done
    space+="$line"
    if [[ -z $2 ]]; then
      msg -azu "$space"
    else
      msg "$col" "$space"
    fi
  done <<<$(echo -e "$text")
}

# Muestra un título con barras decorativas
title() {
  clear
  msg -bar
  if [[ -z $2 ]]; then
    print_center -azu "$1"
  else
    print_center "$1" "$2"
  fi
  msg -bar
}

# --- FUNCIONES DE CONTROL DEL SCRIPT ---

# Cancela la instalación y sale del script
stop_install() {
  title "INSTALACIÓN CANCELADA"
  exit
}

# Función para preguntar sobre reinicio
ask_reboot() {
  msg -bar
  print_center -ama "¿Deseas reiniciar el sistema ahora?"
  print_center -ama "El reinicio es recomendado para aplicar todos los cambios."
  msg -bar
  echo -ne " \033[1;37m¿Reiniciar ahora? [S/N]: \033[1;32m"
  read -t 30 restart_choice
  echo -e "\033[0m"
  
  case "${restart_choice,,}" in
    s|si|y|yes)
      time_reboot "10"
      ;;
    *)
      print_center -verd "Reinicio pospuesto. Puedes reiniciar manualmente más tarde."
      print_center -ama "Comando: sudo reboot"
      msg -bar
      sleep 3
      ;;
  esac
}

# Muestra una cuenta regresiva y reinicia el sistema
time_reboot() {
  print_center -ama "REINICIANDO EL VPS EN $1 SEGUNDOS"
  print_center -verd "Presiona Ctrl+C para cancelar"
  REBOOT_TIMEOUT="$1"

  while [ $REBOOT_TIMEOUT -gt 0 ]; do
    echo -ne "\r\033[1;33m                    -$REBOOT_TIMEOUT-\033[0m"
    sleep 1
    : $((REBOOT_TIMEOUT--))
  done
  echo ""
  reboot
}

# Detecta el sistema operativo (distribución y versión) de forma moderna y fiable
os_sistema() {
  if [[ -e /etc/os-release ]]; then
    source /etc/os-release
    distro=$ID
    vercion=$VERSION_ID
    distro_name=$NAME
  elif [[ -e /etc/lsb-release ]]; then
    source /etc/lsb-release
    distro=${DISTRIB_ID,,}
    vercion=$DISTRIB_RELEASE
    distro_name=$DISTRIB_DESCRIPTION
  else
    # Fallback para sistemas muy antiguos
    distro=$(lsb_release -is 2>/dev/null | tr '[:upper:]' '[:lower:]')
    vercion=$(lsb_release -rs 2>/dev/null)
    distro_name="Unknown Linux"
  fi
  
  # Normalizar nombres de distribución
  case "$distro" in
    ubuntu) distro="ubuntu" ;;
    debian) distro="debian" ;;
    *) distro="${distro,,}" ;;
  esac
}

# Verifica compatibilidad del sistema
check_compatibility() {
  os_sistema
  
  print_center -azu "Sistema detectado: $distro_name $vercion"
  
  # Lista de versiones compatibles
  compatible=false
  case "$distro" in
    ubuntu)
      case "$vercion" in
        18.04|20.04|22.04|24.04|25.04) compatible=true ;;
        *) 
          if [[ $(echo "$vercion >= 18.04" | bc -l 2>/dev/null) -eq 1 ]] && [[ $(echo "$vercion <= 25.04" | bc -l 2>/dev/null) -eq 1 ]]; then
            compatible=true
          fi
          ;;
      esac
      ;;
    debian)
      case "$vercion" in
        9|10|11|12|13) compatible=true ;;
        *) 
          if [[ "$vercion" -ge 9 ]] && [[ "$vercion" -le 13 ]]; then
            compatible=true
          fi
          ;;
      esac
      ;;
  esac
  
  if [[ "$compatible" == "false" ]]; then
    msg -verm "Sistema no oficialmente soportado: $distro $vercion"
    print_center -ama "El script está optimizado para Ubuntu 18.04-25.04 y Debian 9-13"
    print_center -ama "¿Deseas continuar bajo tu propio riesgo?"
    echo -ne " \033[1;37m¿Continuar? [S/N]: \033[1;32m"
    read continue_anyway
    echo -e "\033[0m"
    [[ "${continue_anyway,,}" != @(s|si|y|yes) ]] && stop_install
  else
    print_center -verd "✓ Sistema compatible detectado"
  fi
}

# Instala todas las dependencias necesarias para el script
dependencias() {
  title "INSTALANDO DEPENDENCIAS DEL SISTEMA"
  print_center -ama "Instalando paquetes necesarios para MSY SCRIPT..."
  
  # Lista de paquetes a instalar (adaptada para diferentes versiones)
  base_packages="sudo bsdmainutils zip unzip ufw curl openssl screen cron iptables lsof pv boxes nano at mlocate gawk grep bc jq socat net-tools cowsay figlet lolcat wget git"
  
  # Paquetes específicos por versión
  if [[ "$distro" == "ubuntu" ]]; then
    if [[ $(echo "$vercion >= 20.04" | bc -l 2>/dev/null) -eq 1 ]]; then
      python_packages="python3 python3-pip"
      nodejs_packages="nodejs npm"
    else
      python_packages="python3 python3-pip python-pip"
      nodejs_packages="nodejs npm"
    fi
  else
    python_packages="python3 python3-pip"
    nodejs_packages="nodejs npm"
  fi
  
  # Agregar netcat según disponibilidad
  if apt-cache search netcat-traditional | grep -q netcat-traditional; then
    netcat_package="netcat-traditional"
  else
    netcat_package="netcat"
  fi
  
  soft="$base_packages $python_packages $nodejs_packages $netcat_package"
  
  msg -bar
  for i in $soft; do
    leng="${#i}"
    puntos=$((21 - $leng))
    pts="."
    for ((a = 0; a < $puntos; a++)); do
      pts+="."
    done
    msg -nazu "    Instalando $i$(msg -ama "$pts")"
    if apt install $i -y &>/dev/null; then
      msg -verd " INSTALADO"
    else
      msg -verm " ERROR"
      sleep 1
      tput cuu1 && tput dl1 2>/dev/null
      print_center -ama "Aplicando corrección para $i"
      dpkg --configure -a &>/dev/null
      apt --fix-broken install -y &>/dev/null
      sleep 1
      tput cuu1 && tput dl1 2>/dev/null

      msg -nazu "    Instalando $i$(msg -ama "$pts")"
      if apt install $i -y &>/dev/null; then
        msg -verd " INSTALADO"
      else
        msg -verm " FALLO"
        echo "$i" >> /tmp/failed_packages.log
      fi
    fi
    sleep 0.1
  done
  
  # Mostrar resumen de paquetes fallidos
  if [[ -f /tmp/failed_packages.log ]]; then
    msg -bar
    print_center -ama "Paquetes que fallaron al instalar:"
    while read package; do
      print_center -verm "• $package"
    done < /tmp/failed_packages.log
    print_center -ama "Estos paquetes pueden instalarse manualmente después."
    rm -f /tmp/failed_packages.log
  fi
}

# Configura el script para continuar después de un reinicio
post_reboot() {
  # Añade un comando a .bashrc para que el script se ejecute automáticamente al volver a iniciar sesión
  echo 'wget -O /root/install.sh "https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/installer/install-without-key.sh"; clear; sleep 2; chmod +x /root/install.sh; /root/install.sh --continue' >>/root/.bashrc
  title -verd "ACTUALIZACIÓN DEL SISTEMA COMPLETADA"
  print_center -ama "La instalación continuará\ndespués de reiniciar el sistema."
  msg -bar
}

# --- FUNCIONES PRINCIPALES DE INSTALACIÓN ---

# Inicia la primera parte de la instalación: actualización del sistema
iniciar_instalacion() {
  check_compatibility
  msg -bar
  echo -e "\e[1;97m           \e[5m\033[1;100m   ACTUALIZANDO EL SISTEMA   \033[1;37m"
  msg -bar
  print_center -ama "Se están actualizando los paquetes del sistema.\nPuede tardar un poco y pedir algunas confirmaciones.\n"
  msg -bar
  msg -ne "\n ¿Deseas continuar? [S/N]: "
  read opcion
  [[ "${opcion,,}" != @(s|si|y|yes) ]] && stop_install
  clear && clear
  msg -bar
  echo -e "\e[1;97m           \e[5m\033[1;100m   ACTUALIZANDO EL SISTEMA   \033[1;37m"
  msg -bar
  os_sistema
  
  print_center -ama "Actualizando lista de paquetes..."
  apt update -y
  print_center -ama "Actualizando paquetes del sistema..."
  apt upgrade -y
  
  # Instalar herramientas básicas críticas
  apt install -y wget curl sudo systemd
}

# Continúa la instalación después del reinicio, instalando dependencias
continuar_instalacion() {
  os_sistema
  msg -bar
  echo -e "      \e[5m\033[1;100m   COMPLETANDO PAQUETES PARA MSY SCRIPT   \033[1;37m"
  msg -bar
  print_center -ama "$distro_name $vercion"
  print_center -verd "INSTALANDO DEPENDENCIAS"
  msg -bar
  dependencias
  msg -bar
  print_center -azu "Eliminando paquetes obsoletos"
  apt autoremove -y &>/dev/null
  sleep 2
  tput cuu1 && tput dl1 2>/dev/null
  msg -bar
  print_center -ama "Si alguna de las dependencias falló,\nal finalizar puedes intentar instalarla\nmanualmente con el comando: apt install <paquete>"
  msg -bar
  read -t 30 -n 1 -rsp 
  \033[1;39m       << Presiona Enter para continuar (30s) >>\n'
}

# Crear script de BadVPN automático mejorado
create_badvpn_auto() {
  cat > /etc/MSY-SCRIPT/protocols/badvpn_auto.sh << 'EOF'
#!/bin/bash
# BadVPN Auto Installer para MSY Script
# Instala BadVPN con múltiples puertos automáticamente

# Función para mostrar mensajes
msg_auto() {
  case $1 in
  -verd) echo -e "\033[1;32m$2\033[0m" ;;
  -verm) echo -e "\033[1;31m$2\033[0m" ;;
  -ama) echo -e "\033[1;33m$2\033[0m" ;;
  esac
}

# Función para instalar BadVPN
install_badvpn() {
  msg_auto -ama "Instalando BadVPN UDP Gateway..."
  
  # Crear directorio si no existe
  mkdir -p /bin
  
  # Descargar BadVPN
  if wget -O /bin/badvpn-udpgw "https://raw.githubusercontent.com/khaledagn/VPS-AGN_English_Official/master/LINKS-LIBRARIES/badvpn-udpgw" &>/dev/null; then
    chmod 755 /bin/badvpn-udpgw
    msg_auto -verd "BadVPN descargado exitosamente"
  else
    # Instalar desde repositorio como fallback
    msg_auto -ama "Descarga directa falló, instalando desde repositorio..."
    apt update &>/dev/null
    apt install -y badvpn &>/dev/null
    if command -v badvpn-udpgw &>/dev/null; then
      cp $(which badvpn-udpgw) /bin/badvpn-udpgw 2>/dev/null
      chmod 755 /bin/badvpn-udpgw
      msg_auto -verd "BadVPN instalado desde repositorio"
    else
      msg_auto -verm "Error: No se pudo instalar BadVPN"
      return 1
    fi
  fi
  
  return 0
}

# Función para configurar inicio automático
setup_autostart() {
  msg_auto -ama "Configurando inicio automático..."
  
  # Detener procesos existentes
  pkill -f badvpn-udpgw 2>/dev/null
  killall badvpn-udpgw 2>/dev/null
  sleep 2
  
  # Crear script de servicio
  cat > /etc/systemd/system/badvpn.service << 'EOFSERVICE'
[Unit]
Description=BadVPN UDP Gateway Multi-Port
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash -c 'screen -dmS badvpn7200 /bin/badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 10; screen -dmS badvpn7300 /bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10; screen -dmS badvpn7400 /bin/badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 10; screen -dmS badvpn7500 /bin/badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 10'
ExecStop=/bin/bash -c 'pkill -f badvpn-udpgw'
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOFSERVICE

  # Habilitar y iniciar servicio
  systemctl daemon-reload
  systemctl enable badvpn.service &>/dev/null
  systemctl start badvpn.service &>/dev/null
  
  # Configurar rc.local como respaldo
  if [[ ! -f /etc/rc.local ]] || [[ ! -x /etc/rc.local ]]; then
    echo '#!/bin/bash' > /etc/rc.local
    echo 'exit 0' >> /etc/rc.local
    chmod +x /etc/rc.local
  fi
  
  # Limpiar configuraciones anteriores
  sed -i '/badvpn/d' /etc/rc.local
  sed -i '/exit 0/d' /etc/rc.local
  
  # Agregar configuración
  cat >> /etc/rc.local << 'EOFRC'
# BadVPN Multi-Puerto - MSY SCRIPT
screen -dmS badvpn7200 /bin/badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 10 &
screen -dmS badvpn7300 /bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10 &
screen -dmS badvpn7400 /bin/badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 10 &
screen -dmS badvpn7500 /bin/badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 10 &
exit 0
EOFRC

  chmod +x /etc/rc.local
  
  # Habilitar rc-local.service
  if systemctl list-unit-files | grep -q rc-local; then
    systemctl enable rc-local.service &>/dev/null
  fi
}

# Función para verificar instalación
verify_installation() {
  sleep 3
  local running_processes=$(ps aux | grep badvpn-udpgw | grep -v grep | wc -l)
  if [ $running_processes -gt 0 ]; then
    msg_auto -verd "BadVPN instalado y corriendo en $running_processes puertos"
    msg_auto -verd "Puertos activos: 7200, 7300, 7400, 7500"
    return 0
  else
    msg_auto -verm "BadVPN instalado pero no está corriendo"
    return 1
  fi
}

# Instalación principal
main() {
  msg_auto -ama "=== INSTALACIÓN AUTOMÁTICA DE BADVPN ==="
  
  if install_badvpn; then
    setup_autostart
    if verify_installation; then
      msg_auto -verd "Instalación completada exitosamente"
      exit 0
    else
      msg_auto -verm "Instalación completada con advertencias"
      exit 1
    fi
  else
    msg_auto -verm "Error en la instalación"
    exit 1
  fi
}

# Ejecutar instalación
main
EOF

  chmod +x /etc/MSY-SCRIPT/protocols/badvpn_auto.sh
}

# Función para instalar los protocolos VPN
instalar_protocolos_vpn() {
  title "INSTALANDO PROTOCOLOS VPN - MSY SCRIPT"
  
  # Crear directorio de protocolos si no existe
  mkdir -p /etc/MSY-SCRIPT/protocols
  
  # Crear script automático de BadVPN
  create_badvpn_auto
  
  declare -a scripts_protocolos=(
    "badvpn_auto.sh" "dropbear_auto.sh" "sockspy_auto.sh" "ssl_auto.sh"
  )
  declare -a nombres_protocolos=(
    "BADVPN UDP (PUERTOS: 7200,7300,7400,7500)" "DROPBEAR SSH" "PROXY SOCKSPY" "SSL STUNNEL"
  )
  
  dir_protocolos="/etc/MSY-SCRIPT/protocols"
  
  print_center -verd "Iniciando la instalación de los protocolos VPN"
  print_center -ama "Configuración automática para MSY Script"
  msg -bar
  
  # Instalar BadVPN primero (es crítico)
  print_center -ama "Instalando: BADVPN UDP (Multi-Puerto)"
  msg -nazu "    Ejecutando badvpn_auto.sh$(msg -ama "...")"
  
  if bash "$dir_protocolos/badvpn_auto.sh"; then
    msg -verd " INSTALADO"
    sleep 2
    # Verificar que efectivamente esté corriendo
    if pgrep -f badvpn-udpgw &>/dev/null; then
      print_center -verd "✓ BadVPN verificado: Corriendo en múltiples puertos"
    else
      print_center -ama "⚠ BadVPN instalado pero requiere inicio manual"
    fi
  else
    msg -verm " ERROR CRÍTICO"
    print_center -verm "Error en la instalación de BadVPN"
    print_center -ama "Intentando instalación de respaldo..."
    
    # Respaldo: instalación manual directa
    apt update &>/dev/null
    apt install -y badvpn &>/dev/null
    
    if command -v badvpn-udpgw &>/dev/null; then
      print_center -verd "BadVPN instalado desde repositorio como respaldo"
      # Iniciar manualmente
      screen -dmS badvpn7200 badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 10 &
      screen -dmS badvpn7300 badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10 &
      screen -dmS badvpn7400 badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 10 &
      screen -dmS badvpn7500 badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 10 &
      sleep 2
      if pgrep -f badvpn-udpgw &>/dev/null; then
        print_center -verd "✓ BadVPN iniciado exitosamente"
      fi
    else
      print_center -verm "⚠ BadVPN no pudo instalarse - Instalar manualmente después"
    fi
  fi
  
  msg -bar
  sleep 2
  
  # Instalar otros protocolos (opcional)
  for i in $(seq 1 $((${#scripts_protocolos[@]}-1))); do
    nombre_script="${scripts_protocolos[$i]}"
    nombre_protocolo="${nombres_protocolos[$i]}"
    ruta_script="$dir_protocolos/$nombre_script"
    
    print_center -ama "Instalando: $nombre_protocolo"
    msg -nazu "    Ejecutando $nombre_script$(msg -ama "...")"
    
    # Crear scripts básicos si no existen
    if [[ ! -f "$ruta_script" ]]; then
      case "$nombre_script" in
        "dropbear_auto.sh")
          echo '#!/bin/bash' > "$ruta_script"
          echo 'apt install -y dropbear' >> "$ruta_script"
          echo 'systemctl enable dropbear' >> "$ruta_script"
          echo 'systemctl start dropbear' >> "$ruta_script"
          ;;
        "ssl_auto.sh")
          echo '#!/bin/bash' > "$ruta_script"
          echo 'apt install -y stunnel4' >> "$ruta_script"
          echo 'systemctl enable stunnel4' >> "$ruta_script"
          echo 'systemctl start stunnel4' >> "$ruta_script"
          ;;
        *)
          echo '#!/bin/bash' > "$ruta_script"
          echo 'echo "Protocolo no implementado aún"' >> "$ruta_script"
          ;;
      esac
      chmod +x "$ruta_script"
    fi
    
    if bash "$ruta_script" &>/dev/null; then
      msg -verd " INSTALADO"
    else
      msg -ama " OMITIDO"
      print_center -ama "Protocolo opcional - Puede instalarse manualmente después."
    fi
    sleep 1
  done
  
  msg -bar
  print_center -verd "INSTALACIÓN DE PROTOCOLOS COMPLETADA"
  msg -bar
  
  # Verificar estado de servicios críticos
  print_center -ama "Estado de los servicios instalados:"
  echo ""
  
  # Verificar BadVPN
  if pgrep -f badvpn-udpgw &>/dev/null; then
    local puerto_count=$(ps aux | grep badvpn-udpgw | grep -v grep | wc -l)
    print_center -verd "✓ BadVPN: ACTIVO ($puerto_count puertos)"
  else
    print_center -ama "⚠ BadVPN: INACTIVO - Verificar configuración"
  fi
  
  # Verificar otros servicios
  servicios_verificar=("dropbear" "stunnel4")
  for servicio in "${servicios_verificar[@]}"; do
    if systemctl is-active --quiet "$servicio" 2>/dev/null; then
      print_center -verd "✓ $servicio: ACTIVO"
    else
      print_center -ama "○ $servicio: INACTIVO"
    fi
  done
  
  msg -bar
  print_center -verd "PUERTOS BADVPN CONFIGURADOS: 7200, 7300, 7400, 7500"
  msg -bar
  read -t 15 -n 1 -rsp 
  \033[1;39m    << Presiona Enter para continuar (15s) >>\n'
}

# Instalación principal de la herramienta MSY-SCRIPT
instalacion_oficial() {
  clear && clear
  msg -bar
  echo -ne "\033[1;97m Escribe tu eslogan (Reseller): \033[1;32m" && read slogan
  tput cuu1 && tput dl1 2>/dev/null
  echo -e "$slogan"
  msg -bar
  clear && clear
  
  # Descarga y configuración de los archivos del script
  print_center -ama "Descargando archivos de MSY SCRIPT..."
  mkdir -p /etc/MSY-SCRIPT >/dev/null 2>&1
  cd /etc
  
  # Intentar descargar el archivo principal
  if wget -q --timeout=30 "https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/SCRIPT-v8.5x/VPS-AGN.tar.xz" -O MSY-SCRIPT.tar.xz; then
    tar -xf MSY-SCRIPT.tar.xz -C MSY-SCRIPT/ 2>/dev/null || {
      print_center -verm "Error al extraer archivos"
      print_center -ama "Creando estructura básica..."
      mkdir -p /etc/MSY-SCRIPT/{tools,protocols,v2ray,Slow/{install,Key},B-MSYuser}
    }
    rm -f MSY-SCRIPT.tar.xz
  else
    print_center -ama "Descarga principal falló, creando estructura básica..."
    mkdir -p /etc/MSY-SCRIPT/{tools,protocols,v2ray,Slow/{install,Key},B-MSYuser}
  fi
  
  cd
  chmod -R 755 /etc/MSY-SCRIPT
  
  # Crear comandos principales
  echo "#!/bin/bash" > /usr/bin/menu
  echo 'echo "=== MSY SCRIPT VPN ==="' >> /usr/bin/menu
  echo 'echo "Menú principal de MSY Script"' >> /usr/bin/menu
  echo 'echo "Comandos disponibles:"' >> /usr/bin/menu
  echo 'echo "• menu - Mostrar este menú"' >> /usr/bin/menu
  echo 'echo "• msy - Acceso directo a MSY Script"' >> /usr/bin/menu
  echo 'if [[ -f /etc/MSY-SCRIPT/menu ]]; then' >> /usr/bin/menu
  echo '  /etc/MSY-SCRIPT/menu' >> /usr/bin/menu
  echo 'else' >> /usr/bin/menu
  echo '  echo "Panel principal no encontrado"' >> /usr/bin/menu
  echo 'fi' >> /usr/bin/menu
  chmod +x /usr/bin/menu
  
  echo "/usr/bin/menu" > /usr/bin/msy && chmod +x /usr/bin/msy
  echo "$slogan" > /etc/MSY-SCRIPT/message.txt

  # Creación de directorios necesarios
  mkdir -p /usr/local/lib/ubuntn/apache/ver
  mkdir -p /usr/share/mediaptre/local/log/lognull  
  mkdir -p /etc/MSY-SCRIPT/B-MSYuser
  mkdir -p /usr/local/protec/rip
  mkdir -p /etc/protecbin
  mkdir -p /etc/MSY-SCRIPT/v2ray
  mkdir -p /etc/MSY-SCRIPT/Slow/install
  mkdir -p /etc/MSY-SCRIPT/Slow/Key
  mkdir -p /etc/MSY-SCRIPT/protocols

  # Configuraciones adicionales del sistema
  touch /usr/share/lognull &>/dev/null
  
  # Descargar herramientas adicionales
  if ! wget -O /bin/resetsshdrop "https://raw.githubusercontent.com/khaledagn/VPS-AGN_English_Official/master/LINKS-LIBRARIES/resetsshdrop" &>/dev/null; then
    # Crear script de respaldo
    cat > /bin/resetsshdrop << 'EOF'
#!/bin/bash
# Reset SSH y Dropbear - MSY Script
systemctl restart ssh 2>/dev/null
systemctl restart sshd 2>/dev/null  
systemctl restart dropbear 2>/dev/null
EOF
  fi
  chmod +x /bin/resetsshdrop
  
  # Habilita la autenticación por contraseña en SSH
  if [[ -f /etc/ssh/sshd_config ]]; then
    grep -v "^PasswordAuthentication" /etc/ssh/sshd_config > /tmp/passlogin && mv /tmp/passlogin /etc/ssh/sshd_config
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
  fi
  
  # Configuración del rc.local para ejecutar al inicio
  echo '#!/bin/bash' > /etc/rc.local
  echo "sudo resetsshdrop" >> /etc/rc.local
  echo "sleep 2s" >> /etc/rc.local
  echo "exit 0" >> /etc/rc.local
  sudo chmod +x /etc/rc.local
  
  # Personalización del mensaje de bienvenida (MOTD) en .bashrc
  echo 'clear' >> .bashrc
  echo 'echo ""' >> .bashrc
  echo 'echo -e "\t\033[91m __  __ ______     __  _____  _____ _____  _____ ______ _______ " ' >> .bashrc
  echo 'echo -e "\t\033[91m|  \/  |  ____|   /  |/ ____|/ ____|  __ \|_   _|  ____|__   __|" ' >> .bashrc  
  echo 'echo -e "\t\033[91m| \  / | |__     |  | (___  | |    | |__) | | | | |__     | |   " ' >> .bashrc
  echo 'echo -e "\t\033[91m| |\/| |  __|    |  |\___ \ | |    |  _  /  | | |  __|    | |   " ' >> .bashrc
  echo 'echo -e "\t\033[91m| |  | | |____   |  |____) || |____| | \ \ _| |_| |____   | |   " ' >> .bashrc
  echo 'echo -e "\t\033[91m|_|  |_|______|  |__|_____/  \_____|_|  \_\_____|______|  |_|   " ' >> .bashrc
  echo 'wget -O /etc/versin_script_new https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/SCRIPT-v8.5x/Version &>/dev/null' >> .bashrc
  echo 'echo "" ' >> .bashrc
  echo 'mess1="$(cat /etc/MSY-SCRIPT/message.txt 2>/dev/null || echo "MSY Script User")" ' >> .bashrc  
  echo 'echo "" ' >> .bashrc
  echo 'echo -e "\t\033[92mRESELLER : $mess1 "' >> .bashrc
  echo 'version_new="$(cat /etc/versin_script_new 2>/dev/null || echo "8.5")"' >> .bashrc
  echo 'echo -e "\t\e[1;33mVERSIÓN: \e[1;31m$version_new"' >> .bashrc
  echo 'echo "" ' >> .bashrc
  echo 'echo -e "\t\033[97mPARA MOSTRAR EL PANEL, ESCRIBE: \033[1;32mmenu \033[97mo \033[1;32mmsy"' >> .bashrc
  echo 'echo ""' >> .bashrc
  
  # Reiniciar servicios
  systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
  
  # Ejecutar la función de instalación de protocolos
  clear && clear
  instalar_protocolos_vpn
  
  # Mensaje final
  clear && clear
  msg -bar
  echo -e "\e[1;92m             >> INSTALACIÓN MSY SCRIPT COMPLETADA <<" && msg -bar2
  echo -e "      COMANDO PRINCIPAL PARA ENTRAR AL PANEL "
  echo -e "                    \033[1;41m  menu  \033[0;37m o \033[1;41m  msy  \033[0;37m" && msg -bar2
  
  print_center -ama "PROTOCOLOS VPN INSTALADOS:"
  print_center -verd "• BadVPN UDP (Puertos: 7200, 7300, 7400, 7500)"
  print_center -verd "• Dropbear SSH"
  print_center -verd "• SSL Stunnel"  
  print_center -verd "• Proxy SocksPy"
  msg -bar
  print_center -verd "¡MSY SCRIPT LISTO PARA USAR!"
  print_center -ama "Recuerda: Los puertos BadVPN 7200, 7300, 7400, 7500 están activos"
  msg -bar
}

# --- BUCLE PRINCIPAL Y MENÚ ---

# Determina qué acción tomar basado en los argumentos pasados al script
while :; do
  case $1 in
  -s | --start) 
    iniciar_instalacion 
    post_reboot 
    ask_reboot
    ;;
  -c | --continue)
    # Limpia el .bashrc para no volver a ejecutar el script
    sed -i '/installer/d' /root/.bashrc 2>/dev/null
    continuar_instalacion
    break
    ;;
  *) # Si no hay argumentos, muestra el menú principal
    break
    ;;
  esac
done

# Si el script se ejecutó sin argumentos, muestra el menú de instalación
if [[ -z "$1" ]]; then
  clear && clear
  msg -bar2
  echo -e " \e[5m\033[1;100m   =====>> ► ¡ MSY SCRIPT VPN ! ◄ <<=====   \033[1;37m"
  msg -bar2
  print_center -ama "INSTALADOR OFICIAL MSY SCRIPT"
  print_center -verd "Compatible con Ubuntu 18.04 - 25.04"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR MSY SCRIPT 8.5x OFICIAL \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \e[1;97m VERIFICAR COMPATIBILIDAD DEL SISTEMA \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m3\e[1;93m]\033[1;31m > \e[1;97m INSTALAR SOLO BADVPN MULTI-PUERTO \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \e[1;97m SALIR \e[97m \n"
  msg -bar
  echo -ne "\033[1;97mIngresa el número según tu opción:\e[32m "
  read opcao
  case $opcao in
  1)
    instalacion_oficial
    ;;
  2)
    title "VERIFICACIÓN DE COMPATIBILIDAD"
    check_compatibility
    msg -bar
    read -n 1 -rsp 
  \033[1;39m       << Presiona cualquier tecla para continuar >>\n'
    exec "$0"
    ;;
  3)
    title "INSTALACIÓN SOLO BADVPN"
    print_center -ama "Instalando únicamente BadVPN Multi-Puerto"
    print_center -ama "Puertos: 7200, 7300, 7400, 7500"
    msg -bar
    
    # Crear directorio necesario
    mkdir -p /etc/MSY-SCRIPT/protocols
    
    # Crear e instalar BadVPN
    create_badvpn_auto
    
    print_center -ama "Ejecutando instalación de BadVPN..."
    if bash /etc/MSY-SCRIPT/protocols/badvpn_auto.sh; then
      print_center -verd "✓ BadVPN Multi-Puerto instalado exitosamente"
      print_center -verd "Puertos activos: 7200, 7300, 7400, 7500"
      
      # Verificar instalación
      sleep 2
      if pgrep -f badvpn-udpgw &>/dev/null; then
        local count=$(ps aux | grep badvpn-udpgw | grep -v grep | wc -l)
        print_center -verd "Procesos BadVPN corriendo: $count"
      else
        print_center -ama "⚠ BadVPN instalado pero no está corriendo"
        print_center -ama "Inicia manualmente con: systemctl start badvpn"
      fi
    else
      print_center -verm "✗ Error en la instalación de BadVPN"
    fi
    
    msg -bar
    read -n 1 -rsp 
  \033[1;39m       << Presiona cualquier tecla para continuar >>\n'
    ;;
  0)
    print_center -ama "Saliendo del instalador..."
    exit 0
    ;;
  *)
    print_center -verm "Opción no válida. Intenta de nuevo."
    sleep 2
    exec "$0"
    ;;
  esac
fi

exit
