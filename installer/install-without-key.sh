#!/bin/bash
clear && clear
rm -rf /etc/localtime &>/dev/null
ln -s /usr/share/zoneinfo/Africa/Algiers /etc/localtime &>/dev/null

apt install net-tools -y &>/dev/null
myip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1)
myint=$(ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}')
rm -rf /etc/localtime &>/dev/null
ln -s /usr/share/zoneinfo/Africa/Algiers /etc/localtime &>/dev/null
rm -rf /usr/local/lib/systemubu1 &>/dev/null
rm -rf /etc/versin_script &>/dev/null
v1=$(curl -sSL "https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/SCRIPT-v8.5x/Version")
echo "$v1" >/etc/versin_script
[[ ! -e /etc/versin_script ]] && echo 1 >/etc/versin_script
v22=$(cat /etc/versin_script)
vesaoSCT="\033[1;31m [ \033[1;32m($v22)\033[1;97m\033[1;31m ]"

### COLORES Y BARRA
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
  "-bar2" | "-bar") cor="${RED}——————————————————————————————————————————————————" && echo -e "${SEMCOR}${cor}${SEMCOR}" ;;
  esac
}

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
      sleep 0.5
    done
    echo -ne "\033[1;33m]"
    sleep 1s
    echo
    tput cuu1
    tput dl1
  done
  echo -e " \033[1;33m[\033[1;31m########################################\033[1;33m] - \033[1;32m100%\033[0m"
  sleep 1s
}

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

# Función para instalar protocolos VPN automáticamente
install_vpn_protocols() {
  title -verd "INSTALANDO PROTOCOLOS VPN"
  print_center -ama "Instalando protocolos VPN automáticamente..."
  msg -bar
  
  # Verificar que existe la carpeta de protocolos
  if [[ ! -d "/etc/VPS-AGN/protocols" ]]; then
    mkdir -p /etc/VPS-AGN/protocols
  fi
  
  # Arrays con los scripts
  local dropbear_script="dropbear_auto.sh"
  local parallel_scripts=("badvpn_auto.sh" "sockspy_auto.sh" "ssl_auto.sh" "install_agnudp.sh")
  local parallel_names=("BadVPN UDP" "SocksIP Proxy" "SSL/TLS" "AGN UDP")
  
  # PASO 1: Instalar Dropbear primero
  echo ""
  print_center -azu "PASO 1/2: Instalando Dropbear SSH"
  msg -bar
  
  if [[ -f "/etc/VPS-AGN/protocols/$dropbear_script" ]]; then
    chmod +x "/etc/VPS-AGN/protocols/$dropbear_script"
    
    print_center -ama "Iniciando instalación de Dropbear SSH..."
    
    # Ejecutar dropbear con progreso real
    /etc/VPS-AGN/protocols/$dropbear_script &
    local dropbear_pid=$!
    
    # Mostrar progreso mientras se ejecuta
    local counter=0
    while kill -0 $dropbear_pid 2>/dev/null; do
      counter=$((counter + 1))
      local progress=$((counter * 2))
      if [[ $progress -gt 100 ]]; then
        progress=100
      fi
      printf "\r\033[1;33m[\033[1;32m"
      local filled=$((progress * 40 / 100))
      for ((i = 0; i < filled; i++)); do
        printf "█"
      done
      printf "\033[1;37m"
      for ((i = filled; i < 40; i++)); do
        printf "░"
      done
      printf "\033[1;33m] \033[1;36m%d%% \033[1;97m- \033[1;93mDropbear SSH\033[0m" $progress
      sleep 1
    done
    
    wait $dropbear_pid
    local dropbear_status=$?
    
    echo ""
    if [[ $dropbear_status -eq 0 ]]; then
      print_center -verd "✓ Dropbear SSH instalado correctamente"
    else
      print_center -verm "✗ Error al instalar Dropbear SSH"
    fi
  else
    print_center -verm "✗ Script dropbear_auto.sh no encontrado"
  fi
  
  msg -bar
  print_center -ama "Esperando 6 segundos antes de continuar..."
  
  # Cuenta regresiva visual
  for i in {6..1}; do
    printf "\r\033[1;33mContinuando en: \033[1;31m%d \033[1;33msegundos...\033[0m" $i
    sleep 1
  done
  echo ""
  
  # PASO 2: Instalar los otros 4 protocolos en paralelo
  echo ""
  print_center -azu "PASO 2/2: Instalando protocolos restantes en paralelo"
  msg -bar
  
  # Crear array para almacenar PIDs
  declare -a pids
  declare -a status_files
  
  # Iniciar todos los scripts en paralelo
  for ((i = 0; i < ${#parallel_scripts[@]}; i++)); do
    local script="${parallel_scripts[i]}"
    local name="${parallel_names[i]}"
    
    if [[ -f "/etc/VPS-AGN/protocols/$script" ]]; then
      chmod +x "/etc/VPS-AGN/protocols/$script"
      
      # Crear archivo temporal para el estado
      local status_file="/tmp/protocol_status_$i"
      status_files[i]="$status_file"
      
      print_center -ama "Iniciando $name..."
      
      # Ejecutar en background y guardar estado
      (
        if /etc/VPS-AGN/protocols/$script &>/dev/null; then
          echo "SUCCESS" > "$status_file"
        else
          echo "ERROR" > "$status_file"
        fi
      ) &
      
      pids[i]=$!
    else
      print_center -verm "✗ Script $script no encontrado"
      status_files[i]="/tmp/not_found_$i"
      echo "NOT_FOUND" > "/tmp/not_found_$i"
    fi
  done
  
  msg -bar
  print_center -ama "Instalando protocolos en paralelo..."
  
  # Mostrar progreso general mientras se ejecutan
  local all_done=false
  local progress=0
  while [[ "$all_done" != "true" ]]; do
    local completed=0
    local total=${#parallel_scripts[@]}
    
    # Contar cuántos han terminado
    for pid in "${pids[@]}"; do
      if ! kill -0 $pid 2>/dev/null; then
        completed=$((completed + 1))
      fi
    done
    
    # Calcular progreso
    if [[ $total -gt 0 ]]; then
      progress=$((completed * 100 / total))
    fi
    
    # Mostrar barra de progreso
    printf "\r\033[1;33m[\033[1;32m"
    local filled=$((progress * 40 / 100))
    for ((i = 0; i < filled; i++)); do
      printf "█"
    done
    printf "\033[1;37m"
    for ((i = filled; i < 40; i++)); do
      printf "░"
    done
    printf "\033[1;33m] \033[1;36m%d%% \033[1;97m- \033[1;93mInstalación en paralelo\033[0m" $progress
    
    # Verificar si todos terminaron
    if [[ $completed -eq $total ]]; then
      all_done=true
    else
      sleep 1
    fi
  done
  
  echo ""
  msg -bar
  
  # Mostrar resultados
  for ((i = 0; i < ${#parallel_scripts[@]}; i++)); do
    local name="${parallel_names[i]}"
    local status_file="${status_files[i]}"
    
    if [[ -f "$status_file" ]]; then
      local status=$(cat "$status_file")
      case $status in
        "SUCCESS")
          print_center -verd "✓ $name instalado correctamente"
          ;;
        "ERROR")
          print_center -verm "✗ Error al instalar $name"
          ;;
        "NOT_FOUND")
          print_center -verm "✗ Script de $name no encontrado"
          ;;
      esac
      rm -f "$status_file"
    fi
  done
  
  msg -bar
  print_center -verd "INSTALACIÓN DE PROTOCOLOS VPN COMPLETADA"
  msg -bar
  sleep 2
}

stop_install() {
  title "INSTALACION CANCELADA"
  exit
}

time_reboot() {
  print_center -ama "REINICIANDO VPS EN $1 SEGUNDOS"
  REBOOT_TIMEOUT="$1"

  while [ $REBOOT_TIMEOUT -gt 0 ]; do
    print_center -ne "-$REBOOT_TIMEOUT-\r"
    sleep 1
    : $((REBOOT_TIMEOUT--))
  done
  reboot
}

os_system() {
  system=$(cat -n /etc/issue | grep 1 | cut -d ' ' -f6,7,8 | sed 's/1//' | sed 's/      //')
  distro=$(echo "$system" | awk '{print $1}')

  case $distro in
  Debian) vercion=$(echo $system | awk '{print $3}' | cut -d '.' -f1) ;;
  Ubuntu) vercion=$(echo $system | awk '{print $2}' | cut -d '.' -f1,2) ;;
  esac
}

dependencias() {
  soft="sudo bsdmainutils zip unzip ufw curl python python3 python3-pip openssl screen cron iptables lsof pv boxes nano at mlocate gawk grep bc jq curl npm nodejs socat netcat netcat-traditional net-tools cowsay figlet lolcat"

  for i in $soft; do
    leng="${#i}"
    puntos=$((21 - $leng))
    pts="."
    for ((a = 0; a < $puntos; a++)); do
      pts+="."
    done
    msg -nazu "    instalando $i$(msg -ama "$pts")"
    if apt install $i -y &>/dev/null; then
      msg -verd " INSTALADO"
    else
      msg -verm2 " ERROR"
      sleep 2
      tput cuu1 && tput dl1
      print_center -ama "aplicando corrección a $i"
      dpkg --configure -a &>/dev/null
      sleep 2
      tput cuu1 && tput dl1

      msg -nazu "    instalando $i$(msg -ama "$pts")"
      if apt install $i -y &>/dev/null; then
        msg -verd " INSTALADO"
      else
        msg -verm2 " ERROR"
      fi
    fi
  done
}

post_reboot() {
  echo 'wget -O /root/install.sh "https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/installer/install-without-key.sh"; clear; sleep 2; chmod +x /root/install.sh; /root/install.sh --continue' >>/root/.bashrc
  title -verd "ACTUALIZACIÓN DEL SISTEMA COMPLETADA"
  print_center -ama "La instalación continuará\ndespués del reinicio!!!"
  msg -bar
}

install_start() {
  msg -bar
  echo -e "\e[1;97m           \e[5m\033[1;100m   ACTUALIZACIÓN DEL SISTEMA   \033[1;37m"
  msg -bar
  print_center -ama "Los paquetes del sistema se están actualizando.\n Puede tomar un tiempo y pedir algunas confirmaciones.\n"
  msg -bar3
  msg -ne "\n ¿Desea continuar? [Y/N]: "
  read opcion
  [[ "$opcion" != @(y|Y|s|S) ]] && stop_install
  clear && clear
  msg -bar
  echo -e "\e[1;97m           \e[5m\033[1;100m   ACTUALIZACIÓN DEL SISTEMA   \033[1;37m"
  msg -bar
  os_system
  apt update -y
  apt upgrade -y
}

install_continue() {
  os_system
  msg -bar
  echo -e "      \e[5m\033[1;100m   COMPLETANDO PAQUETES PARA EL SCRIPT   \033[1;37m"
  msg -bar
  print_center -ama "$distro $vercion"
  print_center -verd "INSTALANDO DEPENDENCIAS"
  msg -bar3
  dependencias
  msg -bar3
  print_center -azu "Eliminando paquetes obsoletos"
  apt autoremove -y &>/dev/null
  sleep 2
  tput cuu1 && tput dl1
  msg -bar
  print_center -ama "Si alguna de las dependencias falla!!!\nal finalizar, puedes intentar instalar\nla misma manualmente usando el siguiente comando\napt install nombre_del_paquete"
  msg -bar
  read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para continuar >>\n'
}

while :; do
  case $1 in
  -s | --start) install_start && post_reboot && time_reboot "15" ;;
  -c | --continue)
    #rm /root/install-without-key.sh &>/dev/null
    sed -i '/installer/d' /root/.bashrc
    install_continue
    break
    ;;
  *) exit ;;
  esac
done

clear && clear
msg -bar2
echo -e " \e[5m\033[1;100m   =====>> ►► ⚡ MSY VPN SCRIPT ⚡ ◄◄ <<=====   \033[1;37m"
msg -bar2
print_center -ama "LISTA DE SCRIPTS DISPONIBLES"
msg -bar

#-BASH SOPORTE ONLINE
wget https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/LINKS-LIBRARIES/SPR.sh -O /usr/bin/SPR >/dev/null 2>&1
chmod +x /usr/bin/SPR

#VPS-AGN 8.6 OFICIAL
install_official() {
  clear && clear
  msg -bar
  echo -ne "\033[1;97m Escribe tu eslogan: \033[1;32m" && read slogan
  tput cuu1 && tput dl1
  echo -e "$slogan"
  msg -bar
  clear && clear
  mkdir /etc/VPS-AGN >/dev/null 2>&1
  cd /etc
  wget https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/SCRIPT-v8.5x/VPS-AGN.tar.xz >/dev/null 2>&1
  tar -xf VPS-AGN.tar.xz >/dev/null 2>&1
  chmod +x VPS-AGN.tar.xz >/dev/null 2>&1
  rm -rf VPS-AGN.tar.xz
  cd
  chmod -R 755 /etc/VPS-AGN
  rm -rf /etc/VPS-AGN/MEUIPvps
  echo "/etc/VPS-AGN/menu" >/usr/bin/menu && chmod +x /usr/bin/menu
  echo "/etc/VPS-AGN/menu" >/usr/bin/VPSAGN && chmod +x /usr/bin/VPSAGN
  wget https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/LINKS-LIBRARIES/monitor.sh -P /bin/
  echo "$slogan" >/etc/VPS-AGN/message.txt
  [[ ! -d /usr/local/lib ]] && mkdir /usr/local/lib
  [[ ! -d /usr/local/lib/ubuntn ]] && mkdir /usr/local/lib/ubuntn
  [[ ! -d /usr/local/lib/ubuntn/apache ]] && mkdir /usr/local/lib/ubuntn/apache
  [[ ! -d /usr/local/lib/ubuntn/apache/ver ]] && mkdir /usr/local/lib/ubuntn/apache/ver
  [[ ! -d /usr/share ]] && mkdir /usr/share
  [[ ! -d /usr/share/mediaptre ]] && mkdir /usr/share/mediaptre
  [[ ! -d /usr/share/mediaptre/local ]] && mkdir /usr/share/mediaptre/local
  [[ ! -d /usr/share/mediaptre/local/log ]] && mkdir /usr/share/mediaptre/local/log
  [[ ! -d /usr/share/mediaptre/local/log/lognull ]] && mkdir /usr/share/mediaptre/local/log/lognull
  [[ ! -d /etc/VPS-AGN/B-VPS-AGNuser ]] && mkdir /etc/VPS-AGN/B-VPS-AGNuser
  [[ ! -d /usr/local/protec ]] && mkdir /usr/local/protec
  [[ ! -d /usr/local/protec/rip ]] && mkdir /usr/local/protec/rip
  [[ ! -d /etc/protecbin ]] && mkdir /etc/protecbin
  cd
  [[ ! -d /etc/VPS-AGN/v2ray ]] && mkdir /etc/VPS-AGN/v2ray
  [[ ! -d /etc/VPS-AGN/Slow ]] && mkdir /etc/VPS-AGN/Slow
  [[ ! -d /etc/VPS-AGN/Slow/install ]] && mkdir /etc/VPS-AGN/Slow/install
  [[ ! -d /etc/VPS-AGN/Slow/Key ]] && mkdir /etc/VPS-AGN/Slow/Key
  [[ ! -d /etc/VPS-AGN/protocols ]] && mkdir /etc/VPS-AGN/protocols
  
  touch /usr/share/lognull &>/dev/null
  wget -O /bin/resetsshdrop https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/LINKS-LIBRARIES/resetsshdrop &>/dev/null
  chmod +x /bin/resetsshdrop
  grep -v "^PasswordAuthentication" /etc/ssh/sshd_config >/tmp/passlogin && mv /tmp/passlogin /etc/ssh/sshd_config
  echo "PasswordAuthentication yes" >>/etc/ssh/sshd_config
  rm -rf /usr/local/lib/systemubu1 &>/dev/null
  rm -rf /etc/versin_script &>/dev/null
  v1=$(curl -sSL "https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/SCRIPT-v8.5x/Version")
  echo "$v1" >/etc/versin_script
  wget -O /etc/versin_script_new https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/SCRIPT-v8.5x/Version &>/dev/null
  echo '#!/bin/sh -e' >/etc/rc.local
  sudo chmod +x /etc/rc.local
  echo "sudo resetsshdrop" >>/etc/rc.local
  echo "sleep 2s" >>/etc/rc.local
  echo "exit 0" >>/etc/rc.local
  echo 'clear' >>.bashrc
  echo 'echo ""' >>.bashrc
  echo 'echo -e "\t\033[91m __      _______   _____              _____ _   _ " ' >>.bashrc
  echo 'echo -e "\t\033[91m \ \    / /  __ \ / ____|       /\   / ____| \ | | " ' >>.bashrc
  echo 'echo -e "\t\033[91m  \ \  / /| |__) | (___ ______ /  \ | |  __|  \| |  " ' >>.bashrc
  echo 'echo -e "\t\033[91m   \ \/ / |  ___/ \___ \______/ /\ \| | |_ |     |  " ' >>.bashrc
  echo 'echo -e "\t\033[91m    \  /  | |     ____) |    / ____ \ |__| | |\  | " ' >>.bashrc
  echo 'echo -e "\t\033[91m     \/   |_|    |_____/    /_/    \_\_____|_| \_|" ' >>.bashrc
  echo 'wget -O /etc/versin_script_new https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/SCRIPT-v8.5x/Version &>/dev/null' >>.bashrc
  echo 'echo "" ' >>.bashrc
  echo 'mess1="$(less /etc/VPS-AGN/message.txt)" ' >>.bashrc
  echo 'echo "" ' >>.bashrc
  echo 'echo -e "\t\033[92mREVENDEDOR : $mess1 "' >>.bashrc
  echo 'echo -e "\t\e[1;33mVERSIÓN: \e[1;31m$(cat /etc/versin_script_new)"' >>.bashrc
  echo 'echo "" ' >>.bashrc
  echo 'echo -e "\t\033[97mPARA MOSTRAR EL PANEL BASH ESCRIBE: sudo VPSAGN o menu "' >>.bashrc
  echo 'echo ""' >>.bashrc
  rm -rf /usr/bin/pytransform &>/dev/null
  rm -rf VPS-AGN.sh
  rm -rf lista-arq
  service ssh restart &>/dev/null
  
  # Instalar protocolos VPN automáticamente
  install_vpn_protocols
  
  clear && clear
  msg -bar
  echo -e "\e[1;92m             >> INSTALACIÓN COMPLETADA <<" && msg bar2
  echo -e "      COMANDO PRINCIPAL PARA INGRESAR AL PANEL "
  echo -e "                      \033[1;41m  menu  \033[0;37m" && msg -bar2
  print_center -verd "TODOS LOS PROTOCOLOS VPN HAN SIDO INSTALADOS AUTOMÁTICAMENTE"
  msg -bar
}

#MENÚS
/bin/cp /etc/skel/.bashrc ~/
/bin/cp /etc/skel/.bashrc /etc/bash.bashrc
echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR 8.5x OFICIAL \e[97m \n"
msg -bar
echo -ne "\033[1;97mIngresa solo el número según tu respuesta:\e[32m "
read opcao
case $opcao in
1)
  install_official
  ;;
*)
  print_center -verm "Opción no válida"
  exit 1
  ;;
esac
exit