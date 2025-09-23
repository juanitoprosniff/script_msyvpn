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

# Barra de progreso mejorada para protocolos
protocol_progress_bar() {
  local current=$1
  local total=$2
  local protocol_name="$3"
  local percentage=$((current * 100 / total))
  local filled=$((percentage * 40 / 100))
  
  printf "\r\033[1;33m["
  for ((i = 0; i < filled; i++)); do
    printf "\033[1;32m█"
  done
  for ((i = filled; i < 40; i++)); do
    printf "\033[1;37m░"
  done
  printf "\033[1;33m] \033[1;36m%d%% \033[1;97m- \033[1;93m%s\033[0m" $percentage "$protocol_name"
}

# Función para instalar protocolos VPN automáticamente
install_vpn_protocols() {
  title -verd "INSTALANDO PROTOCOLOS VPN"
  print_center -ama "Instalando protocolos VPN automáticamente..."
  msg -bar
  
  # Array con los scripts de protocolos en orden
  local protocols=("dropbear_auto.sh" "badvpn_auto.sh" "sockspy_auto.sh" "ssl_auto.sh" "install_agnudp.sh")
  local protocol_names=("Dropbear SSH" "BadVPN UDP" "SocksIP Proxy" "SSL/TLS" "AGN UDP")
  local total_protocols=${#protocols[@]}
  
  # Verificar que existe la carpeta de protocolos
  if [[ ! -d "/etc/VPS-AGN/protocols" ]]; then
    mkdir -p /etc/VPS-AGN/protocols
  fi
  
  # Instalar cada protocolo
  for ((i = 0; i < total_protocols; i++)); do
    local current_protocol="${protocols[i]}"
    local protocol_name="${protocol_names[i]}"
    local current_step=$((i + 1))
    
    echo ""
    print_center -azu "PASO $current_step/$total_protocols: Instalando $protocol_name"
    msg -bar
    
    # Mostrar progreso inicial
    protocol_progress_bar $i $total_protocols "Preparando $protocol_name"
    sleep 1
    
    # Verificar si el script existe
    if [[ -f "/etc/VPS-AGN/protocols/$current_protocol" ]]; then
      # Hacer ejecutable el script
      chmod +x "/etc/VPS-AGN/protocols/$current_protocol"
      
      # Mostrar progreso de instalación
      protocol_progress_bar $current_step $total_protocols "Instalando $protocol_name"
      
      # Ejecutar el script de protocolo
      if /etc/VPS-AGN/protocols/$current_protocol &>/dev/null; then
        echo ""
        print_center -verd "✓ $protocol_name instalado correctamente"
      else
        echo ""
        print_center -verm "✗ Error al instalar $protocol_name"
        print_center -ama "Continuando con el siguiente protocolo..."
      fi
    else
      echo ""
      print_center -verm "✗ Script $current_protocol no encontrado"
      print_center -ama "Saltando al siguiente protocolo..."
    fi
    
    sleep 2
  done
  
  # Progreso final
  echo ""
  protocol_progress_bar $total_protocols $total_protocols "Instalación Completa"
  echo ""
  msg -bar
  print_center -verd "TODOS LOS PROTOCOLOS VPN HAN SIDO INSTALADOS"
  msg -bar
  sleep 3
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