#!/bin/bash
clear && clear

# Configuración inicial
rm -rf /etc/localtime &>/dev/null
ln -s /usr/share/zoneinfo/America/Bogota /etc/localtime &>/dev/null

# Variables globales
REPO_BASE="https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main"
SCRIPT_VERSION_URL="${REPO_BASE}/SCRIPT-v8.5x/Version"

# Detectar IP y interfaz de red
detect_network() {
    apt install net-tools -y &>/dev/null
    myip=$(ip route get 8.8.8.8 | awk '/src/{print $7}' | head -1)
    [[ -z $myip ]] && myip=$(hostname -I | awk '{print $1}')
    [[ -z $myip ]] && myip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1)
    myint=$(ip route | grep default | awk '{print $5}' | head -1)
    [[ -z $myint ]] && myint=$(ifconfig | grep -B1 "inet.*$myip" | head -n1 | awk '{print $1}' | sed 's/://')
}

# Obtener versión del script
get_script_version() {
    rm -rf /etc/versin_script &>/dev/null
    v1=$(curl -sSL "$SCRIPT_VERSION_URL" 2>/dev/null || echo "8.5")
    echo "$v1" > /etc/versin_script
    [[ ! -e /etc/versin_script ]] && echo "8.5" > /etc/versin_script
    v22=$(cat /etc/versin_script)
    vesaoSCT="\033[1;31m [ \033[1;32m($v22)\033[1;97m\033[1;31m ]"
}

# Funciones de colores y mensajes
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
        "-bar2"|"-bar") cor="${RED}————————————————————————————————————————————————————" && echo -e "${SEMCOR}${cor}${SEMCOR}" ;;
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
        for ((i=0; i<20; i++)); do
            echo -ne "\033[1;31m##"
            sleep 0.5
        done
        echo -ne "\033[1;33m]"
        sleep 1s
        echo
        tput cuu1 && tput dl1
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
        x=$(( (54 - ${#line}) / 2 ))
        for ((i=0; i<$x; i++)); do
            space+=' '
        done
        space+="$line"
        if [[ -z $2 ]]; then
            msg -azu "$space"
        else
            msg "$col" "$space"
        fi
    done <<< $(echo -e "$text")
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

stop_install() {
    title "INSTALACIÓN CANCELADA"
    exit 1
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

# Detectar sistema operativo
os_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        system="$NAME $VERSION"
        distro="$ID"
        vercion="$VERSION_ID"
    else
        system=$(cat -n /etc/issue | grep 1 | cut -d ' ' -f6,7,8 | sed 's/1//' | sed 's/      //')
        distro=$(echo "$system" | awk '{print $1}')
        case $distro in
            Debian) vercion=$(echo $system | awk '{print $3}' | cut -d '.' -f1) ;;
            Ubuntu) vercion=$(echo $system | awk '{print $2}' | cut -d '.' -f1,2) ;;
        esac
    fi
    
    # Normalizar nombres de distribución
    case $distro in
        ubuntu) distro="Ubuntu" ;;
        debian) distro="Debian" ;;
    esac
}

# Configurar repositorios según la versión
repo() {
    local version="$1"
    local repo_url
    
    case $version in
        18.04)
            repo_url="http://archive.ubuntu.com/ubuntu/"
            cat > /etc/apt/sources.list << EOF
deb $repo_url bionic main restricted
deb $repo_url bionic-updates main restricted
deb $repo_url bionic universe
deb $repo_url bionic-updates universe
deb $repo_url bionic multiverse
deb $repo_url bionic-updates multiverse
deb $repo_url bionic-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu bionic-security main restricted
deb http://security.ubuntu.com/ubuntu bionic-security universe
deb http://security.ubuntu.com/ubuntu bionic-security multiverse
EOF
            ;;
        20.04)
            repo_url="http://archive.ubuntu.com/ubuntu/"
            cat > /etc/apt/sources.list << EOF
deb $repo_url focal main restricted
deb $repo_url focal-updates main restricted
deb $repo_url focal universe
deb $repo_url focal-updates universe
deb $repo_url focal multiverse
deb $repo_url focal-updates multiverse
deb $repo_url focal-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu focal-security main restricted
deb http://security.ubuntu.com/ubuntu focal-security universe
deb http://security.ubuntu.com/ubuntu focal-security multiverse
EOF
            ;;
        22.04)
            repo_url="http://archive.ubuntu.com/ubuntu/"
            cat > /etc/apt/sources.list << EOF
deb $repo_url jammy main restricted
deb $repo_url jammy-updates main restricted
deb $repo_url jammy universe
deb $repo_url jammy-updates universe
deb $repo_url jammy multiverse
deb $repo_url jammy-updates multiverse
deb $repo_url jammy-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted
deb http://security.ubuntu.com/ubuntu jammy-security universe
deb http://security.ubuntu.com/ubuntu jammy-security multiverse
EOF
            ;;
        24.04|24.10)
            repo_url="http://archive.ubuntu.com/ubuntu/"
            cat > /etc/apt/sources.list << EOF
deb $repo_url noble main restricted
deb $repo_url noble-updates main restricted
deb $repo_url noble universe
deb $repo_url noble-updates universe
deb $repo_url noble multiverse
deb $repo_url noble-updates multiverse
deb $repo_url noble-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu noble-security main restricted
deb http://security.ubuntu.com/ubuntu noble-security universe
deb http://security.ubuntu.com/ubuntu noble-security multiverse
EOF
            ;;
    esac
}

# Instalar dependencias con mejor manejo de errores
dependencias() {
    # Actualizar primero
    apt update -y &>/dev/null
    
    # Lista de paquetes básicos
    local basic_packages="sudo wget curl git unzip zip"
    # Lista de paquetes adicionales
    local additional_packages="bsdmainutils ufw python3 python3-pip openssl screen cron iptables lsof pv boxes nano at mlocate gawk grep bc jq socat netcat-openbsd net-tools cowsay figlet lolcat"
    
    # Instalar paquetes básicos primero
    for pkg in $basic_packages; do
        install_package "$pkg"
    done
    
    # Instalar Node.js y npm por separado
    if ! command -v node &> /dev/null; then
        msg -nazu "    instalando nodejs y npm..."
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - &>/dev/null
        apt install -y nodejs &>/dev/null && msg -verd " INSTALADO" || msg -verm " ERROR"
    fi
    
    # Instalar paquetes adicionales
    for pkg in $additional_packages; do
        install_package "$pkg"
    done
    
    # Configuraciones especiales para versiones específicas
    case $vercion in
        22.04|24.04|24.10)
            # En Ubuntu 22+ netcat-traditional puede no estar disponible
            if ! dpkg -l | grep -q netcat-traditional; then
                install_package "netcat-openbsd"
            fi
            ;;
    esac
}

install_package() {
    local package="$1"
    local leng="${#package}"
    local puntos=$((21 - $leng))
    local pts="."
    
    for ((a=0; a<$puntos; a++)); do
        pts+="."
    done
    
    msg -nazu "    instalando $package$(msg -ama "$pts")"
    
    if apt install $package -y &>/dev/null; then
        msg -verd " INSTALADO"
    else
        msg -verm " ERROR"
        sleep 2
        tput cuu1 && tput dl1
        print_center -ama "aplicando corrección a $package"
        
        # Intentar reparar paquetes rotos
        dpkg --configure -a &>/dev/null
        apt --fix-broken install -y &>/dev/null
        sleep 2
        tput cuu1 && tput dl1
        
        msg -nazu "    instalando $package$(msg -ama "$pts")"
        if apt install $package -y &>/dev/null; then
            msg -verd " INSTALADO"
        else
            msg -verm " ERROR - Continuando..."
        fi
    fi
}

post_reboot() {
    echo 'wget -O /root/install.sh "'"$REPO_BASE"'/installer/install-without-key.sh"; clear; sleep 2; chmod +x /root/install.sh; /root/install.sh --continue' >> /root/.bashrc
    title -verd "ACTUALIZACIÓN DEL SISTEMA COMPLETADA"
    print_center -ama "La instalación continuará\ndespués del reinicio!!!"
    msg -bar
}

install_start() {
    msg -bar
    echo -e "\e[1;97m           \e[5m\033[1;100m   ACTUALIZACIÓN DEL SISTEMA   \033[1;37m"
    msg -bar
    print_center -ama "Los paquetes del sistema se están actualizando.\n Puede tomar un tiempo y pedir algunas confirmaciones.\n"
    msg -bar
    msg -ne "\n ¿Deseas continuar? [Y/N]: "
    read opcion
    [[ "$opcion" != @(y|Y|s|S) ]] && stop_install
    
    clear && clear
    msg -bar
    echo -e "\e[1;97m           \e[5m\033[1;100m   ACTUALIZACIÓN DEL SISTEMA   \033[1;37m"
    msg -bar
    
    os_system
    print_center -ama "Sistema detectado: $distro $vercion"
    msg -bar
    
    # Configurar repositorios si es necesario
    repo "$vercion"
    
    # Actualizar sistema
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
}

install_continue() {
    os_system
    detect_network
    get_script_version
    
    msg -bar
    echo -e "      \e[5m\033[1;100m   COMPLETANDO PAQUETES PARA EL SCRIPT   \033[1;37m"
    msg -bar
    print_center -ama "$distro $vercion"
    print_center -verd "INSTALANDO DEPENDENCIAS"
    msg -bar
    dependencias
    msg -bar
    print_center -azu "Removiendo paquetes obsoletos"
    apt autoremove -y &>/dev/null
    sleep 2
    tput cuu1 && tput dl1
    msg -bar
    print_center -ama "Si algunas de las dependencias fallan!!!\nal terminar, puedes intentar instalar\nlas mismas manualmente usando el siguiente comando\napt install nombre_del_paquete"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para continuar >>\n'
}

# Función principal de instalación
install_official() {
    clear && clear
    msg -bar
    echo -ne "\033[1;97m Escribe tu eslogan: \033[1;32m" && read slogan
    tput cuu1 && tput dl1
    echo -e "$slogan"
    msg -bar
    
    clear && clear
    
    # Crear directorios necesarios
    mkdir -p /etc/VPS-AGN >/dev/null 2>&1
    cd /etc
    
    # Descargar script principal
    msg -azu "Descargando archivos del script..."
    if wget -q "${REPO_BASE}/SCRIPT-v8.5x/VPS-AGN.tar.xz" -O VPS-AGN.tar.xz; then
        msg -verd "Descarga completada"
    else
        msg -verm "Error al descargar archivos"
        exit 1
    fi
    
    # Extraer archivos
    tar -xf VPS-AGN.tar.xz >/dev/null 2>&1
    chmod +x VPS-AGN.tar.xz >/dev/null 2>&1
    rm -rf VPS-AGN.tar.xz
    cd
    
    # Configurar permisos
    chmod -R 755 /etc/VPS-AGN
    rm -rf /etc/VPS-AGN/MEUIPvps
    
    # Crear comandos de acceso
    echo "/etc/VPS-AGN/menu" > /usr/bin/menu && chmod +x /usr/bin/menu
    echo "/etc/VPS-AGN/menu" > /usr/bin/VPSAGN && chmod +x /usr/bin/VPSAGN
    echo "/etc/VPS-AGN/menu" > /usr/bin/msyvpn && chmod +x /usr/bin/msyvpn
    
    # Descargar monitor
    wget -q "${REPO_BASE}/LINKS-LIBRARIES/monitor.sh" -P /bin/ 2>/dev/null
    chmod +x /bin/monitor.sh 2>/dev/null
    
    # Guardar eslogan
    echo "$slogan" > /etc/VPS-AGN/message.txt
    
    # Crear estructura de directorios
    create_directory_structure
    
    # Configurar SSH
    configure_ssh
    
    # Descargar utilidades adicionales
    download_utilities
    
    # Configurar arranque
    configure_startup
    
    # Configurar bash
    configure_bash
    
    # Limpiar archivos temporales
    cleanup_temp_files
    
    # Reiniciar servicios
    service ssh restart &>/dev/null
    
    clear && clear
    msg -bar
    echo -e "\e[1;92m             >> INSTALACIÓN COMPLETADA <<" && msg -bar2
    echo -e "      COMANDO PRINCIPAL PARA ENTRAR AL PANEL "
    echo -e "                      \033[1;41m  menu  \033[0;37m"
    echo -e "                      \033[1;41m  msyvpn  \033[0;37m"
    msg -bar2
}

create_directory_structure() {
    local dirs=(
        "/usr/local/lib"
        "/usr/local/lib/ubuntn"
        "/usr/local/lib/ubuntn/apache"
        "/usr/local/lib/ubuntn/apache/ver"
        "/usr/share/mediaptre"
        "/usr/share/mediaptre/local"
        "/usr/share/mediaptre/local/log"
        "/usr/share/mediaptre/local/log/lognull"
        "/etc/VPS-AGN/B-VPS-AGNuser"
        "/usr/local/protec"
        "/usr/local/protec/rip"
        "/etc/protecbin"
        "/etc/VPS-AGN/v2ray"
        "/etc/VPS-AGN/Slow"
        "/etc/VPS-AGN/Slow/install"
        "/etc/VPS-AGN/Slow/Key"
    )
    
    for dir in "${dirs[@]}"; do
        [[ ! -d "$dir" ]] && mkdir -p "$dir"
    done
    
    touch /usr/share/lognull &>/dev/null
}

configure_ssh() {
    # Configurar SSH para permitir autenticación por contraseña
    grep -v "^PasswordAuthentication" /etc/ssh/sshd_config > /tmp/passlogin && mv /tmp/passlogin /etc/ssh/sshd_config
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    
    # Para Ubuntu 22.04+ también necesitamos configurar otros parámetros
    case $vercion in
        22.04|24.04|24.10)
            grep -v "^PubkeyAuthentication" /etc/ssh/sshd_config > /tmp/pubkey && mv /tmp/pubkey /etc/ssh/sshd_config
            echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
            ;;
    esac
}

download_utilities() {
    # Descargar utilidades desde tu repositorio
    wget -O /bin/resetsshdrop "${REPO_BASE}/LINKS-LIBRARIES/resetsshdrop" &>/dev/null
    chmod +x /bin/resetsshdrop
    
    # Descargar soporte online
    wget -q "${REPO_BASE}/LINKS-LIBRARIES/SPR.sh" -O /usr/bin/SPR >/dev/null 2>&1
    chmod +x /usr/bin/SPR 2>/dev/null
}

configure_startup() {
    # Configurar rc.local
    echo '#!/bin/sh -e' > /etc/rc.local
    sudo chmod +x /etc/rc.local
    echo "sudo resetsshdrop" >> /etc/rc.local
    echo "sleep 2s" >> /etc/rc.local
    echo "exit 0" >> /etc/rc.local
    
    # Habilitar rc.local en systemd (Ubuntu 18+)
    if systemctl list-unit-files | grep -q rc-local; then
        systemctl enable rc-local &>/dev/null
    fi
}

configure_bash() {
    # Configurar bash personalizado
    echo 'clear' >> .bashrc
    echo 'echo ""' >> .bashrc
    echo 'echo -e "\t\033[91m __  __  _______     ____     _______   _   _ " ' >> .bashrc
    echo 'echo -e "\t\033[91m|  \/  |/ ____\ \   / /\ \   / /  __ \ | \ | |" ' >> .bashrc
    echo 'echo -e "\t\033[91m| \  / | (___ \ \_/ /  \ \_/ /| |__) ||  \| |" ' >> .bashrc
    echo 'echo -e "\t\033[91m| |\/| |\___ \ \   /    \   / |  ___/ |     |" ' >> .bashrc
    echo 'echo -e "\t\033[91m| |  | |____) | | |      | |  | |     | |\  |" ' >> .bashrc
    echo 'echo -e "\t\033[91m|_|  |_|_____/  |_|      |_|  |_|     |_| \_|" ' >> .bashrc
    echo 'wget -O /etc/versin_script_new '"$SCRIPT_VERSION_URL"' &>/dev/null' >> .bashrc
    echo 'echo "" ' >> .bashrc
    echo 'mess1="$(less /etc/VPS-AGN/message.txt)" ' >> .bashrc
    echo 'echo "" ' >> .bashrc
    echo 'echo -e "\t\033[92mRESELLER : $mess1 "' >> .bashrc
    echo 'echo -e "\t\e[1;33mVERSION: \e[1;31m$(cat /etc/versin_script_new 2>/dev/null || echo '"'8.5'"')"' >> .bashrc
    echo 'echo "" ' >> .bashrc
    echo 'echo -e "\t\033[97mPARA MOSTRAR EL PANEL BASH ESCRIBE: sudo msyvpn o menu "' >> .bashrc
    echo 'echo ""' >> .bashrc
}

cleanup_temp_files() {
    rm -rf /usr/bin/pytransform &>/dev/null
    rm -rf VPS-AGN.sh
    rm -rf lista-arq
    rm -rf /usr/local/lib/systemubu1 &>/dev/null
}

# Ciclo principal
while :; do
    case $1 in
        -s|--start) install_start && post_reboot && time_reboot "15" ;;
        -c|--continue)
            sed -i '/installer/d' /root/.bashrc
            install_continue
            break
            ;;
        *) break ;;
    esac
done

# Menú de instalación
clear && clear
msg -bar2
echo -e " \e[5m\033[1;100m   =====>> ►► 🐲 MSY-VPN - SCRIPT  🐲 ◄◄ <<=====   \033[1;37m"
msg -bar2
print_center -ama "LISTA DE SCRIPTS DISPONIBLES"
msg -bar

# Copiar bashrc
/bin/cp /etc/skel/.bashrc ~/
/bin/cp /etc/skel/.bashrc /etc/bash.bashrc

echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR MSY-VPN 8.5x OFICIAL \e[97m \n"
msg -bar
echo -ne "\033[1;97mIngresa solo el número según tu respuesta:\e[32m "
read opcao

case $opcao in
    1)
        install_official
        ;;
    *)
        echo "Opción no válida"
        exit 1
        ;;
esac

exit 0
