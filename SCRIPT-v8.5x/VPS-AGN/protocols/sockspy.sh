#!/bin/bash
#25/01/2025 by @JuanitoProSniff - Versión Mejorada
clear
clear
SCPdir="/etc/VPS-AGN"
SCPfrm="${SCPdir}/tools" && [[ ! -d ${SCPfrm} ]] && exit
SCPinst="${SCPdir}/protocols"&& [[ ! -d ${SCPinst} ]] && exit
declare -A cor=( [0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m" )

# Verificar e instalar dependencias para Ubuntu 18-25
install_dependencies() {
    if ! command -v python3 &> /dev/null; then
        echo -e "\033[1;33mInstalando Python3...\033[0m"
        apt-get update &>/dev/null
        apt-get install python3 python3-pip -y &>/dev/null
    fi
    
    if ! command -v screen &> /dev/null; then
        echo -e "\033[1;33mInstalando Screen...\033[0m"
        apt-get install screen -y &>/dev/null
    fi
    
    if ! command -v lsof &> /dev/null; then
        echo -e "\033[1;33mInstalando lsof...\033[0m"
        apt-get install lsof -y &>/dev/null
    fi
}

install_dependencies

fun_trans() {
    echo "$1"
}

msg() {
    case $1 in
        -bar) echo -e "\033[1;37m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m";;
        -tit) echo -e "\033[1;32m    GESTOR DE PROXIES VPS-AGN - @JuanitoProSniff\033[0m";;
        -ama) echo -e "\033[1;33m$2\033[0m";;
        -verm2) echo -e "\033[1;32m$2\033[0m";;
    esac
}

mportas() {
    unset portas
    portas_var=$(lsof -V -i tcp -P -n 2>/dev/null | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    while read port; do
        [[ -z "$port" ]] && continue
        var1=$(echo $port | awk '{print $1}') 
        var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas|grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
    done <<< "$portas_var"
    echo -e "$portas"
}

meu_ip() {
    MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    MEU_IP2=$(timeout 10 wget -qO- ipv4.icanhazip.com 2>/dev/null || curl -s ifconfig.me 2>/dev/null)
    [[ "$MEU_IP" != "$MEU_IP2" ]] && echo "$MEU_IP2" || echo "$MEU_IP"
}

tcpbypass_fun() {
    [[ -e $HOME/socks ]] && rm -rf $HOME/socks > /dev/null 2>&1
    [[ -d $HOME/socks ]] && rm -rf $HOME/socks > /dev/null 2>&1
    cd $HOME && mkdir socks > /dev/null 2>&1
    cd socks
    patch="https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/master/LINKS-LIBRARIES/backsocz.zip"
    arq="backsocz.zip"
    
    echo -e "\033[1;33mDescargando archivos TCP Bypass...\033[0m"
    if wget $patch > /dev/null 2>&1; then
        unzip $arq > /dev/null 2>&1
        if [[ -f /root/socks/backsocz/ssh ]]; then
            cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
            mv -f /root/socks/backsocz/ssh /etc/ssh/sshd_config
            systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
        fi
        
        # Detectar versión de Python y mover archivos apropiados
        python_version=$(python3 --version 2>/dev/null | awk '{print $2}' | cut -d'.' -f1,2)
        if [[ -f /root/socks/backsocz/sckt${python_version} ]]; then
            mv -f /root/socks/backsocz/sckt${python_version} /usr/sbin/sckt
        elif [[ -f /root/socks/backsocz/sckt3.6 ]]; then
            mv -f /root/socks/backsocz/sckt3.6 /usr/sbin/sckt
        fi
        
        if [[ -f /root/socks/backsocz/scktcheck ]]; then
            mv -f /root/socks/backsocz/scktcheck /bin/scktcheck
            chmod +x /bin/scktcheck
            chmod +x /usr/sbin/sckt
        fi
    else
        echo -e "\033[1;31mError al descargar archivos TCP Bypass\033[0m"
        return 1
    fi
    
    rm -rf $HOME/socks
    cd $HOME
    
    msg="$2"
    [[ $msg = "" ]] && msg="@JuanitoProSniff"
    portxz="$1"
    [[ $portxz = "" ]] && portxz="8080"
    screen -dmS sokz scktcheck "$portxz" "$msg" > /dev/null 2>&1
    
    echo -e "\033[1;32mTCP Bypass iniciado en puerto $portxz\033[0m"
}

gettunel_fun() {
    echo "master=NetVPS" > ${SCPinst}/pwd.pwd
    while read service; do
        [[ -z $service ]] && break
        echo "127.0.0.1:$(echo $service|cut -d' ' -f2)=$(echo $service|cut -d' ' -f1)" >> ${SCPinst}/pwd.pwd
    done <<< "$(mportas)"
    screen -dmS getpy python3 ${SCPinst}/PGet.py -b "0.0.0.0:$1" -p "${SCPinst}/pwd.pwd"
    
    if [[ "$(ps aux | grep "PGet.py" | grep -v "grep")" ]]; then
        echo -e "\033[1;32mGettunel iniciado correctamente\033[0m"
        msg -bar
        echo -ne "\033[1;37mTu contraseña de Gettunnel es: \033[1;32mJuanitoProSniff\033[0m"
        msg -bar
    else 
        echo -e "\033[1;31mGettunel no se pudo iniciar\033[0m"
    fi
    msg -bar
}

PythonDic_fun() {
    echo -e "\033[1;33m  Configurar Proxy Directo Universal\033[1;37m" 
    msg -bar
    echo -ne "\033[1;97mIngresa un puerto SSH/DROPBEAR activo: \033[1;92m" && read puetoantla 
    msg -bar
    
    # Validar puerto
    if ! [[ "$puetoantla" =~ ^[0-9]+$ ]] || [ "$puetoantla" -lt 1 ] || [ "$puetoantla" -gt 65535 ]; then
        echo -e "\033[1;31mPuerto inválido. Usando puerto 22 por defecto.\033[0m"
        puetoantla=22
    fi
    
    cat > /etc/VPS-AGN/protocols/PDirect.py << 'PYTHON'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket, threading, select, signal, sys, time, getopt
import re

# Configuración de escucha
LISTENING_ADDR = '0.0.0.0'
if sys.argv[1:]:
    LISTENING_PORT = int(sys.argv[1])
else:
    LISTENING_PORT = 80

# Configuración
PASS = ''
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:PUERTO_SSH'

# Respuestas HTTP múltiples para compatibilidad universal
HTTP_RESPONSES = {
    '200': 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n',
    '101': 'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',
    '404': 'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n',
    '500': 'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n'
}

def get_response_for_request(request_data):
    """Detecta el tipo de solicitud y devuelve la respuesta apropiada"""
    request_str = request_data.decode('utf-8', errors='ignore')
    
    # Detectar WebSocket
    if 'Upgrade: websocket' in request_str or 'upgrade: websocket' in request_str:
        return HTTP_RESPONSES['101']
    
    # Detectar tipo de método HTTP
    if request_str.startswith('GET'):
        return HTTP_RESPONSES['200']
    elif request_str.startswith('POST'):
        return HTTP_RESPONSES['200'] 
    elif request_str.startswith('CONNECT'):
        return HTTP_RESPONSES['200']
    else:
        # Respuesta por defecto compatible
        return HTTP_RESPONSES['200']

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        try:
            self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.soc.settimeout(2)
            self.soc.bind((self.host, int(self.port)))
            self.soc.listen(50)  # Incrementar backlog
            self.running = True

            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                    conn = ConnectionHandler(c, self, addr)
                    conn.start()
                    self.addConn(conn)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.printLog(f"Error en servidor: {str(e)}")
        except Exception as e:
            self.printLog(f"Error crítico del servidor: {str(e)}")
        finally:
            self.running = False
            if hasattr(self, 'soc'):
                self.soc.close()

    def printLog(self, log):
        with self.logLock:
            print(log)

    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        with self.threadsLock:
            try:
                self.threads.remove(conn)
            except ValueError:
                pass

    def close(self):
        self.running = False
        with self.threadsLock:
            threads = list(self.threads)
            for c in threads:
                c.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.daemon = True
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = b''
        self.server = server
        self.log = f'Conexión: {str(addr)}'

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client.settimeout(30)
            self.client_buffer = self.client.recv(BUFLEN)

            if not self.client_buffer:
                return

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            if not hostPort:
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')
            if split:
                try:
                    self.client.recv(BUFLEN)
                except:
                    pass

            if hostPort:
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
                
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send(b'HTTP/1.1 400 Wrong Password!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send(b'HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                self.client.send(b'HTTP/1.1 400 No X-Real-Host!\r\n\r\n')

        except Exception as e:
            self.log += f' - error: {str(e)}'
            self.server.printLog(self.log)
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        try:
            head_str = head.decode('utf-8', errors='ignore')
            pattern = header + r': ([^\r\n]*)'
            match = re.search(pattern, head_str, re.IGNORECASE)
            if match:
                return match.group(1).strip()
            return ''
        except:
            return ''

    def connect_target(self, host):
        try:
            if ':' in host:
                host, port = host.rsplit(':', 1)
                port = int(port)
            else:
                port = PUERTO_SSH

            self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.target.settimeout(10)
            self.targetClosed = False
            self.target.connect((host, port))
            
        except Exception as e:
            raise Exception(f"Error conectando al destino {host}:{port} - {str(e)}")

    def method_CONNECT(self, path):
        self.log += f' - CONNECT {path}'
        
        try:
            self.connect_target(path)
            
            # Seleccionar respuesta apropiada basada en la solicitud
            response = get_response_for_request(self.client_buffer)
            self.client.send(response.encode())
            self.client_buffer = b''

            self.server.printLog(self.log)
            self.doCONNECT()
            
        except Exception as e:
            self.server.printLog(f"{self.log} - Error: {str(e)}")
            self.client.send(b'HTTP/1.1 503 Service Unavailable\r\n\r\n')

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        
        while True:
            count += 1
            try:
                recv, _, err = select.select(socs, [], socs, 3)
                if err:
                    error = True
                    break
                    
                if recv:
                    for in_ in recv:
                        try:
                            data = in_.recv(BUFLEN)
                            if data:
                                if in_ is self.target:
                                    self.client.send(data)
                                else:
                                    self.target.send(data)
                                count = 0
                            else:
                                error = True
                                break
                        except Exception as e:
                            error = True
                            break
                            
                if count >= TIMEOUT:
                    error = True
                    
            except Exception as e:
                error = True
                break
                
            if error:
                break

def print_usage():
    print('Uso: python3 PDirect.py <puerto>')
    print('     python3 PDirect.py 8080')

def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print("\n:-------Proxy Python Directo Universal-------:")
    print(f"Dirección de escucha: {LISTENING_ADDR}")
    print(f"Puerto de escucha: {port}")
    print(f"Host de destino: {DEFAULT_HOST}")
    print("Soporta códigos HTTP: 200, 101, 404, 500")
    print("Creado por: @JuanitoProSniff")
    print(":-------------------------------------------:\n")
    
    server = Server(LISTENING_ADDR, port)
    server.start()
    
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print('\nDeteniendo servidor...')
        server.close()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        try:
            LISTENING_PORT = int(sys.argv[1])
        except ValueError:
            print("Puerto inválido")
            print_usage()
            sys.exit(1)
    main()
PYTHON

    # Reemplazar el puerto en el archivo
    sed -i "s/PUERTO_SSH/$puetoantla/g" /etc/VPS-AGN/protocols/PDirect.py
    chmod +x /etc/VPS-AGN/protocols/PDirect.py

    echo -e "\033[1;32mProxy Directo Universal configurado correctamente\033[0m"
    echo -e "\033[1;33mCompatible con códigos HTTP: 200, 101, 404, 500\033[0m"
    
    screen -dmS pydic-"$porta_socket" python3 ${SCPinst}/PDirect.py "$porta_socket" && echo "$porta_socket Universal" >> /etc/VPS-AGN/PortPD.log
}

pid_kill() {
    [[ -z $1 ]] && return 1
    pids="$@"
    for pid in $(echo $pids); do
        kill -9 $pid &>/dev/null
    done
}

remove_fun() {
    echo -e "\033[1;31mDeteniendo todos los proxies Python\033[0m"
    msg -bar
    
    # Detener todos los procesos de proxy
    for process in "PPub.py" "PPriv.py" "PDirect.py" "POpen.py" "PGet.py" "scktcheck" "python.py"; do
        pidproxy=$(ps aux | grep "$process" | grep -v "grep" | awk '{print $2}')
        [[ ! -z $pidproxy ]] && pid_kill $pidproxy
    done
    
    # Limpiar pantallas screen
    screen -ls | grep -E "(sokz|getpy|screen|pydic)" | awk '{print $1}' | xargs -I {} screen -S {} -X quit 2>/dev/null
    
    echo -e "\033[1;91m  Todos los proxies han sido detenidos\033[0m"
    msg -bar
    rm -rf /etc/VPS-AGN/PortPD.log
    touch /etc/VPS-AGN/PortPD.log
    exit 0
}

iniciarsocks() {
    # Verificar estado de los proxies
    pidproxy=$(ps aux | grep -w "PPub.py" | grep -v "grep") && P1="\033[1;32m[ACTIVO]" || P1="\033[1;31m[INACTIVO]"
    pidproxy2=$(ps aux | grep -w "PPriv.py" | grep -v "grep") && P2="\033[1;32m[ACTIVO]" || P2="\033[1;31m[INACTIVO]"
    pidproxy3=$(ps aux | grep -w "PDirect.py" | grep -v "grep") && P3="\033[1;32m[ACTIVO]" || P3="\033[1;31m[INACTIVO]"
    pidproxy4=$(ps aux | grep -w "POpen.py" | grep -v "grep") && P4="\033[1;32m[ACTIVO]" || P4="\033[1;31m[INACTIVO]"
    pidproxy5=$(ps aux | grep "PGet.py" | grep -v "grep") && P5="\033[1;32m[ACTIVO]" || P5="\033[1;31m[INACTIVO]"
    pidproxy6=$(ps aux | grep "scktcheck" | grep -v "grep") && P6="\033[1;32m[ACTIVO]" || P6="\033[1;31m[INACTIVO]"
    
    msg -bar 
    msg -tit
    msg -ama "   INSTALADOR DE PROXIES VPS-AGN Por @JuanitoProSniff"
    msg -bar
    echo -e "${cor[4]} [1] $(msg -verm2 "==>>") \033[1;97mProxy Python SIMPLE\033[1;97m ------------- $P1"
    echo -e "${cor[4]} [2] $(msg -verm2 "==>>") \033[1;97mProxy Python SEGURO\033[1;97m ------------- $P2"
    echo -e "${cor[4]} [3] $(msg -verm2 "==>>") \033[1;97mProxy Python DIRECTO UNIVERSAL\033[1;97m --- $P3"
    echo -e "${cor[4]} [4] $(msg -verm2 "==>>") \033[1;97mProxy Python OPENVPN\033[1;97m ------------ $P4"
    echo -e "${cor[4]} [5] $(msg -verm2 "==>>") \033[1;97mProxy Python GETTUNEL\033[1;97m ----------- $P5"
    echo -e "${cor[4]} [6] $(msg -verm2 "==>>") \033[1;97mProxy Python TCP BYPASS\033[1;97m --------- $P6"
    echo -e "${cor[4]} [7] $(msg -verm2 "==>>") \033[1;97m ¡¡ DETENER TODOS LOS PROXIES !!"
    echo -e "$(msg -bar)\n${cor[4]} [0] $(msg -verm2 "==>>")  \e[97m\033[1;41m REGRESAR \033[1;37m"
    msg -bar
    IP=$(meu_ip)
    
    while [[ -z $portproxy || ! $portproxy =~ ^[0-7]$ ]]; do
        echo -ne "\033[1;37mElige una opción: \033[1;32m" && read portproxy
        tput cuu1 && tput dl1
    done
    
    case $portproxy in
        7) remove_fun;;
        0) return;;
    esac
    
    echo -e "\033[1;33m       Selecciona el Puerto del Proxy Principal"
    msg -bar
    porta_socket=
    while [[ -z $porta_socket || ! $porta_socket =~ ^[0-9]+$ ]] || [[ $porta_socket -lt 1 || $porta_socket -gt 65535 ]] || [[ ! -z $(mportas|grep -w $porta_socket) ]]; do
        echo -ne "\033[1;97mIngresa el puerto (1-65535): \033[1;92m" && read porta_socket
        if [[ ! -z $(mportas|grep -w $porta_socket) ]]; then
            echo -e "\033[1;31mPuerto $porta_socket ya está en uso. Elige otro.\033[0m"
            porta_socket=
        fi
        tput cuu1 && tput dl1
    done
    
    echo -e "\033[1;33mIngresa tu Mini-Banner personalizado"
    msg -bar
    echo -ne "\033[1;97mTexto del estado (texto plano o HTML):\n \033[1;37m" && read texto_soket
    [[ -z "$texto_soket" ]] && texto_soket="@JuanitoProSniff - Proxy Activo"
    
    msg -bar
    
    case $portproxy in
        1) screen -dmS screen python3 ${SCPinst}/PPub.py "$porta_socket" "$texto_soket";;
        2) screen -dmS screen python3 ${SCPinst}/PPriv.py "$porta_socket" "$texto_soket" "$IP";;
        3) PythonDic_fun;;
        4) screen -dmS screen python3 ${SCPinst}/POpen.py "$porta_socket" "$texto_soket";;
        5) gettunel_fun "$porta_socket";;
        6) tcpbypass_fun "$porta_socket" "$texto_soket";;
    esac
    
    sleep 2
    echo -e "\033[1;92mProcedimiento completado exitosamente\033[0m"
    echo -e "\033[1;36mProxy iniciado en puerto: $porta_socket\033[0m"
    echo -e "\033[1;36mIP del servidor: $(meu_ip)\033[0m"
    msg -bar
}

iniciarsocks