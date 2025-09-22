# MSY-VPN Script Manager

```
* MSY-VPN (Version mejorada del VPS-MX 8.5x)
```

![logo](https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/VPS-AGN.png)

## SCRIPT MSY-VPN ® VPS Script Manager

ESTE ES UN SCRIPT PARA LA GESTIÓN DE CUENTAS DE TIPO:

- **SSH**
- **SSL**
- **DROPBEAR**
- **OPENVPN**
- **SHADOWSOCK, SHADOWSOCK-liv, SHADOWSOCKR (PERSONAL)**
- **V2RAY (PERSONAL)**
- **PANEL TROJAN**
- **SLOWDNS**
- **IODINE**
- **BRAINFUCK PSIPHON PRO GO**
- **PROXYS (PYTHON-PUB, PYTHON-SEG, PYTHON-DIR, TCP OVER, SQUID)**

### MONITOREO DE:

- **USUARIOS SSH/DROPBEAR/SSL/OPENVPN**
- **CLIMA**
- **EXPIRACIÓN**
- **MONITOR DE PROTOCOLOS**

### BOT MANAGER:

- **CONTROLA EL USO DE TUS CUENTAS SSH DESDE UN BOT DE TELEGRAM**
  (AGREGAR, ELIMINAR, RENOVAR, VER CONECTADOS, TUS SERVICIOS VPS, INFO DE CUENTA, ETC.)
- **RECIBE NOTIFICACIONES CON BOT ESPECIAL**

## :heavy_exclamation_mark: Requisitos

* Sistema operativo basado en Linux (Ubuntu)
* **Ubuntu 18.04 Server x86_64** ✅
* **Ubuntu 20.04 Server x86_64** ✅ (Recomendado)
* **Ubuntu 22.04 Server x86_64** ✅
* **Ubuntu 24.04 Server x86_64** ✅
* **Ubuntu 24.10 Server x86_64** ✅
* Se recomienda usar una distribución nueva o formateada

## Instalación

### Instalación Rápida (Recomendado)
```bash
wget https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install-without-key.sh && chmod +x install-without-key.sh && ./install-without-key.sh --start
```

### Instalación Paso a Paso
```bash
rm -rf install-without-key.sh
apt update && apt install curl wget -y
wget https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install-without-key.sh
chmod 777 install-without-key.sh
./install-without-key.sh --start
```

## Comandos de Acceso

Una vez instalado, puedes acceder al panel usando cualquiera de estos comandos:

```bash
menu
msyvpn
VPSAGN
```

## Mejoras Implementadas

### ✅ Compatibilidad Extendida
- **Soporte completo para Ubuntu 18.04 a 25.x**
- **Detección automática de versión del sistema**
- **Configuración automática de repositorios según la versión**

### ✅ Gestión Mejorada de Dependencias
- **Instalación inteligente de paquetes**
- **Manejo de errores mejorado**
- **Instalación de Node.js LTS automática**
- **Compatibilidad con paquetes modernos**

### ✅ Detección de Red Mejorada
- **Detección automática de IP externa**
- **Múltiples métodos de detección de interfaz**
- **Mejor compatibilidad con diferentes configuraciones de red**

### ✅ Configuración SSH Mejorada
- **Configuración automática según la versión de Ubuntu**
- **Compatibilidad con Ubuntu 22.04+ y sus nuevos requisitos SSH**
- **Configuración de systemd mejorada**

### ✅ Interfaz de Usuario Mejorada
- **Mensajes en español**
- **Mejor feedback durante la instalación**
- **Barra de progreso mejorada**

## Características Técnicas

### Protocolos Soportados
- **SSH/SSL:** Conexiones seguras con cifrado
- **OpenVPN:** VPN de código abierto
- **V2Ray:** Herramienta de proxy avanzada
- **Trojan:** Proxy no detectable
- **ShadowSocks:** Proxy SOCKS5 seguro
- **SlowDNS:** Túnel DNS
- **Squid Proxy:** Servidor proxy HTTP

### Bot de Telegram
- **Gestión completa de usuarios**
- **Notificaciones en tiempo real**
- **Control remoto del servidor**
- **Estadísticas de uso**

## Solución de Problemas

### Problemas Comunes

#### Error de repositorios en Ubuntu 22.04+
```bash
sudo apt update --fix-missing
sudo dpkg --configure -a
sudo apt install -f
```

#### Error de permisos SSH
```bash
sudo chmod 600 /etc/ssh/ssh_host_*
sudo systemctl restart ssh
```

#### Problemas con Node.js
```bash
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Reinstalación Limpia
Si necesitas reinstalar completamente:
```bash
sudo rm -rf /etc/VPS-AGN
sudo rm -rf /usr/bin/menu /usr/bin/msyvpn /usr/bin/VPSAGN
wget https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install-without-key.sh
chmod +x install-without-key.sh
./install-without-key.sh --start
```

## Estructura del Proyecto

```
script_msyvpn/
├── installer/
│   └── install-without-key.sh      # Script de instalación principal
├── SCRIPT-v8.5x/
│   ├── VPS-AGN.tar.xz             # Archivos principales del script
│   └── Version                     # Archivo de versión
├── LINKS-LIBRARIES/
│   ├── SPR.sh                     # Soporte online
│   ├── monitor.sh                 # Monitor del sistema
│   └── resetsshdrop               # Reset SSH/Dropbear
└── README.md                      # Documentación
```

## Configuración Post-Instalación

### 1. Configurar Bot de Telegram
```bash
menu
# Seleccionar opción de Bot de Telegram
# Seguir las instrucciones para configurar el token
```

### 2. Configurar Protocolos
```bash
menu
# Seleccionar el protocolo deseado (V2Ray, Trojan, etc.)
# Seguir el asistente de configuración
```

### 3. Gestión de Usuarios
```bash
menu
# Ir a gestión de usuarios
# Crear, editar o eliminar usuarios según necesites
```

## Actualizaciones

Para mantener el script actualizado:

```bash
menu
# Buscar opción de actualización en el menú principal
# O ejecutar manualmente:
cd /etc/VPS-AGN && wget https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/SCRIPT-v8.5x/Version -O /etc/versin_script_new
```

## Logs y Monitoreo

### Ubicación de Logs
- **Logs del sistema:** `/var/log/`
- **Logs del script:** `/etc/VPS-AGN/`
- **Logs de conexiones:** `/usr/share/mediaptre/local/log/`

### Monitoreo en Tiempo Real
```bash
monitor.sh  # Si está disponible
# O desde el menú principal
menu
```

## Seguridad

### Recomendaciones de Seguridad
1. **Cambiar puertos por defecto**
2. **Usar contraseñas fuertes**
3. **Configurar fail2ban**
4. **Mantener el sistema actualizado**
5. **Revisar logs regularmente**

### Configuración de Firewall
```bash
ufw enable
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 8080/tcp  # Proxy
# Agregar más puertos según necesites
```

## Contribuir

### Cómo Contribuir
1. **Fork** el repositorio
2. **Crea** una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. **Push** a la rama (`git push origin feature/AmazingFeature`)
5. **Abre** un Pull Request

### Reportar Bugs
Usa el sistema de issues de GitHub para reportar bugs o solicitar nuevas características.

## Licencia y Créditos

### 📧 Contacto y Soporte
<ul>
 <li><strong>GitHub:</strong> https://github.com/juanitoprosniff/script_msyvpn</li>
 <li><strong>Telegram:</strong> @TuUsuarioTelegram</li>
 <li><strong>Email:</strong> tu@email.com</li>
</ul>

### 🏆 Créditos Originales
1. [@Kalix1 - Desarrollador original de VPS-MX](https://github.com/VPS-MX)
2. [@khaledagn - Versión en inglés VPS-AGN](https://github.com/khaledagn/VPS-AGN_English_Official)
3. [@Rufu99 - Contribuidor](https://github.com/rudi9999)
4. [Casita Dev Team - Contribuidor](https://github.com/lacasitamx)
5. [illuminati Dev Team - Contribuidor](https://github.com/AAAAAEXQOSyIpN2JZ0ehUQ)

### 📝 Changelog

#### Versión 8.5x (Actual)
- ✅ Soporte completo Ubuntu 18.04-25.x
- ✅ Instalación mejorada de dependencias
- ✅ Detección automática de red
- ✅ Configuración SSH optimizada
- ✅ Interfaz en español
- ✅ Mejor manejo de errores
- ✅ Compatibilidad con systemd moderno

#### Próximas Características
- 🔄 Instalación vía Docker
- 🔄 Interfaz web moderna
- 🔄 API REST
- 🔄 Soporte para más protocolos
- 🔄 Dashboard mejorado

---

## ⚠️ Disclaimer

Este script es para uso educativo y administrativo. El usuario es responsable del cumplimiento de las leyes locales y términos de servicio de su proveedor de hosting. Úsalo bajo tu propia responsabilidad.

---

**¿Encontraste útil este proyecto? ¡Dale una ⭐ en GitHub!**
