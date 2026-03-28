#!/bin/bash
# mod_ssh.sh - MSY VPN v104+ (FIXED v2)
# SSH: OpenSSH :22 + Dropbear legacy :143
#
# FIXES v2:
#   - BUG PRINCIPAL: make -j$(nproc) causa race condition en libtomcrypt/libtommath
#     dentro del source de Dropbear 2016. Con compilación paralela, los workers
#     arrancan a compilar los .c antes de que los headers de la sublib estén listos
#     → "tomcrypt.h: No such file or directory"
#     SOLUCIÓN: compilar sublibs primero en -j1, luego el resto en paralelo.
#
#   - "Illegal packet size! (1231976033)" = 0x496E7421 = bytes "Int!"
#     Son los primeros bytes de una petición HTTP llegando al puerto SSH.
#     NO es bug de Dropbear/OpenSSH — es tráfico no-SSH en el puerto 143.
#     SOLUCIÓN: wrapper socat que detecta protocolo antes de pasar al daemon.
#
#   - CFLAGS correctos para GCC 7→14 (Ubuntu 18/20/22/24/25)
#   - Fallback triple: 2016 → 2019 → OpenSSH

# ============================================================
# DETECCIÓN DE ENTORNO
# ============================================================
OS_VER=$(lsb_release -rs 2>/dev/null \
    || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null \
    || echo "0")
OS_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
ARCH=$(uname -m)
GCC_VER=$(gcc -dumpversion 2>/dev/null | cut -d. -f1); GCC_VER=${GCC_VER:-0}

echo "=========================================="
echo " SSH/Dropbear Setup"
echo " OS: Ubuntu $OS_VER | Arch: $ARCH | GCC: $GCC_VER"
echo "=========================================="

# ============================================================
# DEPENDENCIAS
# ============================================================
echo ""
echo "Verificando dependencias..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    gcc make wget libc6-dev libssl-dev socat 2>/dev/null
echo "✓ Dependencias OK"

# ============================================================
# OPENSSH (PUERTO 22)
# ============================================================
echo ""
echo "Configurando OpenSSH en puerto 22..."

cat > /etc/ssh/banner.txt <<'EOF'
═══════════════════════════
t.me/FREEINTERNETVPNMSY
═══════════════════════════
EOF

cat > /etc/ssh/sshd_config <<'EOF'
Port 22
AddressFamily inet
ListenAddress 0.0.0.0
Banner /etc/ssh/banner.txt
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
PrintMotd no
PrintLastLog yes
X11Forwarding yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 120
ClientAliveCountMax 3
TCPKeepAlive yes
MaxStartups 100:30:200
MaxSessions 100
Compression no
EOF

systemctl enable ssh >/dev/null 2>&1
systemctl restart ssh
systemctl is-active --quiet ssh \
    && echo "✓ OpenSSH activo en 0.0.0.0:22 (solo IPv4)" \
    || echo "✗ OpenSSH no inició"

# ============================================================
# CFLAGS POR VERSIÓN DE GCC
# ============================================================
if   [ "$GCC_VER" -ge 14 ] 2>/dev/null; then
    COMPAT_CFLAGS="-w -fcommon -std=gnu11"
    echo "  GCC $GCC_VER — CFLAGS máximos (GCC 14)"
elif [ "$GCC_VER" -ge 12 ] 2>/dev/null; then
    COMPAT_CFLAGS="-w -fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-pointer-types"
    echo "  GCC $GCC_VER — CFLAGS GCC 12/13"
else
    COMPAT_CFLAGS="-w -fcommon"
    echo "  GCC $GCC_VER — CFLAGS estándar"
fi

# ============================================================
# FUNCIÓN: compilar Dropbear
#
# FIX CRÍTICO — race condition en libtomcrypt/libtommath:
#   Con -j$(nproc), make lanza todos los compiladores en paralelo.
#   libtomcrypt genera headers internos (tomcrypt.h) durante su
#   propio proceso de build. Si otro worker ya empezó a compilar
#   los .c que necesitan ese header → "No such file or directory".
#
#   SOLUCIÓN en 3 pasos:
#     1. make -j1 libtommath   → sin paralelismo (lib pequeña, rápida)
#     2. make -j1 libtomcrypt  → sin paralelismo, necesita paso 1
#     3. make -j$(nproc) resto → ahora sí en paralelo, las libs ya están
# ============================================================
compilar_dropbear() {
    local VER=$1
    local URL=$2
    local PREFIX=$3
    local TARBALL="dropbear-${VER}.tar.bz2"
    local SRCDIR="/usr/src/dropbear-${VER}"
    local SRVRBIN="${PREFIX}/sbin/dropbear"
    local LOGFILE="/tmp/dropbear_build_${VER}.log"

    echo ""
    echo "  ── Compilando Dropbear $VER ──"
    echo "  Prefix: $PREFIX"
    > "$LOGFILE"

    cd /usr/src

    # ── Descargar ──
    if [ ! -f "$TARBALL" ] || [ ! -s "$TARBALL" ]; then
        echo "  Descargando $TARBALL..."
        wget -q --timeout=60 -O "$TARBALL" "$URL" 2>/dev/null
        if [ ! -s "$TARBALL" ]; then
            echo "  Mirror 2..."
            wget -q --timeout=60 -O "$TARBALL" \
                "https://dropbear.nl/mirror/releases/$TARBALL" 2>/dev/null
        fi
        if [ ! -s "$TARBALL" ]; then
            echo "  ✗ No se pudo descargar Dropbear $VER"
            return 1
        fi
    fi

    # ── Extraer (siempre limpio para evitar builds sucios) ──
    rm -rf "$SRCDIR" 2>/dev/null
    tar xjf "$TARBALL" -C /usr/src 2>/dev/null
    if [ ! -d "$SRCDIR" ]; then
        echo "  ✗ Error extrayendo $TARBALL"
        return 1
    fi

    cd "$SRCDIR"

    # ── Personalizar identificador SSH ──
    for f in sysoptions.h default_options.h options.h; do
        [ -f "$f" ] && grep -q "LOCAL_IDENT" "$f" && \
            sed -i 's|#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' "$f"
    done
    if grep -rq "IDENT_VERSION_PART" . 2>/dev/null; then
        find . -name "*.h" | xargs grep -l "IDENT_VERSION_PART" 2>/dev/null | while read hf; do
            sed -i 's|#define IDENT_VERSION_PART.*|#define IDENT_VERSION_PART "ByJuanitoProSniff"|' "$hf"
        done
    fi

    # ── Configurar ──
    export CFLAGS="$COMPAT_CFLAGS"
    ./configure \
        --prefix="$PREFIX" \
        --disable-zlib \
        --disable-wtmp \
        --disable-lastlog \
        >/dev/null 2>&1

    # ── PASO 1: libtommath solo, sin paralelismo ──
    echo "  [1/3] libtommath..."
    if [ -d libtommath ]; then
        if ! make -C libtommath -j1 CFLAGS="$COMPAT_CFLAGS" >> "$LOGFILE" 2>&1; then
            echo "  ✗ libtommath falló — log: $LOGFILE"
            tail -5 "$LOGFILE"
            unset CFLAGS; cd /root; return 1
        fi
        echo "  ✓ libtommath OK"
    fi

    # ── PASO 2: libtomcrypt solo, sin paralelismo ──
    echo "  [2/3] libtomcrypt..."
    if [ -d libtomcrypt ]; then
        if ! make -C libtomcrypt -j1 CFLAGS="$COMPAT_CFLAGS" >> "$LOGFILE" 2>&1; then
            echo "  ✗ libtomcrypt falló — log: $LOGFILE"
            tail -5 "$LOGFILE"
            unset CFLAGS; cd /root; return 1
        fi
        echo "  ✓ libtomcrypt OK"
    fi

    # ── PASO 3: build principal, ahora en paralelo ──
    echo "  [3/3] Compilando dropbear... (1-3 min)"
    if ! make -j$(nproc) \
            PROGRAMS="dropbear dropbearkey" \
            CFLAGS="$COMPAT_CFLAGS" \
            >> "$LOGFILE" 2>&1; then
        echo "  ✗ make falló — últimas líneas:"
        tail -10 "$LOGFILE"
        unset CFLAGS; cd /root; return 1
    fi

    make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1
    unset CFLAGS

    if [ ! -f "$SRVRBIN" ]; then
        echo "  ✗ Binario no encontrado: $SRVRBIN"
        cd /root; return 1
    fi

    echo "  ✓ Dropbear $VER compilado OK"
    cd /root
    return 0
}

# ============================================================
# COMPILAR AMBAS VERSIONES
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " Compilando Dropbear 2016.74..."
echo "══════════════════════════════════════════"
compilar_dropbear "2016.74" \
    "https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2" \
    "/opt/dropbear-2016"
DB2016_OK=0; [ -f /opt/dropbear-2016/sbin/dropbear ] && DB2016_OK=1

echo ""
echo "══════════════════════════════════════════"
echo " Compilando Dropbear 2019.78..."
echo "══════════════════════════════════════════"
compilar_dropbear "2019.78" \
    "https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2" \
    "/opt/dropbear-2019"
DB2019_OK=0; [ -f /opt/dropbear-2019/sbin/dropbear ] && DB2019_OK=1

echo ""
echo "══════════════════════════════════════════"
echo " Resultado compilaciones:"
[ "$DB2016_OK" = "1" ] && echo "  ✓ Dropbear 2016.74" || echo "  ✗ Dropbear 2016.74 falló"
[ "$DB2019_OK" = "1" ] && echo "  ✓ Dropbear 2019.78" || echo "  ✗ Dropbear 2019.78 falló"
echo "══════════════════════════════════════════"

# ============================================================
# SELECCIONAR VERSIÓN ACTIVA
# ============================================================
ACTIVE_DB_BIN=""; ACTIVE_DB_VER=""; ACTIVE_DB_KEYBIN=""

if [ "$DB2016_OK" = "1" ]; then
    ACTIVE_DB_BIN="/opt/dropbear-2016/sbin/dropbear"
    ACTIVE_DB_KEYBIN="/opt/dropbear-2016/bin/dropbearkey"
    ACTIVE_DB_VER="2016"
elif [ "$DB2019_OK" = "1" ]; then
    ACTIVE_DB_BIN="/opt/dropbear-2019/sbin/dropbear"
    ACTIVE_DB_KEYBIN="/opt/dropbear-2019/bin/dropbearkey"
    ACTIVE_DB_VER="2019"
fi

# ============================================================
# GENERAR LLAVES
# ============================================================
mkdir -p /etc/dropbear-legacy
cat > /etc/dropbear-legacy/banner.txt <<'BANEOF'
t.me/FREEINTERNETVPNMSY
BANEOF

if [ -n "$ACTIVE_DB_KEYBIN" ]; then
    echo "Generando llaves Dropbear..."
    [ ! -f /etc/dropbear-legacy/dropbear_rsa_host_key ] && \
        "$ACTIVE_DB_KEYBIN" -t rsa -f /etc/dropbear-legacy/dropbear_rsa_host_key -s 2048 >/dev/null 2>&1 \
        && echo "  ✓ Llave RSA generada"
    [ ! -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ] && \
        "$ACTIVE_DB_KEYBIN" -t ecdsa -f /etc/dropbear-legacy/dropbear_ecdsa_host_key >/dev/null 2>&1 \
        && echo "  ✓ Llave ECDSA generada"
fi

# ============================================================
# WRAPPER ANTI "Illegal packet size"
#
# El error 1231976033 = 0x496E7421 = ASCII "Int!" son los primeros
# 4 bytes de tráfico HTTP llegando al puerto SSH. Dropbear/OpenSSH
# lo reportan y cierran la conexión. Solución: un wrapper en el
# puerto público 143 que detecta si viene SSH o HTTP:
#
#   Puerto público  :143  ← socat wrapper (detecta protocolo)
#   Puerto interno  :1143 ← Dropbear real (solo recibe SSH limpio)
#
# El wrapper lee la primera línea del cliente:
#   "SSH-*"     → es conexión SSH real  → reenviar a :1143
#   "CONNECT *" → es proxy HTTP CONNECT → responder 200 y tunelizar
#   otro        → tráfico basura        → cerrar limpiamente
# ============================================================
instalar_wrapper_143() {
    echo ""
    echo "Instalando wrapper de protocolo en :143..."

    cat > /usr/local/bin/msy-ssh-wrapper.sh <<'WRAPPER'
#!/bin/bash
# Wrapper MSY VPN - detección de protocolo en puerto 143
# Dropbear escucha en 127.0.0.1:1143 (solo recibe SSH limpio)

read -t 10 -r PRIMERA_LINEA

if [[ "$PRIMERA_LINEA" == SSH-* ]]; then
    # Conexión SSH legítima: pasar a Dropbear con la línea que ya leímos
    { printf '%s\r\n' "$PRIMERA_LINEA"; cat; } | socat - TCP:127.0.0.1:1143
elif [[ "$PRIMERA_LINEA" == CONNECT\ * ]]; then
    # Proxy HTTP CONNECT: responder 200 y tunelizar
    printf 'HTTP/1.0 200 Connection established\r\n\r\n'
    socat - TCP:127.0.0.1:1143
elif [[ -z "$PRIMERA_LINEA" ]]; then
    # Sin datos (timeout o conexión vacía): pasar directo
    socat - TCP:127.0.0.1:1143
else
    # Tráfico no-SSH (GET, POST, escáneres, etc): cerrar limpiamente
    printf 'HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n'
fi
WRAPPER
    chmod +x /usr/local/bin/msy-ssh-wrapper.sh

    cat > /etc/systemd/system/msy-ssh-wrapper.service <<'WSVC'
[Unit]
Description=MSY SSH Protocol Wrapper :143
After=network.target dropbear-legacy.service

[Service]
Type=simple
ExecStart=/usr/bin/socat \
    TCP-LISTEN:143,reuseaddr,fork,backlog=128 \
    EXEC:/usr/local/bin/msy-ssh-wrapper.sh
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
WSVC

    systemctl daemon-reload
    systemctl enable msy-ssh-wrapper >/dev/null 2>&1
    echo "  ✓ Wrapper instalado"
}

# ============================================================
# FUNCIÓN: generar servicio systemd para Dropbear
# Puerto por defecto: 1143 (interno, el wrapper expone :143)
# ============================================================
generar_servicio_dropbear() {
    local BIN=$1
    local VER=$2
    local PUERTO=${3:-1143}
    local BIND=${4:-127.0.0.1}   # interno=127.0.0.1, directo=0.0.0.0

    local KEY_FLAGS=""
    [ -f /etc/dropbear-legacy/dropbear_rsa_host_key ]   && KEY_FLAGS="$KEY_FLAGS -r /etc/dropbear-legacy/dropbear_rsa_host_key"
    [ -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ] && KEY_FLAGS="$KEY_FLAGS -r /etc/dropbear-legacy/dropbear_ecdsa_host_key"

    cat > /etc/systemd/system/dropbear-legacy.service <<DBSVC
[Unit]
Description=Dropbear SSH $VER - Puerto $PUERTO (MSY VPN)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=${BIN} -F -E \\
    -p ${BIND}:${PUERTO} \\
    ${KEY_FLAGS} \\
    -b /etc/dropbear-legacy/banner.txt \\
    -K 120 -I 600
Restart=always
RestartSec=3
KillMode=process
StandardOutput=null
StandardError=null
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
DBSVC

    systemctl daemon-reload
    systemctl enable dropbear-legacy >/dev/null 2>&1
}

# ============================================================
# ARRANCAR DROPBEAR + WRAPPER
# ============================================================
_liberar_puertos() {
    systemctl stop msy-ssh-wrapper  2>/dev/null
    systemctl stop dropbear-legacy  2>/dev/null
    pkill -9 -f "dropbear.*143"     2>/dev/null
    pkill -9 -f "socat.*143"        2>/dev/null
    fuser -k 143/tcp  2>/dev/null
    fuser -k 1143/tcp 2>/dev/null
    sleep 1
}

if [ -n "$ACTIVE_DB_BIN" ]; then
    echo ""
    echo "Activando Dropbear $ACTIVE_DB_VER + wrapper en :143..."
    _liberar_puertos

    # Dropbear en puerto interno 1143 (solo loopback)
    generar_servicio_dropbear "$ACTIVE_DB_BIN" "$ACTIVE_DB_VER" "1143" "127.0.0.1"
    systemctl restart dropbear-legacy
    sleep 1

    if systemctl is-active --quiet dropbear-legacy; then
        echo "✓ Dropbear $ACTIVE_DB_VER activo en 127.0.0.1:1143"

        # Wrapper en :143
        instalar_wrapper_143
        systemctl restart msy-ssh-wrapper
        sleep 1

        if systemctl is-active --quiet msy-ssh-wrapper; then
            echo "✓ Wrapper activo en 0.0.0.0:143"
            echo "  → cliente:143 → wrapper → Dropbear:1143 (sin Illegal packet size)"
        else
            # socat no disponible o fallo: Dropbear directo en :143
            echo "⚠ Wrapper falló (socat?). Dropbear directo en :143..."
            _liberar_puertos
            generar_servicio_dropbear "$ACTIVE_DB_BIN" "$ACTIVE_DB_VER" "143" "0.0.0.0"
            systemctl restart dropbear-legacy
            sleep 2
            systemctl is-active --quiet dropbear-legacy \
                && echo "✓ Dropbear $ACTIVE_DB_VER activo en 0.0.0.0:143 (directo)" \
                || echo "✗ Dropbear no inició"
        fi

    else
        echo "⚠ Dropbear $ACTIVE_DB_VER no inició:"
        journalctl -u dropbear-legacy --no-pager -n 8 2>/dev/null

        # Probar versión alternativa
        if [ "$ACTIVE_DB_VER" = "2016" ] && [ "$DB2019_OK" = "1" ]; then
            echo "  Intentando Dropbear 2019..."
            fuser -k 1143/tcp 2>/dev/null
            generar_servicio_dropbear "/opt/dropbear-2019/sbin/dropbear" "2019" "1143" "127.0.0.1"
            systemctl restart dropbear-legacy; sleep 2
            if systemctl is-active --quiet dropbear-legacy; then
                echo "✓ Dropbear 2019 activo"
                ACTIVE_DB_VER="2019"; ACTIVE_DB_BIN="/opt/dropbear-2019/sbin/dropbear"
                instalar_wrapper_143
                systemctl restart msy-ssh-wrapper
            fi
        fi

        # Fallback final: OpenSSH en :143
        if ! systemctl is-active --quiet dropbear-legacy; then
            echo "⚠ Fallback: OpenSSH en :143"
            fuser -k 143/tcp 2>/dev/null
            grep -q "^Port 143" /etc/ssh/sshd_config || \
                sed -i '/^Port 22/a Port 143' /etc/ssh/sshd_config
            systemctl restart ssh
            ACTIVE_DB_VER="ssh_fallback"
        fi
    fi

else
    # Ningún Dropbear compiló
    echo "⚠ Sin Dropbear — OpenSSH fallback en :143"
    _liberar_puertos
    grep -q "^Port 143" /etc/ssh/sshd_config || \
        sed -i '/^Port 22/a Port 143' /etc/ssh/sshd_config
    systemctl restart ssh
    ACTIVE_DB_VER="ssh_fallback"
fi

# ============================================================
# GUARDAR ESTADO
# ============================================================
echo "$ACTIVE_DB_VER"  > /etc/dropbear-legacy/active_version.txt
echo "$ACTIVE_DB_BIN"  > /etc/dropbear-legacy/active_bin.txt
echo "$DB2016_OK"      > /etc/dropbear-legacy/has_2016.txt
echo "$DB2019_OK"      > /etc/dropbear-legacy/has_2019.txt

# ============================================================
# USUARIO INICIAL VPN
# ============================================================
echo ""
echo "Creando usuario VPN inicial..."
USER_VPN="vpnuser"
PASS_VPN="msy$(openssl rand -hex 4)"

id "$USER_VPN" &>/dev/null && userdel -r "$USER_VPN" 2>/dev/null
useradd -m -s /bin/bash "$USER_VPN"
echo "$USER_VPN:$PASS_VPN" | chpasswd

mkdir -p /etc/ssh-vpn/users
cat > /etc/ssh-vpn/users/$USER_VPN.txt <<USEREOF
Usuario: $USER_VPN
Contraseña: $PASS_VPN
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: Ilimitado
Estado: Activo
Dropbear activo: $ACTIVE_DB_VER
USEREOF

echo "✓ Usuario: $USER_VPN / $PASS_VPN"
export USER_VPN PASS_VPN ACTIVE_DB_VER
