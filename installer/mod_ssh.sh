#!/bin/bash
# mod_ssh.sh - MSY VPN v105
# Dropbear 2016.74 → puerto 143 (OBLIGATORIO, prioridad máxima)
# Dropbear 2019.78 → puerto 142 (secundario)
# OpenSSH          → puerto 22
#
# Compatibilidad: Ubuntu 18 / 20 / 22 / 24 (GCC 7–13)
# Se compilan ambas versiones desde fuente — sin depender de apt.

# ============================================================
# DETECCIÓN DE ENTORNO
# ============================================================
OS_VER=$(lsb_release -rs 2>/dev/null \
    || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null \
    || echo "0")
OS_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
ARCH=$(uname -m)

echo "=========================================="
echo " SSH/Dropbear Setup - MSY VPN v105"
echo " OS: Ubuntu $OS_VER | Arch: $ARCH"
echo " 2016.74 → :143 (principal)"
echo " 2019.78 → :142 (secundario)"
echo "=========================================="

# ============================================================
# DEPENDENCIAS
# ============================================================
echo ""
echo "Instalando dependencias de compilación..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    wget curl socat openssh-server \
    gcc make libc6-dev zlib1g-dev \
    2>/dev/null
echo "✓ Dependencias OK"

# ============================================================
# FLAGS DE COMPILACIÓN COMPATIBLES CON GCC MODERNO
# GCC 10+ en Ubuntu 20/22 rechaza código C antiguo de Dropbear 2016
# sin estos flags. Son obligatorios para que compile sin errores.
# ============================================================
GCC_VER=$(gcc -dumpversion 2>/dev/null | cut -d. -f1)
GCC_VER=${GCC_VER:-0}

# Flags base para Dropbear 2016 (código C89/C99 antiguo)
if [ "$GCC_VER" -ge 10 ] 2>/dev/null; then
    # Ubuntu 20/22/24 — GCC 10, 11, 12, 13
    CFLAGS_2016="-w -fcommon \
        -Wno-error=implicit-function-declaration \
        -Wno-error=implicit-int \
        -Wno-error=int-conversion \
        -Wno-error=incompatible-pointer-types \
        -Wno-error=deprecated-declarations"
else
    # Ubuntu 18 — GCC 7/8/9
    CFLAGS_2016="-w -fcommon"
fi

# Flags para Dropbear 2019 (código más limpio, menos flags necesarios)
if [ "$GCC_VER" -ge 12 ] 2>/dev/null; then
    CFLAGS_2019="-w -fcommon -Wno-error=deprecated-declarations"
else
    CFLAGS_2019="-w -fcommon"
fi

echo "  GCC: $GCC_VER → flags OK"

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

# Limpiar configuración previa limpia
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
    && echo "✓ OpenSSH activo en 0.0.0.0:22" \
    || echo "✗ OpenSSH no inició"

# ============================================================
# DIRECTORIOS
# ============================================================
DB_DIR="/opt/dropbear-bins"
DB_KEYS="/etc/dropbear-legacy"
mkdir -p "$DB_DIR" "$DB_KEYS"

cat > "$DB_KEYS/banner.txt" <<'BANEOF'
t.me/FREEINTERNETVPNMSY
BANEOF

# ============================================================
# FUNCIÓN: COMPILAR DROPBEAR DESDE FUENTE
#
# Parámetros:
#   $1 = versión corta (ej: "2016.74")
#   $2 = URL del tarball
#   $3 = prefijo de instalación (ej: "/opt/dropbear-2016")
#   $4 = CFLAGS a usar
#   $5 = nombre del binario destino en DB_DIR (ej: "dropbear-2016.74")
# ============================================================
_compilar_dropbear() {
    local VER="$1"
    local URL="$2"
    local PREFIX="$3"
    local CF="$4"
    local DEST_BIN="$DB_DIR/$5"
    local DEST_KEY="$DB_DIR/${5/dropbear/dropbearkey}"
    local TB="dropbear-${VER}.tar.bz2"

    echo ""
    echo "══════════════════════════════════════════"
    echo " Compilando Dropbear $VER..."
    echo " (necesario para Ubuntu $OS_VER con GCC $GCC_VER)"
    echo "══════════════════════════════════════════"

    # Descargar (con espejo alternativo)
    cd /usr/src
    if [ ! -s "$TB" ]; then
        wget -q --timeout=90 -O "$TB" "$URL" 2>/dev/null \
        || wget -q --timeout=90 -O "$TB" \
            "https://dropbear.nl/mirror/releases/$TB" 2>/dev/null
    fi

    if [ ! -s "$TB" ]; then
        echo "  ✗ No se pudo descargar dropbear-${VER}"
        return 1
    fi

    rm -rf "dropbear-${VER}"
    tar xjf "$TB" -C /usr/src 2>/dev/null
    cd "/usr/src/dropbear-${VER}" || { echo "  ✗ Error extrayendo tarball"; return 1; }

    # Personalizar banner SSH
    for f in sysoptions.h default_options.h options.h; do
        [ -f "$f" ] && grep -q "LOCAL_IDENT" "$f" && \
            sed -i 's|#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' "$f"
    done

    # Configurar
    export CFLAGS="$CF"
    ./configure --prefix="$PREFIX" \
        --disable-zlib --disable-wtmp --disable-lastlog \
        >/dev/null 2>&1

    # Para 2016: compilar sublibs primero en -j1 para evitar race conditions
    # El race condition entre libtommath y libtomcrypt afecta solo a 2016
    if echo "$VER" | grep -q "^2016"; then
        echo "  Compilando sublibs en -j1 (necesario para 2016)..."
        [ -d libtommath  ] && make -C libtommath  -j1 CFLAGS="$CF" >/dev/null 2>&1
        [ -d libtomcrypt ] && make -C libtomcrypt -j1 CFLAGS="$CF" >/dev/null 2>&1
        echo "  Compilando dropbear 2016..."
        make -j$(nproc) PROGRAMS="dropbear dropbearkey" CFLAGS="$CF" >/tmp/db_compile_${VER}.log 2>&1
    else
        echo "  Compilando dropbear 2019..."
        make -j$(nproc) PROGRAMS="dropbear dropbearkey" CFLAGS="$CF" >/tmp/db_compile_${VER}.log 2>&1
    fi

    if make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1 \
            && [ -x "${PREFIX}/sbin/dropbear" ]; then
        cp "${PREFIX}/sbin/dropbear"   "$DEST_BIN"
        cp "${PREFIX}/bin/dropbearkey" "$DEST_KEY" 2>/dev/null
        chmod +x "$DEST_BIN" "$DEST_KEY" 2>/dev/null
        unset CFLAGS
        echo "  ✓ Dropbear $VER compilado correctamente"
        cd /root
        return 0
    else
        unset CFLAGS
        echo "  ✗ Compilación fallida — últimas líneas del log:"
        tail -5 /tmp/db_compile_${VER}.log 2>/dev/null
        cd /root
        return 1
    fi
}

# ============================================================
# COMPILAR DROPBEAR 2016.74 (OBLIGATORIO - PUERTO 143)
# Esta es la versión que el usuario REQUIERE como principal.
# Se intenta SIEMPRE, independientemente de qué haya en apt.
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " [1/2] Dropbear 2016.74 → Puerto 143 (PRINCIPAL)"
echo "══════════════════════════════════════════"

NEED_COMPILE_2016=true
if [ -x "$DB_DIR/dropbear-2016.74" ]; then
    echo "  ✓ Ya compilado, omitiendo"
    NEED_COMPILE_2016=false
fi

if $NEED_COMPILE_2016; then
    _compilar_dropbear \
        "2016.74" \
        "https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2" \
        "/opt/dropbear-2016" \
        "$CFLAGS_2016" \
        "dropbear-2016.74"
fi

if [ -x "$DB_DIR/dropbear-2016.74" ]; then
    echo "  ✓ Dropbear 2016.74 disponible → :143"
    echo "1" > "$DB_KEYS/has_2016.txt"
else
    echo "  ✗ Dropbear 2016.74 NO disponible"
    echo "0" > "$DB_KEYS/has_2016.txt"
fi

# ============================================================
# COMPILAR DROPBEAR 2019.78 (SECUNDARIO - PUERTO 142)
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " [2/2] Dropbear 2019.78 → Puerto 142 (SECUNDARIO)"
echo "══════════════════════════════════════════"

NEED_COMPILE_2019=true
if [ -x "$DB_DIR/dropbear-2019.78" ]; then
    echo "  ✓ Ya compilado, omitiendo"
    NEED_COMPILE_2019=false
fi

if $NEED_COMPILE_2019; then
    _compilar_dropbear \
        "2019.78" \
        "https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2" \
        "/opt/dropbear-2019" \
        "$CFLAGS_2019" \
        "dropbear-2019.78"
fi

if [ -x "$DB_DIR/dropbear-2019.78" ]; then
    echo "  ✓ Dropbear 2019.78 disponible → :142"
    echo "1" > "$DB_KEYS/has_2019.txt"
else
    echo "  ✗ Dropbear 2019.78 NO disponible"
    echo "0" > "$DB_KEYS/has_2019.txt"
fi

# ============================================================
# GENERAR LLAVES HOST
# ============================================================
_gen_llaves() {
    local KEYBIN=""
    # Preferir keybin de 2016, luego 2019, luego sistema
    for candidate in \
        "$DB_DIR/dropbearkey-2016.74" \
        "$DB_DIR/dropbearkey-2019.78" \
        "$(command -v dropbearkey 2>/dev/null)"; do
        [ -x "$candidate" ] && KEYBIN="$candidate" && break
    done
    [ -z "$KEYBIN" ] && echo "⚠ dropbearkey no disponible, llaves no generadas" && return

    echo ""
    echo "Generando llaves host Dropbear..."
    [ ! -f "$DB_KEYS/dropbear_rsa_host_key" ] && \
        "$KEYBIN" -t rsa -f "$DB_KEYS/dropbear_rsa_host_key" -s 2048 >/dev/null 2>&1 \
        && echo "  ✓ RSA"
    [ ! -f "$DB_KEYS/dropbear_ecdsa_host_key" ] && \
        "$KEYBIN" -t ecdsa -f "$DB_KEYS/dropbear_ecdsa_host_key" >/dev/null 2>&1 \
        && echo "  ✓ ECDSA"
}
_gen_llaves

# ============================================================
# WRAPPER ANTI "Illegal packet size"
# Detecta si la conexión es SSH real, HTTP CONNECT, o tráfico basura.
# Redirige al puerto interno de Dropbear en loopback.
# ============================================================
_crear_wrapper() {
    local PPUB=$1    # puerto público (cliente conecta aquí)
    local PINT=$2    # puerto interno (dropbear escucha aquí en 127.0.0.1)
    local WS="/usr/local/bin/msy-wrap-${PPUB}.sh"
    local SVC="msy-wrap-${PPUB}"

    cat > "$WS" <<WRAP
#!/bin/bash
read -t 10 -r L
if   [[ "\$L" == SSH-* ]];      then { printf '%s\r\n' "\$L"; cat; } | socat - TCP:127.0.0.1:${PINT}
elif [[ "\$L" == CONNECT\ * ]]; then printf 'HTTP/1.0 200 Connection established\r\n\r\n'; socat - TCP:127.0.0.1:${PINT}
elif [[ -z "\$L" ]];            then socat - TCP:127.0.0.1:${PINT}
else                                 printf 'HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n'
fi
WRAP
    chmod +x "$WS"

    cat > "/etc/systemd/system/${SVC}.service" <<WSVC
[Unit]
Description=MSY Wrapper :${PPUB}→:${PINT} (Dropbear)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:${PPUB},reuseaddr,fork,backlog=256 EXEC:${WS}
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
WSVC
    systemctl daemon-reload
    systemctl enable "$SVC" >/dev/null 2>&1
}

# ============================================================
# FUNCIÓN: INICIAR DROPBEAR EN PUERTO ESPECÍFICO
#
# Parámetros:
#   $1 = versión (ej: "2016.74")
#   $2 = puerto público (ej: 143)
#   $3 = puerto interno loopback (ej: 1143)
# ============================================================
_arrancar_db() {
    local VER=$1
    local PPUB=$2
    local PINT=$3
    local BIN="$DB_DIR/dropbear-${VER}"
    local SVC="dropbear-${VER//./-}"
    local WR_SVC="msy-wrap-${PPUB}"

    [ ! -x "$BIN" ] && echo "  ✗ Binario $BIN no encontrado" && return 1

    local KF=""
    [ -f "$DB_KEYS/dropbear_rsa_host_key" ]   && KF="$KF -r $DB_KEYS/dropbear_rsa_host_key"
    [ -f "$DB_KEYS/dropbear_ecdsa_host_key" ] && KF="$KF -r $DB_KEYS/dropbear_ecdsa_host_key"

    # Limpiar antes de arrancar
    systemctl stop "$WR_SVC" "$SVC" 2>/dev/null
    pkill -9 -f "dropbear.*${PINT}" 2>/dev/null
    pkill -9 -f "socat.*${PPUB}"    2>/dev/null
    fuser -k "${PPUB}/tcp" 2>/dev/null
    fuser -k "${PINT}/tcp" 2>/dev/null
    sleep 1

    # Servicio Dropbear (escucha solo en loopback)
    cat > "/etc/systemd/system/${SVC}.service" <<DBSVC
[Unit]
Description=Dropbear $VER :${PINT} interno MSY VPN
After=network.target

[Service]
Type=simple
ExecStart=${BIN} -F -E -p 127.0.0.1:${PINT} ${KF} -b ${DB_KEYS}/banner.txt -K 120 -I 600
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
    systemctl enable "$SVC" >/dev/null 2>&1
    systemctl restart "$SVC"
    sleep 1

    if systemctl is-active --quiet "$SVC"; then
        # Arrancar wrapper en puerto público
        _crear_wrapper "$PPUB" "$PINT"
        systemctl restart "$WR_SVC"
        sleep 1

        if systemctl is-active --quiet "$WR_SVC"; then
            echo "  ✓ Dropbear $VER  → público :${PPUB} (interno :${PINT} + wrapper)"
        else
            # Fallback: Dropbear directo sin wrapper
            systemctl stop "$SVC" 2>/dev/null
            fuser -k "${PPUB}/tcp" 2>/dev/null
            sed -i "s|127.0.0.1:${PINT}|0.0.0.0:${PPUB}|g" "/etc/systemd/system/${SVC}.service"
            systemctl daemon-reload
            systemctl restart "$SVC"
            sleep 1
            systemctl is-active --quiet "$SVC" \
                && echo "  ✓ Dropbear $VER  → :${PPUB} (directo, sin wrapper)" \
                || { echo "  ✗ Dropbear $VER falló completamente"; journalctl -u "$SVC" --no-pager -n 8 2>/dev/null; return 1; }
        fi
        return 0
    else
        echo "  ✗ Dropbear $VER no inició"
        journalctl -u "$SVC" --no-pager -n 8 2>/dev/null
        return 1
    fi
}

# ============================================================
# ARRANCAR SERVICIOS
# Puerto 143 = Dropbear 2016.74 (OBLIGATORIO)
# Puerto 142 = Dropbear 2019.78 (secundario)
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " Iniciando servicios Dropbear..."
echo "══════════════════════════════════════════"

DB_ACTIVOS=()
ACTIVE_DB_VER=""
ACTIVE_DB_BIN=""

# --- Puerto 143: FORZAR 2016.74 ---
echo ""
echo " → Puerto 143 (Dropbear 2016.74 - PRINCIPAL):"
if _arrancar_db "2016.74" 143 1143; then
    DB_ACTIVOS+=("2016.74:143")
    ACTIVE_DB_VER="2016.74"
    ACTIVE_DB_BIN="$DB_DIR/dropbear-2016.74"
else
    # Solo si 2016 falló absolutamente, usar OpenSSH como emergencia
    echo "  ⚠ 2016.74 falló — activando OpenSSH en :143 como emergencia"
    fuser -k 143/tcp 2>/dev/null
    grep -q "^Port 143" /etc/ssh/sshd_config || \
        sed -i '/^Port 22/a Port 143' /etc/ssh/sshd_config
    systemctl restart ssh
    ACTIVE_DB_VER="ssh_fallback"
fi

# --- Puerto 142: Dropbear 2019.78 ---
echo ""
echo " → Puerto 142 (Dropbear 2019.78 - SECUNDARIO):"
if _arrancar_db "2019.78" 142 1142; then
    DB_ACTIVOS+=("2019.78:142")
else
    echo "  ⚠ 2019.78 no disponible en puerto 142"
fi

# ============================================================
# GUARDAR ESTADO (para que el menú lo lea)
# ============================================================
echo "$ACTIVE_DB_VER"            > "$DB_KEYS/active_version.txt"
echo "$ACTIVE_DB_BIN"            > "$DB_KEYS/active_bin.txt"
printf '%s\n' "${DB_ACTIVOS[@]}" > "$DB_KEYS/active_ports.txt"

# Flags de disponibilidad
[ -x "$DB_DIR/dropbear-2016.74" ] && echo "1" || echo "0" > "$DB_KEYS/has_2016.txt"
[ -x "$DB_DIR/dropbear-2019.78" ] && echo "1" || echo "0" > "$DB_KEYS/has_2019.txt"

# ============================================================
# RESUMEN FINAL
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " Resumen Dropbear:"
for info in "${DB_ACTIVOS[@]}"; do
    VER="${info%%:*}"; P="${info##*:}"
    echo "  ✓ Dropbear $VER → puerto :$P"
done
[ "${#DB_ACTIVOS[@]}" = "0" ] && echo "  ⚠ Ningún Dropbear activo"
echo " Versión principal: $ACTIVE_DB_VER (puerto 143)"
echo " Versión secundaria: 2019.78 (puerto 142)"
echo "══════════════════════════════════════════"

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
cat > "/etc/ssh-vpn/users/${USER_VPN}.txt" <<USEREOF
Usuario: $USER_VPN
Contraseña: $PASS_VPN
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: Ilimitado
Estado: Activo
Dropbear activo: $ACTIVE_DB_VER (puerto 143)
USEREOF

echo "✓ Usuario: $USER_VPN / $PASS_VPN"
export USER_VPN PASS_VPN ACTIVE_DB_VER
