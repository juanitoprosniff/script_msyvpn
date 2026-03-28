#!/bin/bash
# mod_ssh.sh - MSY VPN v104+ (BINARIOS PRECOMPILADOS)
#
# Sin compilación — usa binarios precompilados en este orden:
#   1. Dropbear del sistema (apt install dropbear-bin) — más confiable
#   2. Binarios de tu GitHub si los tienes subidos
#   3. Compilar 2019.78 como último recurso (tiene Makefile correcto)
#
# Múltiples versiones en puertos distintos:
#   Puerto :143 → Dropbear versión principal (más reciente disponible)
#   Puerto :142 → Dropbear segunda versión
#   Puerto :141 → Dropbear tercera versión
#
# Wrapper socat en cada puerto público elimina "Illegal packet size"
# (tráfico HTTP llegando al puerto SSH)

# ============================================================
# DETECCIÓN DE ENTORNO
# ============================================================
OS_VER=$(lsb_release -rs 2>/dev/null \
    || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null \
    || echo "0")
OS_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
ARCH=$(uname -m)

echo "=========================================="
echo " SSH/Dropbear Setup (binarios precompilados)"
echo " OS: Ubuntu $OS_VER | Arch: $ARCH"
echo "=========================================="

# ============================================================
# DEPENDENCIAS MÍNIMAS (sin compiladores)
# ============================================================
echo ""
echo "Instalando dependencias..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    wget curl socat openssh-server 2>/dev/null
echo "✓ Dependencias OK"

# ============================================================
# OPENSSH (PUERTO 22)
# ============================================================
echo ""
echo "Configurando OpenSSH en puerto 22..."

# Limpiar puertos viejos del fallback si existían
sed -i '/^Port 14[0-9]/d' /etc/ssh/sshd_config 2>/dev/null

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
# MÉTODO 1: apt install dropbear-bin
# Es el más confiable — binario oficial del sistema, siempre
# compatible con el Ubuntu instalado, sin compilar nada.
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " Método 1: Dropbear via apt..."
echo "══════════════════════════════════════════"

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dropbear-bin 2>/dev/null \
    || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dropbear 2>/dev/null

APT_DB_BIN=$(command -v dropbear 2>/dev/null \
    || ls /usr/sbin/dropbear 2>/dev/null \
    || ls /usr/bin/dropbear  2>/dev/null \
    || echo "")
APT_DB_KEY=$(command -v dropbearkey 2>/dev/null \
    || ls /usr/bin/dropbearkey  2>/dev/null \
    || ls /usr/sbin/dropbearkey 2>/dev/null \
    || echo "")

if [ -n "$APT_DB_BIN" ] && [ -x "$APT_DB_BIN" ]; then
    # Obtener versión
    APT_DB_VER=$("$APT_DB_BIN" -V 2>&1 | grep -oP '\d{4}\.\d+' | head -1)
    APT_DB_VER=${APT_DB_VER:-"apt"}
    echo "  ✓ Dropbear apt: v$APT_DB_VER → $APT_DB_BIN"

    # Copiar al directorio del script para manejarlo nosotros
    cp "$APT_DB_BIN" "$DB_DIR/dropbear-${APT_DB_VER}"
    chmod +x "$DB_DIR/dropbear-${APT_DB_VER}"
    [ -n "$APT_DB_KEY" ] && [ -x "$APT_DB_KEY" ] && \
        cp "$APT_DB_KEY" "$DB_DIR/dropbearkey-${APT_DB_VER}"

    # Detener el servicio oficial de apt (lo manejamos nosotros)
    systemctl stop    dropbear 2>/dev/null
    systemctl disable dropbear 2>/dev/null
else
    echo "  ✗ Dropbear no disponible via apt"
    APT_DB_VER=""
fi

# ============================================================
# MÉTODO 2: binarios desde tu GitHub
# Sube los binarios compilados una vez y el script los descarga.
# Estructura sugerida en tu repo:
#   installer/bins/dropbear-2016-amd64
#   installer/bins/dropbear-2016-arm64
#   installer/bins/dropbearkey-2016-amd64
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " Método 2: Binarios desde GitHub..."
echo "══════════════════════════════════════════"

GITHUB_BASE="https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer"

# Detectar arquitectura para el binario correcto
case "$ARCH" in
    x86_64)  ARCH_SUFFIX="amd64" ;;
    aarch64) ARCH_SUFFIX="arm64" ;;
    armv7l)  ARCH_SUFFIX="armhf" ;;
    *)       ARCH_SUFFIX="amd64" ;;
esac

# Intentar descargar binarios precompilados del GitHub
# (si los has subido en esa estructura)
_descargar_bin_github() {
    local NOMBRE=$1   # ej: dropbear-2016
    local DEST=$2     # destino completo
    local URL="${GITHUB_BASE}/bins/${NOMBRE}-${ARCH_SUFFIX}"

    wget -q --timeout=20 -O "${DEST}.tmp" "$URL" 2>/dev/null
    if [ -s "${DEST}.tmp" ] && file "${DEST}.tmp" 2>/dev/null | grep -q "ELF"; then
        mv "${DEST}.tmp" "$DEST"
        chmod +x "$DEST"
        echo "  ✓ Descargado: $NOMBRE ($ARCH_SUFFIX)"
        return 0
    fi
    rm -f "${DEST}.tmp"
    return 1
}

for VER_CORTA in "2016" "2019"; do
    DEST="$DB_DIR/dropbear-${VER_CORTA}.74"
    [ "$VER_CORTA" = "2019" ] && DEST="$DB_DIR/dropbear-${VER_CORTA}.78"
    [ -x "$DEST" ] && continue   # ya lo tenemos
    _descargar_bin_github "dropbear-${VER_CORTA}" "$DEST" || true
    _descargar_bin_github "dropbearkey-${VER_CORTA}" "${DEST/dropbear/dropbearkey}" || true
done

# ============================================================
# MÉTODO 3: compilar 2019.78 si aún no tenemos nada
#
# 2019.78 tiene el Makefile corregido vs 2016 —  el race condition
# de libtomcrypt no existe en 2019. Aun así compilamos las sublibs
# primero en -j1 por seguridad.
# ============================================================
DB_COUNT=$(ls "$DB_DIR"/dropbear-* 2>/dev/null | grep -vc "key" || echo 0)

if [ "$DB_COUNT" = "0" ]; then
    echo ""
    echo "══════════════════════════════════════════"
    echo " Método 3: Compilando Dropbear 2019.78..."
    echo " (2019 tiene Makefile estable, sin race condition)"
    echo "══════════════════════════════════════════"

    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        gcc make libc6-dev libssl-dev 2>/dev/null

    GCC_VER=$(gcc -dumpversion 2>/dev/null | cut -d. -f1); GCC_VER=${GCC_VER:-0}
    if   [ "$GCC_VER" -ge 14 ] 2>/dev/null; then CF="-w -fcommon -std=gnu11"
    elif [ "$GCC_VER" -ge 12 ] 2>/dev/null; then CF="-w -fcommon"
    else                                          CF="-w -fcommon"; fi

    cd /usr/src
    TB="dropbear-2019.78.tar.bz2"
    wget -q --timeout=90 -O "$TB" \
        "https://matt.ucc.asn.au/dropbear/releases/$TB" 2>/dev/null \
    || wget -q --timeout=90 -O "$TB" \
        "https://dropbear.nl/mirror/releases/$TB" 2>/dev/null

    if [ -s "$TB" ]; then
        rm -rf dropbear-2019.78
        tar xjf "$TB"
        cd dropbear-2019.78

        # Personalizar banner SSH
        for f in sysoptions.h default_options.h options.h; do
            [ -f "$f" ] && grep -q "LOCAL_IDENT" "$f" && \
                sed -i 's|#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' "$f"
        done

        export CFLAGS="$CF"
        ./configure --prefix="/opt/db-build" \
            --disable-zlib --disable-wtmp --disable-lastlog >/dev/null 2>&1

        # Sublibs primero en -j1 (previene cualquier race condition)
        echo "  Compilando sublibs..."
        [ -d libtommath ]  && make -C libtommath  -j1 CFLAGS="$CF" >/dev/null 2>&1
        [ -d libtomcrypt ] && make -C libtomcrypt -j1 CFLAGS="$CF" >/dev/null 2>&1

        echo "  Compilando dropbear..."
        make -j$(nproc) PROGRAMS="dropbear dropbearkey" CFLAGS="$CF" >/dev/null 2>&1
        make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1
        unset CFLAGS

        if [ -x /opt/db-build/sbin/dropbear ]; then
            cp /opt/db-build/sbin/dropbear   "$DB_DIR/dropbear-2019.78"
            cp /opt/db-build/bin/dropbearkey "$DB_DIR/dropbearkey-2019.78" 2>/dev/null
            chmod +x "$DB_DIR/dropbear-2019.78"
            echo "  ✓ Dropbear 2019.78 compilado y listo"
        else
            echo "  ✗ Compilación falló"
        fi
        cd /root
    else
        echo "  ✗ No se pudo descargar el tarball de 2019"
    fi
fi

# ============================================================
# GENERAR LLAVES HOST
# ============================================================
_gen_llaves() {
    local KEYBIN=""
    for v in "$APT_DB_VER" "2019.78" "2016.74" "apt"; do
        [ -z "$v" ] && continue
        [ -x "$DB_DIR/dropbearkey-${v}" ] && KEYBIN="$DB_DIR/dropbearkey-${v}" && break
    done
    [ -z "$KEYBIN" ] && command -v dropbearkey >/dev/null 2>&1 && KEYBIN="dropbearkey"
    [ -z "$KEYBIN" ] && return

    echo "Generando llaves host..."
    [ ! -f "$DB_KEYS/dropbear_rsa_host_key" ] && \
        "$KEYBIN" -t rsa -f "$DB_KEYS/dropbear_rsa_host_key" -s 2048 >/dev/null 2>&1 \
        && echo "  ✓ RSA"
    [ ! -f "$DB_KEYS/dropbear_ecdsa_host_key" ] && \
        "$KEYBIN" -t ecdsa -f "$DB_KEYS/dropbear_ecdsa_host_key" >/dev/null 2>&1 \
        && echo "  ✓ ECDSA"
}
_gen_llaves

# ============================================================
# RESUMEN DE BINARIOS
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " Binarios disponibles:"
LISTA_VERS=()
for bin in "$DB_DIR"/dropbear-*; do
    [[ "$bin" == *"key"* ]] && continue
    [ -x "$bin" ] || continue
    VER="${bin##*dropbear-}"
    LISTA_VERS+=("$VER")
    echo "  ✓ Dropbear $VER"
done
[ "${#LISTA_VERS[@]}" = "0" ] && echo "  ✗ Ningún binario disponible"
echo "══════════════════════════════════════════"

# ============================================================
# WRAPPER ANTI "Illegal packet size"
#
# 1231976033 = 0x496E7421 = "Int!" = primeros bytes de HTTP
# El wrapper lee la primera línea y decide:
#   SSH-*     → conexión SSH real  → reenviar a Dropbear interno
#   CONNECT * → proxy HTTP CONNECT → responder 200 y tunelizar
#   vacío     → cliente TCP directo → pasar sin filtrar
#   otro      → tráfico basura     → cerrar limpiamente
# ============================================================
_crear_wrapper() {
    local PPUB=$1    # puerto público (cliente)
    local PINT=$2    # puerto interno (dropbear)
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
Description=MSY Wrapper :${PPUB}→:${PINT}
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
# FUNCIÓN: iniciar un Dropbear en su puerto
# ============================================================
_arrancar_db() {
    local VER=$1
    local PPUB=$2    # puerto público
    local PINT=$3    # puerto interno (dropbear escucha aquí)
    local BIN="$DB_DIR/dropbear-${VER}"
    local SVC="dropbear-${VER/./-}"
    local WR_SVC="msy-wrap-${PPUB}"

    [ ! -x "$BIN" ] && return 1

    local KF=""
    [ -f "$DB_KEYS/dropbear_rsa_host_key" ]   && KF="$KF -r $DB_KEYS/dropbear_rsa_host_key"
    [ -f "$DB_KEYS/dropbear_ecdsa_host_key" ] && KF="$KF -r $DB_KEYS/dropbear_ecdsa_host_key"

    # Liberar puertos
    systemctl stop "$WR_SVC" "$SVC" 2>/dev/null
    pkill -9 -f "dropbear.*${PINT}" 2>/dev/null
    pkill -9 -f "socat.*${PPUB}"    2>/dev/null
    fuser -k "${PPUB}/tcp" 2>/dev/null
    fuser -k "${PINT}/tcp" 2>/dev/null
    sleep 1

    # Servicio Dropbear (loopback interno)
    cat > "/etc/systemd/system/${SVC}.service" <<DBSVC
[Unit]
Description=Dropbear $VER :${PINT} interno (MSY VPN)
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
        # Wrapper en puerto público
        _crear_wrapper "$PPUB" "$PINT"
        systemctl restart "$WR_SVC"
        sleep 1

        if systemctl is-active --quiet "$WR_SVC"; then
            echo "  ✓ Dropbear $VER  :${PPUB} → :${PINT} (wrapper activo)"
        else
            # Sin socat: Dropbear directo en puerto público
            systemctl stop "$SVC" 2>/dev/null
            fuser -k "${PPUB}/tcp" 2>/dev/null
            sed -i "s|127.0.0.1:${PINT}|0.0.0.0:${PPUB}|" "/etc/systemd/system/${SVC}.service"
            systemctl daemon-reload
            systemctl restart "$SVC"
            sleep 1
            systemctl is-active --quiet "$SVC" \
                && echo "  ✓ Dropbear $VER  :${PPUB} (directo, sin wrapper)" \
                || { echo "  ✗ Dropbear $VER falló"; return 1; }
        fi
        return 0
    else
        echo "  ✗ Dropbear $VER no inició"
        journalctl -u "$SVC" --no-pager -n 5 2>/dev/null
        return 1
    fi
}

# ============================================================
# ARRANCAR TODAS LAS VERSIONES EN SUS PUERTOS
# Puerto 143 = principal, 142 = secundario, 141 = tercero
# ============================================================
echo ""
echo "Iniciando servicios Dropbear..."

PPUBS=(143  142  141)
PINTS=(1143 1142 1141)

ACTIVE_DB_VER=""
ACTIVE_DB_BIN=""
DB_ACTIVOS=()

for i in "${!LISTA_VERS[@]}"; do
    [ "$i" -ge "${#PPUBS[@]}" ] && break
    VER="${LISTA_VERS[$i]}"
    PPUB="${PPUBS[$i]}"
    PINT="${PINTS[$i]}"

    if _arrancar_db "$VER" "$PPUB" "$PINT"; then
        DB_ACTIVOS+=("$VER:$PPUB")
        [ -z "$ACTIVE_DB_VER" ] && \
            ACTIVE_DB_VER="$VER" && \
            ACTIVE_DB_BIN="$DB_DIR/dropbear-${VER}"
    fi
done

# Fallback OpenSSH en :143
if [ -z "$ACTIVE_DB_VER" ]; then
    echo "⚠ Ningún Dropbear disponible — OpenSSH fallback en :143"
    fuser -k 143/tcp 2>/dev/null
    grep -q "^Port 143" /etc/ssh/sshd_config || \
        sed -i '/^Port 22/a Port 143' /etc/ssh/sshd_config
    systemctl restart ssh
    ACTIVE_DB_VER="ssh_fallback"
fi

# ============================================================
# GUARDAR ESTADO
# ============================================================
echo "$ACTIVE_DB_VER"              > /etc/dropbear-legacy/active_version.txt
echo "$ACTIVE_DB_BIN"              > /etc/dropbear-legacy/active_bin.txt
printf '%s\n' "${LISTA_VERS[@]}"   > /etc/dropbear-legacy/all_versions.txt
printf '%s\n' "${DB_ACTIVOS[@]}"   > /etc/dropbear-legacy/active_ports.txt
[ -x "$DB_DIR/dropbear-2016.74" ] && echo "1" || echo "0" > /etc/dropbear-legacy/has_2016.txt
[ -x "$DB_DIR/dropbear-2019.78" ] && echo "1" || echo "0" > /etc/dropbear-legacy/has_2019.txt

echo ""
echo "══════════════════════════════════════════"
echo " Resumen final:"
for info in "${DB_ACTIVOS[@]}"; do
    VER="${info%%:*}"; P="${info##*:}"
    echo "  ✓ Dropbear $VER → puerto :$P"
done
[ "${#DB_ACTIVOS[@]}" = "0" ] && echo "  ⚠ Fallback: OpenSSH en :143"
echo " Principal: $ACTIVE_DB_VER"
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
Dropbear activo: $ACTIVE_DB_VER
USEREOF

echo "✓ Usuario: $USER_VPN / $PASS_VPN"
export USER_VPN PASS_VPN ACTIVE_DB_VER
