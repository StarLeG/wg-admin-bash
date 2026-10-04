#!/usr/bin/env bash
# wg-admin.sh - Управление WireGuard сервером (Hub-and-Spoke)
# Версия: 1.0.0
# Лицензия: MIT
# Поддерживает Debian/Ubuntu. Запускать от root.
#
# Использование:
#   sudo bash wg-admin.sh          — интерактивное меню
#   sudo bash wg-admin.sh --help   — краткая справка
# Поддерживаемые ОС: Debian 11/12, Ubuntu 20.04/22.04/24.04 (x86_64, arm64)
# Первый запуск: [2] Инициализация сервера → [3] Управление клиентами → Добавить клиента.

set -o pipefail

# ==================== КОНСТАНТЫ ====================
WG_IF="wg0"
WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/${WG_IF}.conf"
CLIENTS_DIR="${WG_DIR}/clients"
EXPIRY_DB="${WG_DIR}/expiry.db"
SETTINGS_FILE="${WG_DIR}/wg-admin.conf"
LOG_FILE="/var/log/wg-admin.log"
SERVER_PRIVATE_KEY="${WG_DIR}/server_private.key"
SERVER_PUBLIC_KEY="${WG_DIR}/server_public.key"
VERSION="1.0.0"
SERVER_VPN_IP="10.8.0.1"
VPN_SUBNET="10.8.0.0/24"
WG_PORT="51820"
DNS_DEFAULT="1.1.1.1"
MTU_DEFAULT=""
CLIENT_KEEPALIVE="25"
EXPIRE_CHECK_SCRIPT="/usr/local/bin/wg-expire-check.sh"

# ==================== ЦВЕТА ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ==================== СОСТОЯНИЕ ====================
USE_COLOR=1
LOG_LEVEL="INFO"          # DEBUG | INFO | WARN | ERROR
LANG_UI="ru"              # ru | en
TMP_FILES=()

# ==================== ЛОКАЛИЗАЦИЯ ====================
# t "русский" "english" — выводит строку на выбранном языке интерфейса
t() {
  if [[ "${LANG_UI}" == "en" ]]; then
    printf '%s' "${2}"
  else
    printf '%s' "${1}"
  fi
}

# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

# init_colors — включает цвета только для tty и если не отключены настройкой
init_colors() {
  if [[ ! -t 1 ]] || [[ "${USE_COLOR}" -eq 0 ]]; then
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
  fi
}

# make_temp — создаёт временный файл и регистрирует его для очистки по EXIT
make_temp() {
  local tmp
  tmp="$(mktemp)" || die "$(t 'Не удалось создать временный файл' 'Failed to create temp file')"
  TMP_FILES+=("${tmp}")
  printf '%s' "${tmp}"
}

# cleanup — удаляет временные файлы (trap EXIT)
cleanup() {
  local f
  for f in "${TMP_FILES[@]}"; do
    [[ -n "${f}" && -e "${f}" ]] && rm -f -- "${f}"
  done
}

# init_log — открывает лог-файл и пишет стартовую запись
init_log() {
  touch "${LOG_FILE}" 2>/dev/null || true
  chmod 600 "${LOG_FILE}" 2>/dev/null || true
  log INFO "$(t 'Скрипт запущен' 'Script started') v${VERSION}"
}

# log — пишет строку в лог с timestamp и уровнем
log() {
  local level="$1"
  shift
  local msg="$*"
  local ts levels_num level_num
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  case "${LOG_LEVEL}" in
    DEBUG) levels_num=0 ;;
    INFO)  levels_num=1 ;;
    WARN)  levels_num=2 ;;
    ERROR) levels_num=3 ;;
    *)     levels_num=1 ;;
  esac
  case "${level}" in
    DEBUG) level_num=0 ;;
    INFO)  level_num=1 ;;
    WARN)  level_num=2 ;;
    ERROR) level_num=3 ;;
    *)     level_num=1 ;;
  esac
  (( level_num >= levels_num )) || return 0
  if [[ -w "${LOG_FILE}" ]] || touch "${LOG_FILE}" 2>/dev/null; then
    printf '[%s] [%s] %s\n' "${ts}" "${level}" "${msg}" >>"${LOG_FILE}"
  fi
}

# info — информационное сообщение в терминал и лог
info() {
  local msg="$*"
  printf '%b[INFO]%b %s\n' "${GREEN}" "${NC}" "${msg}"
  log INFO "${msg}"
}

# warn — предупреждение в терминал и лог
warn() {
  local msg="$*"
  printf '%b[WARN]%b %s\n' "${YELLOW}" "${NC}" "${msg}" >&2
  log WARN "${msg}"
}

# die — фатальная ошибка: сообщение и выход
die() {
  local msg="$*"
  printf '%b[ERROR]%b %s\n' "${RED}" "${NC}" "${msg}" >&2
  log ERROR "${msg}"
  exit 1
}

# confirm — запрос подтверждения y/N; возвращает 0 при y/Y
confirm() {
  local prompt="${1:-$(t 'Продолжить? (y/N): ' 'Continue? (y/N): ')}"
  local ans
  read -r -p "${prompt}" ans
  [[ "${ans}" =~ ^[Yy]$ ]]
}

# check_root — требует запуска от root
check_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "$(t 'Скрипт должен запускаться от root (sudo)' 'Script must be run as root (sudo)')"
  fi
}

# check_os — проверяет, что система Debian/Ubuntu
check_os() {
  local id=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    id="$(. /etc/os-release && printf '%s' "${ID}")"
  elif [[ -r /etc/debian_version ]]; then
    id="debian"
  fi
  case "${id}" in
    debian|ubuntu|raspbian|linuxmint|pop) : ;;
    *) die "$(t "Неподдерживаемая ОС: ${id:-unknown}. Нужны Debian/Ubuntu" "Unsupported OS: ${id:-unknown}. Debian/Ubuntu required")" ;;
  esac
  if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    die "$(t "Требуется bash >= 4.4, найден ${BASH_VERSION}" "bash >= 4.4 required, found ${BASH_VERSION}")"
  fi
}

# validate_name — имя клиента: буквы/цифры/_/-, без пустого
validate_name() {
  [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]]
}

# validate_ip — проверка IPv4
validate_ip() {
  local ip="$1"
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o
  IFS=. read -r -a o <<<"${ip}"
  local x
  for x in "${o[@]}"; do
    (( x >= 0 && x <= 255 )) || return 1
  done
  return 0
}

# validate_cidr — проверка IPv4/префикс
validate_cidr() {
  local cidr="$1"
  local ip prefix
  [[ "${cidr}" == */* ]] || return 1
  ip="${cidr%%/*}"
  prefix="${cidr##*/}"
  validate_ip "${ip}" || return 1
  [[ "${prefix}" =~ ^[0-9]+$ ]] || return 1
  (( prefix >= 0 && prefix <= 32 ))
}

# validate_port — проверка TCP/UDP-порта 1-65535
validate_port() {
  local port="$1"
  [[ "${port}" =~ ^[0-9]+$ ]] || return 1
  (( port >= 1 && port <= 65535 ))
}

# validate_iface — проверка существования сетевого интерфейса
validate_iface() {
  [[ -n "$1" ]] && ip link show "$1" >/dev/null 2>&1
}

# load_settings — читает настройки скрипта из SETTINGS_FILE
load_settings() {
  [[ -f "${SETTINGS_FILE}" ]] || return 0
  local line key val
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" =~ ^[[:space:]]*# ]] && continue
    [[ "${line}" == *"="* ]] || continue
    key="${line%%=*}"
    val="${line#*=}"
    case "${key}" in
      VPN_SUBNET)   VPN_SUBNET="${val}" ;;
      WG_PORT)      WG_PORT="${val}" ;;
      DNS_DEFAULT)  DNS_DEFAULT="${val}" ;;
      WG_DIR)       WG_DIR="${val}"
                    WG_CONF="${WG_DIR}/${WG_IF}.conf"
                    CLIENTS_DIR="${WG_DIR}/clients"
                    EXPIRY_DB="${WG_DIR}/expiry.db"
                    SETTINGS_FILE="${WG_DIR}/wg-admin.conf"
                    SERVER_PRIVATE_KEY="${WG_DIR}/server_private.key"
                    SERVER_PUBLIC_KEY="${WG_DIR}/server_public.key" ;;
      USE_COLOR)    USE_COLOR="${val}" ;;
      LOG_LEVEL)    LOG_LEVEL="${val}" ;;
      LANG_UI)      LANG_UI="${val}" ;;
    esac
  done <"${SETTINGS_FILE}"
}

# save_settings — сохраняет настройки скрипта
save_settings() {
  mkdir -p "${WG_DIR}" 2>/dev/null || true
  {
    printf '# wg-admin.sh settings\n'
    printf 'VPN_SUBNET=%s\n' "${VPN_SUBNET}"
    printf 'WG_PORT=%s\n' "${WG_PORT}"
    printf 'DNS_DEFAULT=%s\n' "${DNS_DEFAULT}"
    printf 'WG_DIR=%s\n' "${WG_DIR}"
    printf 'USE_COLOR=%s\n' "${USE_COLOR}"
    printf 'LOG_LEVEL=%s\n' "${LOG_LEVEL}"
    printf 'LANG_UI=%s\n' "${LANG_UI}"
  } >"${SETTINGS_FILE}"
  chmod 600 "${SETTINGS_FILE}" 2>/dev/null || true
}

# prompt_value — читает ввод с дефолтом в скобках; при EOF завершает скрипт
# prompt_value "Подсказка" "дефолт" → stdout значение
prompt_value() {
  local prompt="$1"
  local def="${2:-}"
  local ans
  if [[ -n "${def}" ]]; then
    read -r -p "${prompt} [${def}]: " ans || die "$(t 'Ввод закрыт' 'Input closed')"
    printf '%s' "${ans:-${def}}"
  else
    read -r -p "${prompt}: " ans || die "$(t 'Ввод закрыт' 'Input closed')"
    printf '%s' "${ans}"
  fi
}

# ask_yes_no — y/N с дефолтом N
ask_yes_no() {
  local prompt="$1"
  local ans
  read -r -p "${prompt} (y/N): " ans
  [[ "${ans}" =~ ^[Yy]$ ]]
}

# external_ip — внешний IP сервера с fallback
external_ip() {
  local ip=""
  ip="$(curl -s --max-time 5 ifconfig.me 2>/dev/null)" || true
  if ! validate_ip "${ip}"; then
    ip="$(curl -s --max-time 5 api.ipify.org 2>/dev/null)" || true
  fi
  if ! validate_ip "${ip}"; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')" || true
  fi
  if ! validate_ip "${ip}"; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  fi
  printf '%s' "${ip}"
}

# detect_interface — внешний интерфейс по умолчанию
detect_interface() {
  ip route 2>/dev/null | awk '/default/ {print $5; exit}'
}

# vpn_network — вычисляет сеть из VPN_SUBNET (IP с нулевым хостом)
vpn_network() {
  local cidr="$1"
  local ip prefix
  ip="${cidr%%/*}"
  prefix="${cidr##*/}"
  local a b c d
  IFS=. read -r a b c d <<<"${ip}"
  local mask=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))
  local n
  n=$(( (a << 24 | b << 16 | c << 8 | d) & mask ))
  printf '%d.%d.%d.%d/%s' $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) $(( (n >> 8) & 255 )) $(( n & 255 )) "${prefix}"
}

# parse_duration — 30d|12h|never|YYYY-MM-DD|unix → unix ts или 0 (never)
parse_duration() {
  local s="$1"
  local now
  now="$(date +%s)"
  case "${s}" in
    never|NEVER|Never|"") printf '0' ;;
    *d)
      local days="${s%d}"
      [[ "${days}" =~ ^[0-9]+$ ]] || return 1
      printf '%d' "$(( now + days * 86400 ))" ;;
    *h)
      local hours="${s%h}"
      [[ "${hours}" =~ ^[0-9]+$ ]] || return 1
      printf '%d' "$(( now + hours * 3600 ))" ;;
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])
      local ts
      ts="$(date -d "${s} 23:59:59" +%s 2>/dev/null)" || return 1
      printf '%s' "${ts}" ;;
    *)
      [[ "${s}" =~ ^[0-9]+$ ]] || return 1
      printf '%s' "${s}" ;;
  esac
}

# fmt_ts — unix ts → человекочитаемо / never
fmt_ts() {
  local ts="$1"
  if [[ -z "${ts}" || "${ts}" == "0" || "${ts}" == "never" ]]; then
    printf '%s' "$(t 'бессрочно' 'never')"
  else
    date -d "@${ts}" '+%Y-%m-%d %H:%M' 2>/dev/null || printf '%s' "${ts}"
  fi
}

# section — заголовок раздела
section() {
  printf '\n%b=== %s ===%b\n' "${BLUE}" "$1" "${NC}"
}

# pause — «Нажмите Enter»; при EOF выходит
pause() {
  local msg
  msg="$(t 'Нажмите Enter для продолжения...' 'Press Enter to continue...')"
  read -r -p "${msg}" _ || exit 0
}

# pause_trap — trap EXIT
trap cleanup EXIT

# ==================== ПАРСИНГ wg0.conf ====================

# peer_names — список имён клиентов из wg0.conf
peer_names() {
  [[ -f "${WG_CONF}" ]] || return 0
  awk '
    /^# [A-Za-z0-9_-]+$/ && !/^# (EXPIRES|DISABLED)/ { print substr($0, 3) }
  ' "${WG_CONF}" 2>/dev/null
}

# peer_exists — есть ли пир с таким именем
peer_exists() {
  local name="$1"
  peer_names | grep -Fxq -- "${name}"
}

# peer_block_line — номер строки комментария `# name` в wg0.conf
peer_block_line() {
  local name="$1"
  grep -n "^# ${name}$" "${WG_CONF}" 2>/dev/null | head -1 | cut -d: -f1
}

# extract_peer_block — печатает строки блока пира (от `# name` до следующего
# комментария-имени/EOF/следующего [Interface])
extract_peer_block() {
  local name="$1"
  [[ -f "${WG_CONF}" ]] || return 1
  awk -v name="${name}" '
    $0 == "# " name { inb=1 }
    inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { exit }
    inb && /^\[Interface\]/ { exit }
    inb { print }
  ' "${WG_CONF}"
}

# peer_field — значение поля внутри блока пира (учитывая закомментированные строки);
# поддерживает форматы «Key = value» и «# EXPIRES value»
peer_field() {
  local name="$1" field="$2"
  extract_peer_block "${name}" | awk -v f="${field}" '
    {
      line = $0
      sub(/^[# ]+/, "", line)
      if (line ~ ("^" f "[[:space:]]*=")) {
        sub(/^[^=]*=[[:space:]]*/, "", line)
        print line
        exit
      }
      if (line ~ ("^" f "[[:space:]]+[0-9]+$")) {
        sub(/^[^[:space:]]+[[:space:]]+/, "", line)
        print line
        exit
      }
    }
  '
}

# comment_peer_lines — комментирует активные строки пира (для disable)
comment_peer_lines() {
  local name="$1"
  local tmp
  tmp="$(make_temp)"
  awk -v name="${name}" '
    $0 == "# " name { inb=1; print; next }
    inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
    inb && /^\[Interface\]/ { inb=0 }
    inb && /^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=/ {
      print "# " $0; next
    }
    { print }
  ' "${WG_CONF}" >"${tmp}" && mv -- "${tmp}" "${WG_CONF}"
  # маркер DISABLED
  if ! extract_peer_block "${name}" | grep -q '^# DISABLED'; then
    awk -v name="${name}" '
      $0 == "# " name { inb=1; print; next }
      inb && /^\[Peer\]/ { print; print "# DISABLED 1"; inb=2; next }
      inb==2 && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
      inb==2 && /^\[Interface\]/ { inb=0 }
      { print }
    ' "${WG_CONF}" >"${tmp}" 2>/dev/null || true
    # повторно: безопасный путь — добавить DISABLED после [Peer] блока
    if ! extract_peer_block "${name}" | grep -q '^# DISABLED'; then
      tmp="$(make_temp)"
      awk -v name="${name}" '
        $0 == "# " name { inb=1; print; next }
        inb==1 && /^\[Peer\]/ { print; print "# DISABLED 1"; inb=2; next }
        { print }
      ' "${WG_CONF}" >"${tmp}" && mv -- "${tmp}" "${WG_CONF}"
    fi
  fi
  log INFO "$(t "Клиент ${name} отключён" "Client ${name} disabled")"
}

# uncomment_peer_lines — раскомментирует строки пира (для enable)
uncomment_peer_lines() {
  local name="$1"
  local tmp
  tmp="$(make_temp)"
  awk -v name="${name}" '
    $0 == "# " name { inb=1; print; next }
    inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
    inb && /^\[Interface\]/ { inb=0 }
    inb && /^# DISABLED 1/ { next }
    inb && /^# (PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=/ {
      sub(/^# /, ""); print; next
    }
    { print }
  ' "${WG_CONF}" >"${tmp}" && mv -- "${tmp}" "${WG_CONF}"
  log INFO "$(t "Клиент ${name} включён" "Client ${name} enabled")"
}

# remove_peer_block — удаляет блок пира целиком
remove_peer_block() {
  local name="$1"
  local tmp
  tmp="$(make_temp)"
  awk -v name="${name}" '
    $0 == "# " name { inb=1; next }
    inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
    inb && /^\[Interface\]/ { inb=0 }
    inb { next }
    { print }
  ' "${WG_CONF}" >"${tmp}" && mv -- "${tmp}" "${WG_CONF}"
}

# append_peer_block — дописывает блок пира в wg0.conf
append_peer_block() {
  local name="$1" pubkey="$2" allowed_ips="$3" keepalive="${4:-}" expires="${5:-}"
  {
    printf '\n# %s\n' "${name}"
    printf '[Peer]\n'
    printf 'PublicKey = %s\n' "${pubkey}"
    printf 'AllowedIPs = %s\n' "${allowed_ips}"
    if [[ -n "${keepalive}" ]]; then
      printf 'PersistentKeepalive = %s\n' "${keepalive}"
    fi
    if [[ -n "${expires}" && "${expires}" != "0" ]]; then
      printf '# EXPIRES %s\n' "${expires}"
    fi
  } >>"${WG_CONF}"
}

# expiry_get — срок действия клиента (unix ts | 0 | "")
expiry_get() {
  local name="$1"
  [[ -f "${EXPIRY_DB}" ]] || return 0
  awk -F: -v n="${name}" '$1==n {print $2; exit}' "${EXPIRY_DB}"
}

# expiry_set — записывает срок действия клиента
expiry_set() {
  local name="$1" ts="$2"
  local tmp
  mkdir -p "$(dirname "${EXPIRY_DB}")" 2>/dev/null || true
  touch "${EXPIRY_DB}" 2>/dev/null || true
  tmp="$(make_temp)"
  if [[ -f "${EXPIRY_DB}" ]]; then
    awk -F: -v n="${name}" -v t="${ts}" 'BEGIN{OFS=":"} $1!=n {print} ' "${EXPIRY_DB}" >"${tmp}"
  else
    : >"${tmp}"
  fi
  printf '%s:%s\n' "${name}" "${ts}" >>"${tmp}"
  mv -- "${tmp}" "${EXPIRY_DB}"
  chmod 600 "${EXPIRY_DB}" 2>/dev/null || true
  # синхронизация комментария в wg0.conf
  if [[ -f "${WG_CONF}" ]] && peer_exists "${name}"; then
    local blk
    blk="$(extract_peer_block "${name}")"
    if [[ "${ts}" != "0" ]]; then
      if grep -q '^# EXPIRES ' <<<"${blk}"; then
        local tmp2
        tmp2="$(make_temp)"
        awk -v name="${name}" -v ts="${ts}" '
          $0 == "# " name { inb=1; print; next }
          inb && /^# EXPIRES / { print "# EXPIRES " ts; next }
          inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
          inb && /^\[Interface\]/ { inb=0 }
          { print }
        ' "${WG_CONF}" >"${tmp2}" && mv -- "${tmp2}" "${WG_CONF}"
      else
        local tmp2
        tmp2="$(make_temp)"
        awk -v name="${name}" -v ts="${ts}" '
          $0 == "# " name { inb=1; print; next }
          inb==1 && /^\[Peer\]/ { print; next }
          inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name {
            if (!done) { print "# EXPIRES " ts; done=1 }
            inb=0
          }
          inb && /^\[Interface\]/ {
            if (!done) { print "# EXPIRES " ts; done=1 }
            inb=0
          }
          { print }
          END { if (inb && !done) print "# EXPIRES " ts }
        ' "${WG_CONF}" >"${tmp2}" && mv -- "${tmp2}" "${WG_CONF}"
      fi
    else
      local tmp2
      tmp2="$(make_temp)"
      awk -v name="${name}" '
        $0 == "# " name { inb=1; print; next }
        inb && /^# EXPIRES / { next }
        inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
        inb && /^\[Interface\]/ { inb=0 }
        { print }
      ' "${WG_CONF}" >"${tmp2}" && mv -- "${tmp2}" "${WG_CONF}"
    fi
  fi
}

# set_peer_pubkey — заменяет PublicKey в блоке пира
set_peer_pubkey() {
  local name="$1" newkey="$2"
  local tmp
  tmp="$(make_temp)"
  awk -v name="${name}" -v key="${newkey}" '
    $0 == "# " name { inb=1; print; next }
    inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
    inb && /^\[Interface\]/ { inb=0 }
    inb && /^[# ]*PublicKey[[:space:]]*=/ {
      print "PublicKey = " key; next
    }
    { print }
  ' "${WG_CONF}" >"${tmp}" && mv -- "${tmp}" "${WG_CONF}"
}

# set_peer_allowed_ips — заменяет AllowedIPs в блоке пира
set_peer_allowed_ips() {
  local name="$1" newips="$2"
  local tmp
  tmp="$(make_temp)"
  awk -v name="${name}" -v ips="${newips}" '
    $0 == "# " name { inb=1; print; next }
    inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
    inb && /^\[Interface\]/ { inb=0 }
    inb && /^[# ]*AllowedIPs[[:space:]]*=/ {
      print "AllowedIPs = " ips; next
    }
    { print }
  ' "${WG_CONF}" >"${tmp}" && mv -- "${tmp}" "${WG_CONF}"
}

# set_peer_keepalive — заменяет PersistentKeepalive
set_peer_keepalive() {
  local name="$1" ka="$2"
  local tmp
  tmp="$(make_temp)"
  awk -v name="${name}" -v ka="${ka}" '
    $0 == "# " name { inb=1; print; next }
    inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
    inb && /^\[Interface\]/ { inb=0 }
    inb && /^[# ]*PersistentKeepalive[[:space:]]*=/ {
      if (ka == "") next
      print "PersistentKeepalive = " ka; next
    }
    { print }
  ' "${WG_CONF}" >"${tmp}" && mv -- "${tmp}" "${WG_CONF}"
}

# peer_is_disabled — маркер DISABLED в блоке
peer_is_disabled() {
  local name="$1"
  extract_peer_block "${name}" | grep -q '^# DISABLED'
}

# peer_is_expired — срок истёк (ts > 0 и < now)
peer_is_expired() {
  local name="$1"
  local ts now
  ts="$(expiry_get "${name}")"
  [[ -n "${ts}" && "${ts}" != "0" ]] || return 1
  now="$(date +%s)"
  (( ts < now ))
}

# ==================== УСТАНОВКА ====================

# check_installed — показывает состояние компонентов
check_installed() {
  section "$(t 'Проверка компонентов' 'Component check')"
  local pkgs=(wireguard wireguard-tools qrencode iptables)
  local p st
  for p in "${pkgs[@]}"; do
    if dpkg -s "${p}" >/dev/null 2>&1; then
      st="$(dpkg -s "${p}" 2>/dev/null | awk -F': ' '/^Version:/ {print $2}')"
      printf '  %b✔%b %-18s %s\n' "${GREEN}" "${NC}" "${p}" "${st}"
    else
      printf '  %b✖%b %-18s %s\n' "${RED}" "${NC}" "${p}" "$(t 'не установлен' 'not installed')"
    fi
  done
  if command -v wg >/dev/null 2>&1; then
    printf '  %b✔%b %-18s %s\n' "${GREEN}" "${NC}" "wg" "$(wg --version 2>/dev/null | head -1)"
  fi
  if command -v wg-quick >/dev/null 2>&1; then
    printf '  %b✔%b %-18s\n' "${GREEN}" "${NC}" "wg-quick"
  fi
}

# install_wireguard — ставит пакеты через apt
install_wireguard() {
  section "$(t 'Установка WireGuard' 'Installing WireGuard')"
  export DEBIAN_FRONTEND=noninteractive
  info "$(t 'Обновление индекса apt...' 'Updating apt index...')"
  apt-get update -qq || die "$(t 'apt-get update завершился с ошибкой' 'apt-get update failed')"
  info "$(t 'Установка wireguard wireguard-tools qrencode iptables...' 'Installing wireguard wireguard-tools qrencode iptables...')"
  apt-get install -y -qq wireguard wireguard-tools qrencode iptables \
    || die "$(t 'Не удалось установить пакеты' 'Package installation failed')"
  if ! command -v curl >/dev/null 2>&1; then
    apt-get install -y -qq curl || true
  fi
  info "$(t 'Установка завершена' 'Installation complete')"
  log INFO "install_wireguard: ok"
  check_installed
}

# update_wireguard — обновляет WireGuard до последней версии в репозитории
update_wireguard() {
  section "$(t 'Обновление WireGuard' 'Updating WireGuard')"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || die "$(t 'apt-get update завершился с ошибкой' 'apt-get update failed')"
  apt-get install -y -qq --only-upgrade wireguard wireguard-tools \
    || warn "$(t 'Обновление не выполнено (пакеты, возможно, уже актуальны)' 'Upgrade failed (packages may be up to date)')"
  check_installed
}

# ==================== ИНИЦИАЛИЗАЦИЯ ====================

# generate_server_keys — генерирует ключи сервера (umask 077)
generate_server_keys() {
  local priv pub
  umask 077
  priv="$(wg genkey)" || die "$(t 'Не удалось сгенерировать приватный ключ' 'Failed to generate private key')"
  pub="$(printf '%s' "${priv}" | wg pubkey)" || die "$(t 'Не удалось вычислить публичный ключ' 'Failed to compute public key')"
  printf '%s\n' "${priv}" >"${SERVER_PRIVATE_KEY}"
  chmod 600 "${SERVER_PRIVATE_KEY}"
  printf '%s\n' "${pub}" >"${SERVER_PUBLIC_KEY}"
  chmod 644 "${SERVER_PUBLIC_KEY}"
  log INFO "generate_server_keys: keys written to ${WG_DIR}"
}

# enable_ip_forward — включает форвардинг через sysctl.d
enable_ip_forward() {
  mkdir -p /etc/sysctl.d
  cat > /etc/sysctl.d/99-wireguard.conf <<'EOF'
# wg-admin.sh: IP forwarding для WireGuard
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
  sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null 2>&1 \
    || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 \
    || die "$(t 'Не удалось включить ip_forward' 'Failed to enable ip_forward')"
  log INFO "enable_ip_forward: ok"
}

# setup_nat — iptables MASQUERADE + FORWARD для внешнего интерфейса
setup_nat() {
  local ext_if="$1"
  local net="$2"
  iptables -t nat -C POSTROUTING -s "${net}" -o "${ext_if}" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "${net}" -o "${ext_if}" -j MASQUERADE \
    || die "$(t 'Не удалось добавить MASQUERADE' 'Failed to add MASQUERADE')"
  iptables -C FORWARD -i "${WG_IF}" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "${WG_IF}" -j ACCEPT
  iptables -C FORWARD -o "${WG_IF}" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -o "${WG_IF}" -j ACCEPT
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  else
    mkdir -p /etc/iptables
    iptables-save >/etc/iptables/rules.v4 2>/dev/null || true
  fi
  log INFO "setup_nat: MASQUERADE ${net} via ${ext_if}"
}

# apply_config — применяет конфиг без разрыва активных сессий
apply_config() {
  local stripped
  if ! command -v wg-quick >/dev/null 2>&1 || ! command -v wg >/dev/null 2>&1; then
    warn "$(t 'wg / wg-quick не найдены — конфиг не применён' 'wg / wg-quick not found — config not applied')"
    return 1
  fi
  if ! stripped="$(wg-quick strip "${WG_IF}" 2>/dev/null)"; then
    warn "$(t "Синтаксис ${WG_CONF} некорректен — применение отменено" "${WG_CONF} syntax error — apply aborted")"
    return 1
  fi
  if ip link show "${WG_IF}" >/dev/null 2>&1; then
    if wg syncconf "${WG_IF}" <(printf '%s\n' "${stripped}"); then
      info "$(t "Конфиг применён (wg syncconf, без разрыва)" "Config applied (wg syncconf, no downtime)")"
      log INFO "apply_config: syncconf ok"
      return 0
    fi
    warn "$(t 'wg syncconf не удался, пробую wg-quick up' 'wg syncconf failed, trying wg-quick up')"
  fi
  if wg-quick up "${WG_IF}"; then
    info "$(t "Интерфейс ${WG_IF} поднят" "Interface ${WG_IF} is up")"
    log INFO "apply_config: wg-quick up ok"
    return 0
  fi
  warn "$(t 'Не удалось применить конфиг' 'Failed to apply config')"
  return 1
}

# init_server — интерактивная инициализация сервера
init_server() {
  section "$(t 'Инициализация сервера' 'Server initialization')"
  if [[ -f "${WG_CONF}" ]]; then
    warn "$(t "Конфиг ${WG_CONF} уже существует" "${WG_CONF} already exists")"
    if ! confirm "$(t 'Перезаписать конфигурацию? (y/N): ' 'Overwrite configuration? (y/N): ')"; then
      info "$(t 'Инициализация отменена' 'Initialization cancelled')"
      return 0
    fi
    # бэкап существующего
    cp -a "${WG_CONF}" "${WG_CONF}.bak.$(date +%s)" 2>/dev/null || true
  fi

  local def_if ext_if vpn_net vpn_ip port dns mtu
  def_if="$(detect_interface)"
  ext_if="$(prompt_value "$(t 'Внешний интерфейс' 'External interface')" "${def_if}")"
  validate_iface "${ext_if}" || die "$(t "Интерфейс ${ext_if} не найден" "Interface ${ext_if} not found")"
  vpn_net="$(prompt_value "$(t 'VPN-подсеть' 'VPN subnet')" "${VPN_SUBNET}")"
  validate_cidr "${vpn_net}" || die "$(t "Некорректная подсеть: ${vpn_net}" "Invalid subnet: ${vpn_net}")"
  vpn_ip="$(prompt_value "$(t 'VPN IP сервера' 'Server VPN IP')" "${SERVER_VPN_IP}")"
  validate_ip "${vpn_ip}" || die "$(t "Некорректный IP: ${vpn_ip}" "Invalid IP: ${vpn_ip}")"
  port="$(prompt_value "$(t 'Порт UDP' 'UDP port')" "${WG_PORT}")"
  validate_port "${port}" || die "$(t "Некорректный порт: ${port}" "Invalid port: ${port}")"
  dns="$(prompt_value "$(t 'DNS' 'DNS')" "${DNS_DEFAULT}")"
  validate_ip "${dns}" || die "$(t "Некорректный DNS: ${dns}" "Invalid DNS: ${dns}")"
  mtu="$(prompt_value "$(t 'MTU (пусто = авто)' 'MTU (empty = auto)')" "${MTU_DEFAULT}")"

  mkdir -p "${WG_DIR}" "${CLIENTS_DIR}"
  chmod 700 "${WG_DIR}" "${CLIENTS_DIR}"
  generate_server_keys

  local priv pub
  priv="$(cat "${SERVER_PRIVATE_KEY}")"
  pub="$(cat "${SERVER_PUBLIC_KEY}")"

  local ext_ip
  ext_ip="$(external_ip)"

  umask 077
  {
    printf '# wg-admin.sh v%s\n' "${VERSION}"
    printf '# Создан: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '# Внешний интерфейс: %s\n' "${ext_if}"
    printf '\n[Interface]\n'
    printf 'Address = %s/32\n' "${vpn_ip}"
    printf 'ListenPort = %s\n' "${port}"
    printf 'PrivateKey = %s\n' "${priv}"
    printf 'SaveConfig = false\n'
    printf 'PostUp = iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE; iptables -A FORWARD -i %s -j ACCEPT; iptables -A FORWARD -o %s -j ACCEPT\n' \
      "${vpn_net}" "${ext_if}" "${WG_IF}" "${WG_IF}"
    printf 'PreDown = iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE; iptables -D FORWARD -i %s -j ACCEPT; iptables -D FORWARD -o %s -j ACCEPT\n' \
      "${vpn_net}" "${ext_if}" "${WG_IF}" "${WG_IF}"
  } >"${WG_CONF}"
  chmod 600 "${WG_CONF}"

  # доп. MTU — только если задан явно
  if [[ -n "${mtu}" ]]; then
    sed -i "/^PrivateKey = /a MTU = ${mtu}" "${WG_CONF}"
  fi

  enable_ip_forward
  setup_nat "${ext_if}" "${vpn_net}"

  systemctl enable "wg-quick@${WG_IF}" >/dev/null 2>&1 \
    || warn "$(t 'Не удалось включить автозапуск' 'Failed to enable autostart')"
  systemctl start "wg-quick@${WG_IF}" \
    || warn "$(t 'Не удалось запустить сервис' 'Failed to start service')"

  # сохраняем рабочие значения в настройки
  VPN_SUBNET="${vpn_net}"
  WG_PORT="${port}"
  DNS_DEFAULT="${dns}"
  SERVER_VPN_IP="${vpn_ip}"
  save_settings

  # проверка конфига
  if wg-quick strip "${WG_IF}" >/dev/null 2>&1; then
    info "$(t 'Конфиг проверен: OK' 'Config check: OK')"
  else
    warn "$(t 'Проверка конфига: ошибки' 'Config check: errors')"
  fi

  info "$(t "Сервер инициализирован" "Server initialized")"
  info "$(t "Публичный ключ: ${pub}" "Public key: ${pub}")"
  if [[ -n "${ext_ip}" ]]; then
    info "$(t "Внешний адрес: ${ext_ip}:${port}" "External endpoint: ${ext_ip}:${port}")"
  fi
  log INFO "init_server: configured iface=${ext_if} net=${vpn_net} port=${port}"
}

# ==================== УПРАВЛЕНИЕ КЛИЕНТАМИ ====================

# generate_client_keys — создаёт ключевую пару клиента; печатает "priv pub"
generate_client_keys() {
  local priv pub
  umask 077
  priv="$(wg genkey)" || return 1
  pub="$(printf '%s' "${priv}" | wg pubkey)" || return 1
  printf '%s %s' "${priv}" "${pub}"
}

# write_client_config — сохраняет конфиг клиента в CLIENTS_DIR
write_client_config() {
  local name="$1" client_priv="$2" server_pub="$3" endpoint="$4" client_ip="$5"
  local allowed="$6" dns="$7" keepalive="$8" mtu="$9"
  local conf="${CLIENTS_DIR}/${name}.conf"
  umask 077
  {
    printf '# wg-admin.sh client: %s\n' "${name}"
    printf '# Создан: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '\n[Interface]\n'
    printf 'PrivateKey = %s\n' "${client_priv}"
    printf 'Address = %s/32\n' "${client_ip}"
    if [[ -n "${dns}" ]]; then
      printf 'DNS = %s\n' "${dns}"
    fi
    if [[ -n "${mtu}" ]]; then
      printf 'MTU = %s\n' "${mtu}"
    fi
    printf '\n[Peer]\n'
    printf 'PublicKey = %s\n' "${server_pub}"
    printf 'AllowedIPs = %s\n' "${allowed}"
    printf 'Endpoint = %s\n' "${endpoint}"
    if [[ -n "${keepalive}" ]]; then
      printf 'PersistentKeepalive = %s\n' "${keepalive}"
    fi
  } >"${conf}"
  chmod 600 "${conf}"
  printf '%s' "${conf}"
}

# next_free_ip — первый свободный IP в VPN-подсети (начиная с .2)
next_free_ip() {
  local net="${VPN_SUBNET}"
  local base prefix
  base="${net%%/*}"
  prefix="${net##*/}"
  local a b c d
  IFS=. read -r a b c d <<<"${base}"
  # считаем адрес сети
  local mask=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))
  local n=$(( (a << 24 | b << 16 | c << 8 | d) & mask ))
  local used i ip_candidate
  used="$( (grep -Eho '([0-9]{1,3}\.){3}[0-9]{1,3}' "${WG_CONF}" "${EXPIRY_DB}" 2>/dev/null || true); \
           grep -Eho 'Address = ([0-9]{1,3}\.){3}[0-9]{1,3}' "${CLIENTS_DIR}"/*.conf 2>/dev/null | awk '{print $3}' || true )"
  for (( i = 2; i < 254; i++ )); do
    ip_candidate="$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( i ))"
    if ! grep -Fxq "${ip_candidate}" <<<"${used}" && [[ "${ip_candidate}" != "${SERVER_VPN_IP}" ]]; then
      printf '%s' "${ip_candidate}"
      return 0
    fi
  done
  return 1
}

# add_client — интерактивное добавление клиента (пункт 3.1)
add_client() {
  section "$(t 'Добавление клиента' 'Add client')"
  if [[ ! -f "${WG_CONF}" ]]; then
    die "$(t "Сначала выполните инициализацию сервера (пункт 2)" "Initialize the server first (menu 2)")"
  fi
  mkdir -p "${CLIENTS_DIR}"
  chmod 700 "${CLIENTS_DIR}"

  # 1. имя
  local name
  while true; do
    name="$(prompt_value "$(t 'Имя клиента (pc1, laptop-ivan, ...)' 'Client name (pc1, laptop-ivan, ...)')" "")"
    if validate_name "${name}"; then
      if peer_exists "${name}"; then
        warn "$(t "Клиент ${name} уже существует" "Client ${name} already exists")"
        continue
      fi
      if [[ -f "${CLIENTS_DIR}/${name}.conf" ]]; then
        warn "$(t "Файл ${CLIENTS_DIR}/${name}.conf уже есть" "${CLIENTS_DIR}/${name}.conf already exists")"
        continue
      fi
      break
    fi
    warn "$(t 'Недопустимое имя (разрешены буквы, цифры, _ и -)' 'Invalid name (letters, digits, _ and - allowed)')"
  done

  # 2. VPN IP
  local def_ip client_ip
  def_ip="$(next_free_ip 2>/dev/null || echo "")"
  while true; do
    client_ip="$(prompt_value "$(t 'VPN IP клиента' 'Client VPN IP')" "${def_ip}")"
    validate_ip "${client_ip}" || { warn "$(t 'Некорректный IP' 'Invalid IP')"; continue; }
    if [[ "${client_ip}" == "${SERVER_VPN_IP}" ]]; then
      warn "$(t 'IP сервера занят — выберите другой' 'Server IP is taken — choose another')"
      continue
    fi
    if grep -q "AllowedIPs = ${client_ip}/32" "${WG_CONF}" 2>/dev/null; then
      warn "$(t "IP ${client_ip} уже назначен другому пиру" "IP ${client_ip} is already assigned")"
      continue
    fi
    break
  done

  # 3. публичный ключ
  local pubkey priv pub
  pubkey="$(prompt_value "$(t 'Публичный ключ (пусто = сгенерировать)' 'Public key (empty = generate)')" "")"
  if [[ -z "${pubkey}" ]]; then
    read -r priv pub <<<"$(generate_client_keys)" \
      || die "$(t 'Не удалось сгенерировать ключи' 'Key generation failed')"
  else
    [[ "${pubkey}" =~ ^[A-Za-z0-9+/]{42,44}=$ ]] \
      || die "$(t "Некорректный публичный ключ" "Invalid public key")"
    priv=""
  fi

  # 4. внешний адрес сервера
  local def_ext ext_addr
  def_ext="$(external_ip)"
  ext_addr="$(prompt_value "$(t 'Внешний адрес сервера' 'Server external address')" "${def_ext}")"

  # 5. порт
  local port
  port="$(prompt_value "$(t 'Порт сервера' 'Server port')" "${WG_PORT}")"
  validate_port "${port}" || die "$(t "Некорректный порт: ${port}" "Invalid port: ${port}")"

  # 6. режим маршрутизации
  local allowed mode
  printf '%s\n' "$(t 'Режим маршрутизации:' 'Routing mode:')"
  printf '  1) %s  ← %s\n' "$(t 'Только VPN-сеть' 'VPN network only') (${VPN_SUBNET})" "$(t 'по умолчанию' 'default')"
  printf '  2) %s\n' "$(t 'Весь трафик через VPN' 'All traffic via VPN') (0.0.0.0/0)"
  printf '  3) %s\n' "$(t 'VPN + указанные подсети' 'VPN + specified subnets')"
  printf '  4) %s\n' "$(t 'Свой вариант (CIDR вручную)' 'Custom (manual CIDR)')"
  read -r -p "$(t 'Выбор [1]: ' 'Choice [1]: ')" mode || exit 0
  mode="${mode:-1}"
  case "${mode}" in
    2) allowed="0.0.0.0/0" ;;
    3)
      local extra
      extra="$(prompt_value "$(t 'Дополнительные подсети через запятую' 'Extra subnets, comma-separated')" "")"
      allowed="${VPN_SUBNET}"
      local s
      IFS=',' read -ra _subs <<<"${extra}"
      for s in "${_subs[@]}"; do
        s="$(echo "${s}" | tr -d '[:space:]')"
        [[ -z "${s}" ]] && continue
        validate_cidr "${s}" || die "$(t "Некорректный CIDR: ${s}" "Invalid CIDR: ${s}")"
        allowed="${allowed}, ${s}"
      done
      ;;
    4)
      allowed="$(prompt_value "$(t 'AllowedIPs (CIDR через запятую)' 'AllowedIPs (comma-separated CIDR)')" "${VPN_SUBNET}")"
      ;;
    *) allowed="${VPN_SUBNET}" ;;
  esac

  # 7. DNS
  local dns
  dns="$(prompt_value "$(t 'DNS' 'DNS')" "${DNS_DEFAULT}")"

  # 8. PersistentKeepalive
  local keepalive
  keepalive="$(prompt_value "$(t 'PersistentKeepalive' 'PersistentKeepalive')" "${CLIENT_KEEPALIVE}")"
  [[ "${keepalive}" =~ ^[0-9]+$ ]] || keepalive="${CLIENT_KEEPALIVE}"

  # 9. MTU
  local mtu
  mtu="$(prompt_value "$(t 'MTU (пусто = авто)' 'MTU (empty = auto)')" "")"

  # 10. срок действия
  local exp_str exp_ts
  exp_str="$(prompt_value "$(t 'Срок действия (30d / 12h / never / YYYY-MM-DD)' 'Expiry (30d / 12h / never / YYYY-MM-DD)')" "never")"
  exp_ts="$(parse_duration "${exp_str}")" \
    || die "$(t "Не удалось разобрать срок: ${exp_str}" "Cannot parse expiry: ${exp_str}")"

  # 11. комментарий
  local comment
  comment="$(prompt_value "$(t 'Комментарий (описание)' 'Comment (description)')" "")"

  # 12. QR
  local want_qr=false
  if ask_yes_no "$(t 'Показать QR-код?' 'Show QR code?')"; then
    want_qr=true
  fi

  # --- создание ---
  local server_pub endpoint
  server_pub="$(cat "${SERVER_PUBLIC_KEY}" 2>/dev/null)" \
    || die "$(t "Нет публичного ключа сервера (${SERVER_PUBLIC_KEY})" "Missing server public key (${SERVER_PUBLIC_KEY})")"
  endpoint="${ext_addr}:${port}"

  local conf_path=""
  if [[ -n "${priv}" ]]; then
    conf_path="$(write_client_config "${name}" "${priv}" "${server_pub}" "${endpoint}" \
      "${client_ip}" "${allowed}" "${dns}" "${keepalive}" "${mtu}")"
    chmod 600 "${conf_path}"
    info "$(t "Файл клиента: ${conf_path}" "Client config: ${conf_path}")"
  else
    # импорт чужого ключа — файл без приватного ключа не имеет смысла
    warn "$(t 'Приватный ключ не сгенерирован — конфиг клиента не сохранён (импорт ключа)' 'No private key generated — client config not saved (key import)')"
  fi

  append_peer_block "${name}" "${pubkey:-${pub}}" "${client_ip}/32" "${keepalive}" "${exp_ts}"
  if [[ -n "${comment}" ]]; then
    local tmp
    tmp="$(make_temp)"
    awk -v name="${name}" -v c="${comment}" '
      $0 == "# " name { print; print "# COMMENT " c; next }
      { print }
    ' "${WG_CONF}" >"${tmp}" && mv -- "${tmp}" "${WG_CONF}"
  fi
  expiry_set "${name}" "${exp_ts}"
  apply_config || warn "$(t 'Конфиг не применён — проверьте wg0.conf' 'Config not applied — check wg0.conf')"

  info "$(t "Создан клиент: ${name} (${client_ip}/32)" "Client created: ${name} (${client_ip}/32)")"
  if [[ "${exp_ts}" != "0" ]]; then
    info "$(t "Срок действия: $(fmt_ts "${exp_ts}")" "Expires: $(fmt_ts "${exp_ts}")")"
  fi
  if ${want_qr} && [[ -n "${conf_path}" && -f "${conf_path}" ]]; then
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -t ansiutf8 <"${conf_path}"
    else
      warn "$(t 'qrencode не установлен' 'qrencode is not installed')"
    fi
  fi
  log INFO "add_client: name=${name} ip=${client_ip} expires=${exp_ts}"
}

# list_clients — список клиентов с фильтрами и экспортом CSV (3.2)
list_clients() {
  section "$(t 'Список клиентов' 'Client list')"
  if [[ ! -f "${WG_CONF}" ]]; then
    warn "$(t 'Конфиг сервера не найден' 'Server config not found')"
    return 1
  fi
  printf '%s\n' "$(t 'Фильтр: 1) все  2) активные  3) отключённые  4) истёкшие' 'Filter: 1) all  2) active  3) disabled  4) expired')"
  local flt
  read -r -p "$(t 'Выбор [1]: ' 'Choice [1]: ')" flt || exit 0
  flt="${flt:-1}"

  local name
  local rows=0
  local csv
  csv="$(make_temp)"
  printf 'name,ip,status,expires,comment\n' >"${csv}"

  printf '%-18s %-16s %-12s %-18s %s\n' \
    "$(t 'Имя' 'Name')" "$(t 'IP' 'IP')" "$(t 'Статус' 'Status')" "$(t 'Срок' 'Expires')" "$(t 'Комментарий' 'Comment')"
  printf '%s\n' "--------------------------------------------------------------"

  while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    local ip status expires comment
    ip="$(peer_field "${name}" AllowedIPs | cut -d/ -f1)"
    expires="$(expiry_get "${name}")"
    [[ -z "${expires}" ]] && expires="$(peer_field "${name}" EXPIRES)"
    comment="$(extract_peer_block "${name}" | awk '/^# COMMENT /{sub(/^# COMMENT /,""); print; exit}')"
    if peer_is_disabled "${name}"; then
      status="disabled"
    elif peer_is_expired "${name}"; then
      status="expired"
    else
      status="active"
    fi
    case "${flt}" in
      2) [[ "${status}" == "active" ]] || continue ;;
      3) [[ "${status}" == "disabled" ]] || continue ;;
      4) [[ "${status}" == "expired" ]] || continue ;;
    esac
    printf '%-18s %-16s %-12s %-18s %s\n' \
      "${name}" "${ip}" "${status}" "$(fmt_ts "${expires}")" "${comment}"
    printf '%s,%s,%s,%s,%s\n' "${name}" "${ip}" "${status}" "${expires:-0}" "${comment}" >>"${csv}"
    rows=$((rows + 1))
  done < <(peer_names)

  printf '%s\n' "--------------------------------------------------------------"
  info "$(t "Всего: ${rows}" "Total: ${rows}")"
  if ask_yes_no "$(t 'Экспортировать в CSV?' 'Export to CSV?')"; then
    local out
    out="$(prompt_value "$(t 'Файл для экспорта' 'Export file')" "./wg-clients.csv")"
    cp -- "${csv}" "${out}" && chmod 600 "${out}" && info "$(t "CSV: ${out}" "CSV: ${out}")"
  fi
}

# toggle_client — отключить/включить клиента (3.5)
toggle_client() {
  section "$(t 'Отключить / включить клиента' 'Disable / enable client')"
  local name
  name="$(prompt_value "$(t 'Имя клиента' 'Client name')" "")"
  validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
  peer_exists "${name}" || die "$(t "Клиент ${name} не найден" "Client ${name} not found")"
  if peer_is_disabled "${name}"; then
    uncomment_peer_lines "${name}"
    info "$(t "Клиент ${name} включён" "Client ${name} enabled")"
  else
    comment_peer_lines "${name}"
    info "$(t "Клиент ${name} отключён" "Client ${name} disabled")"
  fi
  apply_config || true
}

# remove_client — удаление клиента: одного / нескольких / всех неактивных (3.4)
remove_client() {
  section "$(t 'Удаление клиента' 'Remove client')"
  printf '  1) %s\n' "$(t 'Один клиент' 'Single client')"
  printf '  2) %s\n' "$(t 'Несколько клиентов (через пробел)' 'Several clients (space-separated)')"
  printf '  3) %s\n' "$(t 'Все неактивные (отключённые/истёкшие)' 'All inactive (disabled/expired)')"
  printf '  4) %s\n' "$(t 'Назад' 'Back')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  local to_remove=()
  case "${ch}" in
    1)
      local name
      name="$(prompt_value "$(t 'Имя клиента' 'Client name')" "")"
      validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
      peer_exists "${name}" || die "$(t "Клиент ${name} не найден" "Client ${name} not found")"
      to_remove=("${name}")
      ;;
    2)
      local names
      names="$(prompt_value "$(t 'Имена через пробел' 'Names, space-separated')" "")"
      local n
      for n in ${names}; do
        if peer_exists "${n}"; then
          to_remove+=("${n}")
        else
          warn "$(t "Пропуск: ${n} не найден" "Skip: ${n} not found")"
        fi
      done
      ;;
    3)
      local n
      while IFS= read -r n; do
        [[ -z "${n}" ]] && continue
        if peer_is_disabled "${n}" || peer_is_expired "${n}"; then
          to_remove+=("${n}")
        fi
      done < <(peer_names)
      ;;
    *) return 0 ;;
  esac
  if (( ${#to_remove[@]} == 0 )); then
    info "$(t 'Нечего удалять' 'Nothing to remove')"
    return 0
  fi
  info "$(t "Будут удалены: ${to_remove[*]}" "Will remove: ${to_remove[*]}")"
  confirm "$(t 'Удалить? (y/N): ' 'Delete? (y/N): ')" || { info "$(t 'Отмена' 'Cancelled')"; return 0; }
  local name
  for name in "${to_remove[@]}"; do
    remove_peer_block "${name}"
    rm -f -- "${CLIENTS_DIR}/${name}.conf" 2>/dev/null || true
    expiry_set "${name}" "" 2>/dev/null || true
    # вычистить запись из expiry.db
    if [[ -f "${EXPIRY_DB}" ]]; then
      local tmp
      tmp="$(make_temp)"
      awk -F: -v n="${name}" '$1!=n' "${EXPIRY_DB}" >"${tmp}" && mv -- "${tmp}" "${EXPIRY_DB}"
    fi
    info "$(t "Удалён: ${name}" "Removed: ${name}")"
    log INFO "remove_client: ${name}"
  done
  apply_config || true
}

# edit_client — редактирование клиента (3.3)
edit_client() {
  section "$(t 'Редактирование клиента' 'Edit client')"
  local name
  name="$(prompt_value "$(t 'Имя клиента' 'Client name')" "")"
  validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
  peer_exists "${name}" || die "$(t "Клиент ${name} не найден" "Client ${name} not found")"

  local cur_ip cur_pub cur_ka cur_exp cur_comment
  cur_ip="$(peer_field "${name}" AllowedIPs)"
  cur_pub="$(peer_field "${name}" PublicKey)"
  cur_ka="$(peer_field "${name}" PersistentKeepalive)"
  cur_exp="$(expiry_get "${name}")"
  cur_comment="$(extract_peer_block "${name}" | awk '/^# COMMENT /{sub(/^# COMMENT /,""); print; exit}')"

  info "$(t "Текущие данные ${name}:" "Current data ${name}:")"
  printf '  IP/AllowedIPs: %s\n' "${cur_ip}"
  printf '  PublicKey:     %s\n' "${cur_pub}"
  printf '  Keepalive:     %s\n' "${cur_ka:-—}"
  printf '  Expires:       %s\n' "$(fmt_ts "${cur_exp:-0}")"
  printf '  Comment:       %s\n' "${cur_comment:-—}"
  printf '\n'
  printf '  1) %s\n' "$(t 'Изменить IP' 'Change IP')"
  printf '  2) %s\n' "$(t 'Изменить публичный ключ' 'Change public key')"
  printf '  3) %s\n' "$(t 'Изменить PersistentKeepalive' 'Change PersistentKeepalive')"
  printf '  4) %s\n' "$(t 'Изменить срок действия' 'Change expiry')"
  printf '  5) %s\n' "$(t 'Изменить комментарий' 'Change comment')"
  printf '  6) %s\n' "$(t 'Перегенерировать ключи клиента' 'Regenerate client keys')"
  printf '  7) %s\n' "$(t 'Назад' 'Back')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1)
      local newip
      newip="$(prompt_value "$(t 'Новый VPN IP' 'New VPN IP')" "${cur_ip%%/*}")"
      validate_ip "${newip}" || die "$(t 'Некорректный IP' 'Invalid IP')"
      set_peer_allowed_ips "${name}" "${newip}/32"
      # синхронизировать конфиг клиента
      if [[ -f "${CLIENTS_DIR}/${name}.conf" ]]; then
        sed -i "s/^Address = .*/Address = ${newip}\/32/" "${CLIENTS_DIR}/${name}.conf"
      fi
      info "$(t "IP обновлён: ${newip}" "IP updated: ${newip}")"
      ;;
    2)
      local newpub
      newpub="$(prompt_value "$(t 'Новый публичный ключ' 'New public key')" "")"
      [[ "${newpub}" =~ ^[A-Za-z0-9+/]{42,44}=$ ]] || die "$(t 'Некорректный ключ' 'Invalid key')"
      set_peer_pubkey "${name}" "${newpub}"
      info "$(t 'Ключ обновлён' 'Key updated')"
      ;;
    3)
      local newka
      newka="$(prompt_value "$(t 'PersistentKeepalive (пусто = убрать)' 'PersistentKeepalive (empty = remove)')" "${cur_ka}")"
      set_peer_keepalive "${name}" "${newka}"
      info "$(t 'Keepalive обновлён' 'Keepalive updated')"
      ;;
    4)
      set_expiry "${name}"
      ;;
    5)
      local newc
      newc="$(prompt_value "$(t 'Комментарий' 'Comment')" "${cur_comment}")"
      local tmp
      tmp="$(make_temp)"
      awk -v name="${name}" -v c="${newc}" '
        $0 == "# " name { print; next }
        { if (p && /^# COMMENT /) next }
        /^# COMMENT / && prev_name { next }
        { print }
      ' "${WG_CONF}" >"${tmp}" 2>/dev/null || true
      # проще: перезаписать комментарий точечно
      tmp="$(make_temp)"
      extract_peer_block "${name}" | awk -v c="${newc}" '
        /^# COMMENT / { if (!done) { if (c != "") print "# COMMENT " c; done=1 }; next }
        { print }
        END { if (!done && c != "") print "# COMMENT " c }
      ' >"${tmp}.blk"
      local full
      full="$(make_temp)"
      awk -v name="${name}" -v blk="${tmp}.blk" '
        $0 == "# " name { print; while ((getline line < blk) > 0) print line; inb=1; next }
        inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
        inb && /^\[Interface\]/ { inb=0 }
        inb { next }
        { print }
      ' "${WG_CONF}" >"${full}" && mv -- "${full}" "${WG_CONF}"
      info "$(t 'Комментарий обновлён' 'Comment updated')"
      ;;
    6)
      local priv pub
      read -r priv pub <<<"$(generate_client_keys)" \
        || die "$(t 'Ошибка генерации ключей' 'Key generation error')"
      set_peer_pubkey "${name}" "${pub}"
      if [[ -f "${CLIENTS_DIR}/${name}.conf" ]]; then
        sed -i "s/^PrivateKey = .*/PrivateKey = ${priv}/" "${CLIENTS_DIR}/${name}.conf"
        chmod 600 "${CLIENTS_DIR}/${name}.conf"
      else
        warn "$(t 'Файл конфига клиента не найден — создайте его заново' 'Client config file not found — recreate it')"
      fi
      info "$(t 'Ключи клиента перегенерированы' 'Client keys regenerated')"
      ;;
    *) return 0 ;;
  esac
  apply_config || true
}

# show_client_config — вывод конфига / QR / сохранение (3.7)
show_client_config() {
  section "$(t 'Конфиг клиента' 'Client config')"
  local name
  name="$(prompt_value "$(t 'Имя клиента' 'Client name')" "")"
  validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
  local conf="${CLIENTS_DIR}/${name}.conf"
  if [[ ! -f "${conf}" ]]; then
    warn "$(t "Файл ${conf} не найден" "${conf} not found")"
    return 1
  fi
  printf '  1) %s\n' "$(t 'Показать в терминале' 'Print to terminal')"
  printf '  2) %s\n' "$(t 'Показать QR-код' 'Show QR code')"
  printf '  3) %s\n' "$(t 'Сохранить в файл' 'Save to file')"
  printf '  4) %s\n' "$(t 'Назад' 'Back')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1)
      printf '\n'
      cat -- "${conf}"
      printf '\n'
      ;;
    2)
      if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ansiutf8 <"${conf}"
      else
        warn "$(t 'qrencode не установлен' 'qrencode is not installed')"
      fi
      ;;
    3)
      local out
      out="$(prompt_value "$(t 'Куда сохранить' 'Save as')" "./${name}.conf")"
      cp -- "${conf}" "${out}" && chmod 600 "${out}" \
        && info "$(t "Сохранено: ${out}" "Saved: ${out}")"
      ;;
  esac
}

# ==================== СРОК ДЕЙСТВИЯ ====================

# set_expiry — установить срок действия клиента (3.6)
set_expiry() {
  local name="${1:-}"
  if [[ -z "${name}" ]]; then
    name="$(prompt_value "$(t 'Имя клиента' 'Client name')" "")"
    validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
  fi
  peer_exists "${name}" || die "$(t "Клиент ${name} не найден" "Client ${name} not found")"
  local cur
  cur="$(expiry_get "${name}")"
  info "$(t "Текущий срок: $(fmt_ts "${cur:-0}")" "Current expiry: $(fmt_ts "${cur:-0}")")"
  local s ts
  s="$(prompt_value "$(t 'Новый срок (30d / 12h / never / YYYY-MM-DD)' 'New expiry (30d / 12h / never / YYYY-MM-DD)')" "never")"
  ts="$(parse_duration "${s}")" || die "$(t "Не удалось разобрать: ${s}" "Cannot parse: ${s}")"
  expiry_set "${name}" "${ts}"
  if [[ "${ts}" == "0" ]]; then
    info "$(t "Срок сброшен (бессрочно)" "Expiry reset (never)")"
    # продление/сброс автоматически включает пира
    if peer_is_disabled "${name}"; then
      uncomment_peer_lines "${name}"
    fi
  else
    info "$(t "Срок установлен: $(fmt_ts "${ts}")" "Expiry set: $(fmt_ts "${ts}")")"
  fi
  apply_config || true
  log INFO "set_expiry: ${name} -> ${ts}"
}

# extend_expiry — продлить срок на N дней от текущего
extend_expiry() {
  section "$(t 'Продление срока' 'Extend expiry')"
  local name days cur ts
  name="$(prompt_value "$(t 'Имя клиента' 'Client name')" "")"
  validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
  peer_exists "${name}" || die "$(t "Клиент ${name} не найден" "Client ${name} not found")"
  days="$(prompt_value "$(t 'На сколько дней продлить' 'Extend by (days)')" "30")"
  [[ "${days}" =~ ^[0-9]+$ ]] || die "$(t "Некорректное число дней: ${days}" "Invalid days: ${days}")"
  cur="$(expiry_get "${name}")"
  local now base
  now="$(date +%s)"
  if [[ -n "${cur}" && "${cur}" != "0" && "${cur}" -gt "${now}" ]]; then
    base="${cur}"
  else
    base="${now}"
  fi
  ts=$(( base + days * 86400 ))
  expiry_set "${name}" "${ts}"
  if peer_is_disabled "${name}"; then
    uncomment_peer_lines "${name}"
    info "$(t "Клиент ${name} включён (срок продлён)" "Client ${name} enabled (expiry extended)")"
  fi
  info "$(t "Новый срок: $(fmt_ts "${ts}")" "New expiry: $(fmt_ts "${ts}")")"
  apply_config || true
  log INFO "extend_expiry: ${name} +${days}d -> ${ts}"
}

# reset_expiry — сделать клиента бессрочным
reset_expiry() {
  section "$(t 'Сброс срока (бессрочно)' 'Reset expiry (never)')"
  local name
  name="$(prompt_value "$(t 'Имя клиента' 'Client name')" "")"
  validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
  peer_exists "${name}" || die "$(t "Клиент ${name} не найден" "Client ${name} not found")"
  expiry_set "${name}" "0"
  if peer_is_disabled "${name}"; then
    uncomment_peer_lines "${name}"
  fi
  info "$(t "Клиент ${name}: бессрочно" "Client ${name}: never expires")"
  apply_config || true
  log INFO "reset_expiry: ${name}"
}

# show_expiring — истекающие / истёкшие
show_expiring() {
  section "$(t 'Сроки действия' 'Expirations')"
  printf '  1) %s\n' "$(t 'Истекающие в ближайшие N дней' 'Expiring within N days')"
  printf '  2) %s\n' "$(t 'Уже истёкшие' 'Already expired')"
  printf '  3) %s\n' "$(t 'Все со сроком' 'All with expiry')"
  local ch
  read -r -p "$(t 'Выбор [1]: ' 'Choice [1]: ')" ch || exit 0
  ch="${ch:-1}"
  local days=0
  if [[ "${ch}" == "1" ]]; then
    days="$(prompt_value "$(t 'Сколько дней вперёд' 'Days ahead')" "7")"
    [[ "${days}" =~ ^[0-9]+$ ]] || days=7
  fi
  local now name ts
  now="$(date +%s)"
  local found=0
  while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    ts="$(expiry_get "${name}")"
    [[ -n "${ts}" && "${ts}" != "0" ]] || continue
    case "${ch}" in
      1)
        (( ts >= now && ts <= now + days * 86400 )) || continue
        ;;
      2)
        (( ts < now )) || continue
        ;;
    esac
    printf '  %-18s %s\n' "${name}" "$(fmt_ts "${ts}")"
    found=$((found + 1))
  done < <(peer_names)
  if (( found == 0 )); then
    info "$(t 'Ничего не найдено' 'Nothing found')"
  else
    info "$(t "Записей: ${found}" "Entries: ${found}")"
  fi
}

# install_expiry_check — ставит cron или systemd timer автопроверки
install_expiry_check() {
  section "$(t 'Автопроверка сроков' 'Expiry auto-check')"
  printf '  1) %s\n' "$(t 'Cron каждые 5 минут' 'Cron every 5 minutes')"
  printf '  2) %s\n' "$(t 'systemd timer' 'systemd timer')"
  printf '  3) %s\n' "$(t 'Отключить автопроверку' 'Disable auto-check')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1|2)
      # скрипт проверки
      cat >"${EXPIRE_CHECK_SCRIPT}" <<'EXPIREEOF'
#!/usr/bin/env bash
# wg-expire-check.sh — автодействия по истечении срока клиентов wg-admin.sh
set -o pipefail
WG_IF="${WG_IF:-wg0}"
WG_CONF="${WG_CONF:-/etc/wireguard/wg0.conf}"
EXPIRY_DB="${EXPIRY_DB:-/etc/wireguard/expiry.db}"
LOG_FILE="${LOG_FILE:-/var/log/wg-admin.log}"
log() { printf '[%s] [INFO] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"${LOG_FILE}" 2>/dev/null || true; }
[[ -f "${EXPIRY_DB}" && -f "${WG_CONF}" ]] || exit 0
now="$(date +%s)"
while IFS=: read -r name ts; do
  [[ -z "${name}" || -z "${ts}" || "${ts}" == "0" ]] && continue
  (( ts < now )) || continue
  # уже отключён?
  if grep -q "^# ${name}$" "${WG_CONF}" 2>/dev/null; then
    block="$(awk -v name="${name}" '
      $0 == "# " name { inb=1; next }
      inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { exit }
      inb && /^\[Interface\]/ { exit }
      inb { print }
    ' "${WG_CONF}")"
    if grep -q '^# DISABLED' <<<"${block}"; then
      continue
    fi
    # отключаем пира
    tmp="$(mktemp)"
    awk -v name="${name}" '
      $0 == "# " name { inb=1; print; next }
      inb && /^# [A-Za-z0-9_-]+$/ && $0 != "# " name { inb=0 }
      inb && /^\[Interface\]/ { inb=0 }
      inb && /^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=/ {
        print "# " $0; next
      }
      inb && /^\[Peer\]/ { print; print "# DISABLED 1"; next }
      { print }
    ' "${WG_CONF}" >"${tmp}" && mv -- "${tmp}" "${WG_CONF}"
    if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
      wg syncconf "${WG_IF}" <(wg-quick strip "${WG_IF}") 2>/dev/null || true
    fi
    log "wg-expire-check: disabled ${name} (expired)"
  fi
done <"${EXPIRY_DB}"
EXPIREEOF
      chmod 700 "${EXPIRE_CHECK_SCRIPT}"
      if [[ "${ch}" == "1" ]]; then
        local cron_line="*/5 * * * * ${EXPIRE_CHECK_SCRIPT}"
        if crontab -l 2>/dev/null | grep -qF "${EXPIRE_CHECK_SCRIPT}"; then
          local tmp
          tmp="$(make_temp)"
          crontab -l 2>/dev/null | grep -vF "${EXPIRE_CHECK_SCRIPT}" >"${tmp}"
          printf '%s\n' "${cron_line}" >>"${tmp}"
          crontab "${tmp}"
        else
          ( crontab -l 2>/dev/null; printf '%s\n' "${cron_line}" ) | crontab -
        fi
        info "$(t 'Cron-задача установлена (каждые 5 минут)' 'Cron job installed (every 5 minutes)')"
      else
        cat >/etc/systemd/system/wg-expire.service <<SVCEOF
[Unit]
Description=wg-admin expiry check
After=network.target

[Service]
Type=oneshot
ExecStart=${EXPIRE_CHECK_SCRIPT}
SVCEOF
        cat >/etc/systemd/system/wg-expire.timer <<TMREOF
[Unit]
Description=wg-admin expiry check timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=wg-expire.service

[Install]
WantedBy=timers.target
TMREOF
        systemctl daemon-reload
        systemctl enable --now wg-expire.timer >/dev/null 2>&1 \
          || warn "$(t 'Не удалось включить таймер' 'Failed to enable timer')"
        info "$(t 'systemd timer установлен' 'systemd timer installed')"
      fi
      ;;
    3)
      if crontab -l 2>/dev/null | grep -qF "${EXPIRE_CHECK_SCRIPT}"; then
        local tmp
        tmp="$(make_temp)"
        crontab -l 2>/dev/null | grep -vF "${EXPIRE_CHECK_SCRIPT}" >"${tmp}"
        crontab "${tmp}" || true
        info "$(t 'Cron-задача удалена' 'Cron job removed')"
      fi
      if [[ -f /etc/systemd/system/wg-expire.timer ]]; then
        systemctl disable --now wg-expire.timer >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/wg-expire.timer /etc/systemd/system/wg-expire.service
        systemctl daemon-reload
        info "$(t 'systemd timer удалён' 'systemd timer removed')"
      fi
      rm -f -- "${EXPIRE_CHECK_SCRIPT}" 2>/dev/null || true
      ;;
  esac
  log INFO "install_expiry_check: choice=${ch}"
}

# ==================== МОНИТОРИНГ ====================

# show_status — wg show с классификацией пиров (4.1)
show_status() {
  section "$(t 'wg show / статус пиров' 'wg show / peer status')"
  if ! ip link show "${WG_IF}" >/dev/null 2>&1; then
    warn "$(t "Интерфейс ${WG_IF} не поднят" "Interface ${WG_IF} is down")"
    return 1
  fi
  wg show "${WG_IF}"
  printf '\n'
  # сводка по памяти
  local now name hs last
  now="$(date +%s)"
  local active=0 silent=0 lost=0
  printf '%s\n' "$(t 'Сводка пиров:' 'Peer summary:')"
  while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    peer_is_disabled "${name}" && continue
    local pub
    pub="$(peer_field "${name}" PublicKey)"
    [[ -z "${pub}" ]] && continue
    local dump
    dump="$(wg show "${WG_IF}" latest-handshakes 2>/dev/null | awk -v p="${pub}" '$1==p {print $2}')"
    hs="${dump:-0}"
    if (( hs == 0 )); then
      printf '  %-18s %s\n' "${name}" "$(t 'нет рукопожатия (молчит)' 'no handshake (silent)')"
      silent=$((silent + 1))
    else
      last=$(( now - hs ))
      if (( last < 300 )); then
        printf '  %-18s %s %s\n' "${name}" "$(t 'активен' 'active')" "$(t "последний контакт ${last}s назад" "last seen ${last}s ago")"
        active=$((active + 1))
      elif (( last < 1800 )); then
        printf '  %-18s %s %s\n' "${name}" "$(t 'молчит' 'silent')" "$(t "последний контакт ${last}s назад" "last seen ${last}s ago")"
        silent=$((silent + 1))
      else
        printf '  %-18s %s %s\n' "${name}" "$(t 'потерян' 'lost')" "$(t "последний контакт ${last}s назад" "last seen ${last}s ago")"
        lost=$((lost + 1))
      fi
    fi
  done < <(peer_names)
  printf '%s\n' "------------------------------"
  printf '%s: %s  %s: %s  %s: %s\n' \
    "$(t 'активные' 'active')" "${active}" \
    "$(t 'молчащие' 'silent')" "${silent}" \
    "$(t 'потерянные' 'lost')" "${lost}"
}

# show_traffic — трафик по клиентам (4.2)
show_traffic() {
  section "$(t 'Трафик по клиентам' 'Traffic per client')"
  if ! ip link show "${WG_IF}" >/dev/null 2>&1; then
    warn "$(t "Интерфейс ${WG_IF} не поднят" "Interface ${WG_IF} is down")"
    return 1
  fi
  printf '%s\n' "$(t 'Сортировка: 1) по имени  2) по rx  3) по tx' 'Sort: 1) name  2) rx  3) tx')"
  local sort
  read -r -p "$(t 'Выбор [1]: ' 'Choice [1]: ')" sort || exit 0
  sort="${sort:-1}"
  local tmp
  tmp="$(make_temp)"
  printf 'name\trx_bytes\ttx_bytes\n' >"${tmp}"
  local name pub line
  while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    pub="$(peer_field "${name}" PublicKey)"
    [[ -z "${pub}" ]] && continue
    line="$(wg show "${WG_IF}" transfer 2>/dev/null | awk -v p="${pub}" '$1==p {print $2 "\t" $3}')"
    printf '%s\t%s\n' "${name}" "${line:-0	0}" >>"${tmp}"
  done < <(peer_names)
  case "${sort}" in
    2) tail -n +2 "${tmp}" | sort -t$'\t' -k2 -nr | { read -r _; cat; } ;;
    3) tail -n +2 "${tmp}" | sort -t$'\t' -k3 -nr ;;
    *) tail -n +2 "${tmp}" | sort -t$'\t' -k1 ;;
  esac | while IFS=$'\t' read -r n rx tx; do
    printf '  %-18s rx=%12s  tx=%12s\n' "${n}" \
      "$(numfmt --to=iec --suffix=B "${rx:-0}" 2>/dev/null || echo "${rx:-0}B")" \
      "$(numfmt --to=iec --suffix=B "${tx:-0}" 2>/dev/null || echo "${tx:-0}B")"
  done
  printf '\n'
  printf '  1) %s\n' "$(t 'Экспорт в CSV' 'Export CSV')"
  printf '  2) %s\n' "$(t 'Сбросить счётчики' 'Reset counters')"
  printf '  3) %s\n' "$(t 'Назад' 'Back')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1)
      local out
      out="$(prompt_value "$(t 'Файл' 'File')" "./wg-traffic.csv")"
      cp -- "${tmp}" "${out}" && info "$(t "CSV: ${out}" "CSV: ${out}")"
      ;;
    2) reset_counters ;;
  esac
}

# ping_peers — ping всех пиров по VPN IP (4.4 / 11.4)
ping_peers() {
  section "$(t 'Ping всех пиров' 'Ping all peers')"
  local name ip ok=0 fail=0
  while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    peer_is_disabled "${name}" && continue
    ip="$(peer_field "${name}" AllowedIPs | cut -d/ -f1)"
    [[ -z "${ip}" ]] && continue
    if ping -c 1 -W 2 "${ip}" >/dev/null 2>&1; then
      printf '  %b✔%b %-18s %s\n' "${GREEN}" "${NC}" "${name}" "${ip}"
      ok=$((ok + 1))
    else
      printf '  %b✖%b %-18s %s\n' "${RED}" "${NC}" "${name}" "${ip}"
      fail=$((fail + 1))
    fi
  done < <(peer_names)
  info "$(t "OK: ${ok}  FAIL: ${fail}" "OK: ${ok}  FAIL: ${fail}")"
}

# show_server_pubkey — публичный ключ сервера (4.5)
show_server_pubkey() {
  section "$(t 'Публичный ключ сервера' 'Server public key')"
  if [[ -f "${SERVER_PUBLIC_KEY}" ]]; then
    cat "${SERVER_PUBLIC_KEY}"
  elif command -v wg >/dev/null 2>&1 && ip link show "${WG_IF}" >/dev/null 2>&1; then
    wg show "${WG_IF}" public-key 2>/dev/null || warn "$(t 'Не удалось получить ключ' 'Cannot get key')"
  else
    warn "$(t "Файл ${SERVER_PUBLIC_KEY} не найден" "${SERVER_PUBLIC_KEY} not found")"
    return 1
  fi
}

# show_server_ip — внешний IP сервера (4.6)
show_server_ip() {
  section "$(t 'Внешний IP сервера' 'Server external IP')"
  local ip
  ip="$(external_ip)"
  if [[ -n "${ip}" ]]; then
    printf '  %s\n' "${ip}"
    if [[ -f "${WG_CONF}" ]]; then
      local port
      port="$(awk -F'= ' '/^ListenPort/ {print $2; exit}' "${WG_CONF}")"
      printf '  %s:%s\n' "${ip}" "${port:-${WG_PORT}}"
    fi
  else
    warn "$(t 'Не удалось определить внешний IP' 'Cannot detect external IP')"
    return 1
  fi
}

# ==================== СЕРВИС ====================

# service_manage — запуск/остановка/перезапуск/автозапуск (5.x)
service_manage() {
  section "$(t 'Управление сервисом' 'Service management')"
  printf '  1) %s\n' "$(t 'Запустить' 'Start')"
  printf '  2) %s\n' "$(t 'Остановить' 'Stop')"
  printf '  3) %s\n' "$(t 'Перезапустить' 'Restart')"
  printf '  4) %s\n' "$(t 'Включить автозапуск' 'Enable autostart')"
  printf '  5) %s\n' "$(t 'Отключить автозапуск' 'Disable autostart')"
  printf '  6) %s\n' "$(t 'Статус' 'Status')"
  local ch unit="wg-quick@${WG_IF}"
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1) systemctl start "${unit}" && info "$(t 'Запущен' 'Started')" ;;
    2) systemctl stop "${unit}" && info "$(t 'Остановлен' 'Stopped')" ;;
    3) systemctl restart "${unit}" && info "$(t 'Перезапущен' 'Restarted')" ;;
    4) systemctl enable "${unit}" && info "$(t 'Автозапуск включён' 'Autostart enabled')" ;;
    5) systemctl disable "${unit}" && info "$(t 'Автозапуск отключён' 'Autostart disabled')" ;;
    6) systemctl status "${unit}" --no-pager || true ;;
    *) return 0 ;;
  esac
  log INFO "service_manage: choice=${ch}"
}

# reload_config — перезагрузка конфига без разрыва (5.6)
reload_config() {
  section "$(t 'Перезагрузка конфига без разрыва' 'Reload config without downtime')"
  apply_config
}

# show_journal — журнал сервиса (5.7)
show_journal() {
  section "$(t 'Журнал wg-quick@' 'wg-quick@ journal')${WG_IF}"
  local lines
  lines="$(prompt_value "$(t 'Сколько строк' 'How many lines')" "50")"
  [[ "${lines}" =~ ^[0-9]+$ ]] || lines=50
  journalctl -u "wg-quick@${WG_IF}" --no-pager -n "${lines}" || true
}

# ==================== КОНФИГ ====================

# edit_config — открыть wg0.conf в nano (6.1)
edit_config() {
  section "$(t 'Редактирование конфига' 'Edit config')"
  [[ -f "${WG_CONF}" ]] || die "$(t "Файл ${WG_CONF} не найден" "${WG_CONF} not found")"
  local editor
  editor="$(command -v nano || command -v vi || command -v vim)" \
    || die "$(t 'Редактор не найден (nano/vi)' 'Editor not found (nano/vi)')"
  "${editor}" "${WG_CONF}"
  if confirm "$(t 'Проверить синтаксис после правки? (y/N): ' 'Check syntax after edit? (y/N): ')"; then
    check_config_syntax
  fi
  if confirm "$(t 'Применить конфиг? (y/N): ' 'Apply config? (y/N): ')"; then
    apply_config
  fi
}

# check_config_syntax — проверка синтаксиса (6.2)
check_config_syntax() {
  section "$(t 'Проверка синтаксиса' 'Syntax check')"
  if [[ ! -f "${WG_CONF}" ]]; then
    warn "$(t "Файл ${WG_CONF} не найден" "${WG_CONF} not found")"
    return 1
  fi
  if command -v wg-quick >/dev/null 2>&1; then
    if wg-quick strip "${WG_IF}" >/dev/null 2>&1; then
      info "$(t 'wg-quick strip: OK' 'wg-quick strip: OK')"
    else
      warn "$(t 'wg-quick strip: ошибки' 'wg-quick strip: errors')"
      wg-quick strip "${WG_IF}" 2>&1 | head -20
      return 1
    fi
  fi
  if command -v wg >/dev/null 2>&1; then
    local stripped
    stripped="$(wg-quick strip "${WG_IF}" 2>/dev/null)" || return 1
    if printf '%s\n' "${stripped}" | wg setconf "${WG_IF}" /dev/stdin --dry-run 2>/dev/null; then
      info "$(t 'wg setconf --dry-run: OK' 'wg setconf --dry-run: OK')"
    else
      # wg без --dry-run в старых версиях — просто парсим
      if printf '%s\n' "${stripped}" | grep -q '^\[Interface\]'; then
        info "$(t 'Базовая структура конфига: OK' 'Basic config structure: OK')"
      fi
    fi
  fi
  # дубликаты AllowedIPs
  local dups
  dups="$(grep -E '^[# ]*AllowedIPs' "${WG_CONF}" | sed 's/^[# ]*AllowedIPs[[:space:]]*=[[:space:]]*//' | sort | uniq -d)"
  if [[ -n "${dups}" ]]; then
    warn "$(t "Дубликаты AllowedIPs: ${dups}" "Duplicate AllowedIPs: ${dups}")"
  fi
}

# change_external_interface — смена внешнего интерфейса (6.3)
change_external_interface() {
  section "$(t 'Внешний интерфейс' 'External interface')"
  local cur def new
  cur="$(awk '/^# Внешний интерфейс:/ {print $3; exit}' "${WG_CONF}" 2>/dev/null)"
  def="$(detect_interface)"
  info "$(t "Текущий (из комментария): ${cur:-?}" "Current (from comment): ${cur:-?}")"
  new="$(prompt_value "$(t 'Новый внешний интерфейс' 'New external interface')" "${def}")"
  validate_iface "${new}" || die "$(t "Интерфейс ${new} не найден" "Interface ${new} not found")"
  sed -i "s/-o [a-zA-Z0-9_.:-]*/-o ${new}/g; s/-i ${WG_IF}/-i ${WG_IF}/g" "${WG_CONF}"
  sed -i "s/^# Внешний интерфейс:.*/# Внешний интерфейс: ${new}/" "${WG_CONF}"
  # пересоздать NAT для нового интерфейса
  local net
  net="$(vpn_network "${VPN_SUBNET}")"
  setup_nat "${new}" "${net}"
  info "$(t "Интерфейс изменён на ${new}" "Interface changed to ${new}")"
  apply_config || true
  log INFO "change_external_interface: ${new}"
}

# change_port — смена порта (6.4)
change_port() {
  section "$(t 'Порт сервера' 'Server port')"
  local cur new
  cur="$(awk -F'= ' '/^ListenPort/ {print $2; exit}' "${WG_CONF}" 2>/dev/null)"
  new="$(prompt_value "$(t 'Новый UDP-порт' 'New UDP port')" "${cur:-${WG_PORT}}")"
  validate_port "${new}" || die "$(t "Некорректный порт: ${new}" "Invalid port: ${new}")"
  sed -i "s/^ListenPort = .*/ListenPort = ${new}/" "${WG_CONF}"
  WG_PORT="${new}"
  save_settings
  info "$(t "Порт изменён на ${new}" "Port changed to ${new}")"
  apply_config || true
  log INFO "change_port: ${new}"
}

# change_subnet — смена VPN-подсети (6.5)
change_subnet() {
  section "$(t 'VPN-подсеть' 'VPN subnet')"
  warn "$(t 'Смена подсети не обновляет адреса клиентов автоматически!' 'Subnet change does not rewrite client addresses automatically!')"
  local cur new vpn_ip
  cur="${VPN_SUBNET}"
  new="$(prompt_value "$(t 'Новая подсеть (CIDR)' 'New subnet (CIDR)')" "${cur}")"
  validate_cidr "${new}" || die "$(t "Некорректный CIDR: ${new}" "Invalid CIDR: ${new}")"
  vpn_ip="$(prompt_value "$(t 'VPN IP сервера' 'Server VPN IP')" "${SERVER_VPN_IP}")"
  validate_ip "${vpn_ip}" || die "$(t 'Некорректный IP' 'Invalid IP')"
  sed -i "s/^Address = .*/Address = ${vpn_ip}\/32/" "${WG_CONF}"
  sed -i "s|PostUp = iptables -t nat -A POSTROUTING -s [^ ]*|PostUp = iptables -t nat -A POSTROUTING -s ${new}|" "${WG_CONF}"
  sed -i "s|PreDown = iptables -t nat -D POSTROUTING -s [^ ]*|PreDown = iptables -t nat -D POSTROUTING -s ${new}|" "${WG_CONF}"
  VPN_SUBNET="${new}"
  SERVER_VPN_IP="${vpn_ip}"
  save_settings
  local net
  net="$(vpn_network "${new}")"
  local ext_if
  ext_if="$(detect_interface)"
  setup_nat "${ext_if}" "${net}"
  info "$(t "Подсеть изменена: ${new}" "Subnet changed: ${new}")"
  apply_config || true
  log INFO "change_subnet: ${new}"
}

# manage_iptables — управление iptables (6.6)
manage_iptables() {
  section "$(t 'Управление iptables' 'iptables management')"
  printf '  1) %s\n' "$(t 'Показать NAT-правила' 'Show NAT rules')"
  printf '  2) %s\n' "$(t 'Показать FORWARD-правила' 'Show FORWARD rules')"
  printf '  3) %s\n' "$(t 'Пересоздать правила WireGuard' 'Recreate WireGuard rules')"
  printf '  4) %s\n' "$(t 'Сохранить правила' 'Save rules')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1) iptables -t nat -L -n -v --line-numbers ;;
    2) iptables -L FORWARD -n -v --line-numbers ;;
    3)
      local ext_if net
      ext_if="$(detect_interface)"
      net="$(vpn_network "${VPN_SUBNET}")"
      setup_nat "${ext_if}" "${net}"
      ;;
    4)
      if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
      else
        mkdir -p /etc/iptables
        iptables-save >/etc/iptables/rules.v4
        info "$(t 'Сохранено в /etc/iptables/rules.v4' 'Saved to /etc/iptables/rules.v4')"
      fi
      ;;
  esac
}

# manage_sysctl — управление sysctl (6.7)
manage_sysctl() {
  section "$(t 'Управление sysctl' 'sysctl management')"
  printf '  1) %s\n' "$(t 'Показать текущие значения' 'Show current values')"
  printf '  2) %s\n' "$(t 'Включить форвардинг' 'Enable forwarding')"
  printf '  3) %s\n' "$(t 'Показать /etc/sysctl.d/99-wireguard.conf' 'Show /etc/sysctl.d/99-wireguard.conf')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1)
      sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding 2>/dev/null || true
      ;;
    2) enable_ip_forward ;;
    3)
      if [[ -f /etc/sysctl.d/99-wireguard.conf ]]; then
        cat /etc/sysctl.d/99-wireguard.conf
      else
        warn "$(t 'Файл не найден' 'File not found')"
      fi
      ;;
  esac
}

# ==================== МАРШРУТИЗАЦИЯ ====================

# allow_lan_access — доступ клиентов к LAN сервера (7.1)
allow_lan_access() {
  section "$(t 'Доступ клиентов к LAN сервера' 'Client access to server LAN')"
  local lan_net ext_if
  lan_net="$(prompt_value "$(t 'LAN-подсеть сервера (CIDR)' 'Server LAN subnet (CIDR)')" "192.168.1.0/24")"
  validate_cidr "${lan_net}" || die "$(t "Некорректный CIDR: ${lan_net}" "Invalid CIDR: ${lan_net}")"
  ext_if="$(detect_interface)"
  iptables -C FORWARD -i "${WG_IF}" -d "${lan_net}" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "${WG_IF}" -d "${lan_net}" -j ACCEPT
  iptables -C FORWARD -o "${WG_IF}" -s "${lan_net}" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -o "${WG_IF}" -s "${lan_net}" -j ACCEPT
  # маршруты клиентам: AllowedIPs клиентов дополнить lan_net (через комментарий)
  info "$(t "Разрешён доступ ${WG_IF} → ${lan_net}" "Allowed ${WG_IF} → ${lan_net}")"
  info "$(t 'Добавьте LAN-подсеть в AllowedIPs клиентов, если нужен полный доступ' 'Add the LAN subnet to client AllowedIPs for full access')"
  log INFO "allow_lan_access: ${lan_net}"
}

# allow_client_lan — доступ к LAN за клиентом (7.2)
allow_client_lan() {
  section "$(t 'Доступ к LAN за клиентом' 'Access to LAN behind client')"
  local name client_lan
  name="$(prompt_value "$(t 'Имя клиента' 'Client name')" "")"
  validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
  peer_exists "${name}" || die "$(t "Клиент ${name} не найден" "Client ${name} not found")"
  client_lan="$(prompt_value "$(t 'LAN за клиентом (CIDR)' 'LAN behind client (CIDR)')" "192.168.2.0/24")"
  validate_cidr "${client_lan}" || die "$(t "Некорректный CIDR: ${client_lan}" "Invalid CIDR: ${client_lan}")"
  local cur
  cur="$(peer_field "${name}" AllowedIPs)"
  if grep -qF "${client_lan}" <<<"${cur}"; then
    info "$(t 'Уже добавлено' 'Already present')"
  else
    set_peer_allowed_ips "${name}" "${cur}, ${client_lan}"
    info "$(t "AllowedIPs ${name}: ${cur}, ${client_lan}" "AllowedIPs ${name}: ${cur}, ${client_lan}")"
  fi
  iptables -C FORWARD -i "${WG_IF}" -d "${client_lan}" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "${WG_IF}" -d "${client_lan}" -j ACCEPT
  iptables -C FORWARD -o "${WG_IF}" -s "${client_lan}" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -o "${WG_IF}" -s "${client_lan}" -j ACCEPT
  apply_config || true
  log INFO "allow_client_lan: ${name} ${client_lan}"
}

# setup_site_to_site — соединение двух сетей (7.3)
setup_site_to_site() {
  section "$(t 'Site-to-Site' 'Site-to-Site')"
  info "$(t 'Соединяет две локальные сети через два WireGuard-узла' 'Connects two LANs via two WireGuard endpoints')"
  local remote_pub remote_allowed remote_endpoint
  remote_pub="$(prompt_value "$(t 'Публичный ключ удалённого узла' 'Remote peer public key')" "")"
  [[ -n "${remote_pub}" ]] || die "$(t 'Ключ обязателен' 'Key is required')"
  remote_allowed="$(prompt_value "$(t 'Подсети за удалённым узлом (CIDR через запятую)' 'Remote subnets (comma-separated CIDR)')" "")"
  [[ -n "${remote_allowed}" ]] || die "$(t 'Подсети обязательны' 'Subnets are required')"
  remote_endpoint="$(prompt_value "$(t 'Endpoint удалённого узла (ip:port)' 'Remote endpoint (ip:port)')" "")"
  [[ -n "${remote_endpoint}" ]] || die "$(t 'Endpoint обязателен' 'Endpoint is required')"
  local name
  name="$(prompt_value "$(t 'Имя пира (латиница)' 'Peer name (latin)')" "site2site")"
  validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
  peer_exists "${name}" && die "$(t "Пир ${name} уже существует" "Peer ${name} already exists")"
  {
    printf '\n# %s\n' "${name}"
    printf '# COMMENT site-to-site\n'
    printf '[Peer]\n'
    printf 'PublicKey = %s\n' "${remote_pub}"
    printf 'AllowedIPs = %s\n' "${remote_allowed}"
    printf 'Endpoint = %s\n' "${remote_endpoint}"
    printf 'PersistentKeepalive = 25\n'
  } >>"${WG_CONF}"
  local net
  net="$(vpn_network "${VPN_SUBNET}")"
  iptables -C FORWARD -i "${WG_IF}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "${WG_IF}" -j ACCEPT
  iptables -C FORWARD -o "${WG_IF}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "${WG_IF}" -j ACCEPT
  info "$(t "Site-to-Site пир ${name} добавлен" "Site-to-Site peer ${name} added")"
  info "$(t 'Настройте зеркальный пир на удалённой стороне' 'Configure the mirror peer on the remote side')"
  apply_config || true
  log INFO "setup_site_to_site: ${name} ${remote_endpoint}"
}

# setup_dns — dnsmasq / AdGuardHome (7.4)
setup_dns() {
  section "$(t 'DNS (dnsmasq / AdGuardHome)' 'DNS (dnsmasq / AdGuardHome)')"
  printf '  1) %s\n' "$(t 'Установить dnsmasq' 'Install dnsmasq')"
  printf '  2) %s\n' "$(t 'Установить AdGuard Home' 'Install AdGuard Home')"
  printf '  3) %s\n' "$(t 'Указать DNS для клиентов (в конфигах)' 'Set DNS for clients (in configs)')"
  printf '  4) %s\n' "$(t 'Назад' 'Back')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1)
      export DEBIAN_FRONTEND=noninteractive
      apt-get install -y -qq dnsmasq || die "$(t 'Не удалось установить dnsmasq' 'dnsmasq install failed')"
      cat >/etc/dnsmasq.d/wg-admin.conf <<EOF
# wg-admin.sh
interface=${WG_IF}
listen-address=${SERVER_VPN_IP}
bind-interfaces
no-resolv
server=${DNS_DEFAULT}
cache-size=1000
EOF
      systemctl enable --now dnsmasq >/dev/null 2>&1 || true
      info "$(t "dnsmasq установлен, слушает ${SERVER_VPN_IP}" "dnsmasq installed, listening on ${SERVER_VPN_IP}")"
      DNS_DEFAULT="${SERVER_VPN_IP}"
      save_settings
      ;;
    2)
      info "$(t 'Установка AdGuard Home через официальный скрипт' 'AdGuard Home via official script')"
      if confirm "$(t 'Запустить установщик? (y/N): ' 'Run installer? (y/N): ')"; then
        curl -s -S -L https://static.adtidy.org/adguardhome.sh | sh \
          || die "$(t 'Установка AdGuard Home не удалась' 'AdGuard Home install failed')"
        info "$(t 'Следуйте инструкциям AdGuard Home (обычно :3000)' 'Follow AdGuard Home wizard (usually :3000)')"
      fi
      ;;
    3)
      local dns
      dns="$(prompt_value "$(t 'DNS для клиентов' 'DNS for clients')" "${DNS_DEFAULT}")"
      validate_ip "${dns}" || die "$(t 'Некорректный DNS' 'Invalid DNS')"
      DNS_DEFAULT="${dns}"
      save_settings
      info "$(t "DNS по умолчанию: ${dns}" "Default DNS: ${dns}")"
      info "$(t 'Новые клиенты получат этот DNS; для существующих — отредактируйте вручную' 'New clients will get this DNS; edit existing ones manually')"
      ;;
  esac
  log INFO "setup_dns: choice=${ch}"
}

# setup_split_tunnel — split-tunnel (7.6)
setup_split_tunnel() {
  section "$(t 'Split-tunnel' 'Split-tunnel')"
  info "$(t 'Только указанные подсети идут через VPN' 'Only listed subnets go via VPN')"
  local name
  name="$(prompt_value "$(t 'Имя клиента' 'Client name')" "")"
  validate_name "${name}" || die "$(t 'Некорректное имя' 'Invalid name')"
  peer_exists "${name}" || die "$(t "Клиент ${name} не найден" "Client ${name} not found")"
  local subnets
  subnets="$(prompt_value "$(t 'Подсети через запятую' 'Subnets, comma-separated')" "${VPN_SUBNET}")"
  local s allowed=""
  local first=1
  IFS=',' read -ra _slist <<<"${subnets}"
  for s in "${_slist[@]}"; do
    s="$(echo "${s}" | tr -d '[:space:]')"
    [[ -z "${s}" ]] && continue
    validate_cidr "${s}" || die "$(t "Некорректный CIDR: ${s}" "Invalid CIDR: ${s}")"
    if (( first )); then allowed="${s}"; first=0; else allowed="${allowed}, ${s}"; fi
  done
  [[ -n "${allowed}" ]] || die "$(t 'Нет валидных подсетей' 'No valid subnets')"
  set_peer_allowed_ips "${name}" "${allowed}"
  # обновить клиентский конфиг
  if [[ -f "${CLIENTS_DIR}/${name}.conf" ]]; then
    sed -i "s/^AllowedIPs = .*/AllowedIPs = ${allowed}/" "${CLIENTS_DIR}/${name}.conf"
  fi
  info "$(t "Split-tunnel для ${name}: ${allowed}" "Split-tunnel for ${name}: ${allowed}")"
  apply_config || true
  log INFO "setup_split_tunnel: ${name} ${allowed}"
}

# ==================== БЕЗОПАСНОСТЬ ====================

# setup_firewall — ufw / iptables (8.1)
setup_firewall() {
  section "$(t 'Firewall' 'Firewall')"
  printf '  1) %s\n' "$(t 'UFW: базовые правила WireGuard' 'UFW: basic WireGuard rules')"
  printf '  2) %s\n' "$(t 'iptables: только порт WireGuard + SSH' 'iptables: WireGuard port + SSH only')"
  printf '  3) %s\n' "$(t 'Показать состояние' 'Show state')"
  local ch port
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  port="$(awk -F'= ' '/^ListenPort/ {print $2; exit}' "${WG_CONF}" 2>/dev/null || echo "${WG_PORT}")"
  case "${ch}" in
    1)
      if ! command -v ufw >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y -qq ufw || die "$(t 'Не удалось установить ufw' 'ufw install failed')"
      fi
      ufw allow "${port}/udp" comment 'WireGuard'
      ufw allow OpenSSH || ufw allow 22/tcp
      ufw --force enable
      info "$(t "UFW: разрешён ${port}/udp и SSH" "UFW: allowed ${port}/udp and SSH")"
      ;;
    2)
      iptables -P INPUT DROP
      iptables -A INPUT -i lo -j ACCEPT
      iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A INPUT -p udp --dport "${port}" -j ACCEPT
      iptables -A INPUT -p tcp --dport 22 -j ACCEPT
      iptables -A INPUT -i "${WG_IF}" -j ACCEPT
      info "$(t "iptables: политика INPUT DROP, разрешены ${port}/udp и 22/tcp" "iptables: INPUT DROP policy, ${port}/udp and 22/tcp allowed")"
      warn "$(t 'Правила не сохранены автоматически — используйте п. 6.6 «Сохранить»' 'Rules not persisted — use 6.6 «Save»')"
      ;;
    3)
      if command -v ufw >/dev/null 2>&1; then
        ufw status verbose || true
      fi
      iptables -L INPUT -n -v --line-numbers || true
      ;;
  esac
  log INFO "setup_firewall: choice=${ch}"
}

# setup_fail2ban — fail2ban для WireGuard (8.2)
setup_fail2ban() {
  section "$(t 'Fail2ban для WireGuard' 'Fail2ban for WireGuard')"
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq fail2ban || die "$(t 'Не удалось установить fail2ban' 'fail2ban install failed')"
  fi
  cat >/etc/fail2ban/jail.d/wg-admin.conf <<EOF
# wg-admin.sh: защита журнала WireGuard
[wg-admin]
enabled = true
filter = wg-admin
logpath = /var/log/wg-admin.log
maxretry = 5
findtime = 300
bantime = 3600
EOF
  cat >/etc/fail2ban/filter.d/wg-admin.conf <<EOF
# wg-admin.sh
[Definition]
failregex = ^.*\[ERROR\].*failed auth.*<HOST>
ignoreregex =
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  info "$(t 'fail2ban настроен для /var/log/wg-admin.log' 'fail2ban configured for /var/log/wg-admin.log')"
  info "$(t 'Сам WireGuard не логирует handshake — jail ловит ошибки скрипта' 'WireGuard does not log handshakes — jail catches script errors')"
  log INFO "setup_fail2ban: ok"
}

# restrict_by_ip — ограничение по IP (8.3)
restrict_by_ip() {
  section "$(t 'Ограничение по IP' 'IP restriction')"
  printf '  1) %s\n' "$(t 'Разрешить подключение с указанных IP' 'Allow connections from listed IPs')"
  printf '  2) %s\n' "$(t 'Убрать ограничения' 'Remove restrictions')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  local port
  port="$(awk -F'= ' '/^ListenPort/ {print $2; exit}' "${WG_CONF}" 2>/dev/null || echo "${WG_PORT}")"
  case "${ch}" in
    1)
      local ips ip
      ips="$(prompt_value "$(t 'Разрешённые IP через запятую' 'Allowed IPs, comma-separated')" "")"
      [[ -n "${ips}" ]] || { warn "$(t 'Пустой список' 'Empty list')"; return 1; }
      # снять старые wg-source правила
      restrict_by_ip_flush "${port}"
      IFS=',' read -ra _iplist <<<"${ips}"
      for ip in "${_iplist[@]}"; do
        ip="$(echo "${ip}" | tr -d '[:space:]')"
        [[ -z "${ip}" ]] && continue
        validate_ip "${ip}" || { warn "$(t "Пропуск: ${ip}" "Skip: ${ip}")"; continue; }
        iptables -I INPUT -p udp --dport "${port}" -s "${ip}" -j ACCEPT
        info "$(t "Разрешён ${ip} → udp/${port}" "Allowed ${ip} → udp/${port}")"
      done
      ;;
    2)
      restrict_by_ip_flush "${port}"
      info "$(t 'Ограничения сняты' 'Restrictions removed')"
      ;;
  esac
  log INFO "restrict_by_ip: choice=${ch}"
}

# restrict_by_ip_flush — удалить правила источника для порта wg
restrict_by_ip_flush() {
  local port="$1"
  while iptables -D INPUT -p udp --dport "${port}" -j ACCEPT 2>/dev/null; do :; done
  while iptables -D INPUT -p udp --dport "${port}" -s 0.0.0.0/0 -j DROP 2>/dev/null; do :; done
  true
}

# audit_connections — аудит подключений (8.4)
audit_connections() {
  section "$(t 'Аудит подключений' 'Connection audit')"
  printf '%s\n' "$(t 'Последние действия из лога:' 'Recent actions from log:')"
  if [[ -f "${LOG_FILE}" ]]; then
    tail -n 50 "${LOG_FILE}"
  else
    warn "$(t "Лог ${LOG_FILE} не найден" "${LOG_FILE} not found")"
  fi
  printf '\n%s\n' "$(t 'Активные handshake:' 'Active handshakes:')"
  if ip link show "${WG_IF}" >/dev/null 2>&1; then
    wg show "${WG_IF}" latest-handshakes 2>/dev/null | while read -r pub ts; do
      local name
      name="$(peer_names | while IFS= read -r n; do
        [[ "$(peer_field "${n}" PublicKey)" == "${pub}" ]] && { echo "${n}"; break; }
      done)"
      printf '  %-18s %s %s\n' "${name:-?}" "${ts}" \
        "$( (( ts > 0 )) && date -d "@${ts}" '+%Y-%m-%d %H:%M:%S' || echo '—')"
    done
  fi
}

# rotate_server_keys — ротация ключей сервера (8.5)
rotate_server_keys() {
  section "$(t 'Ротация ключей сервера' 'Rotate server keys')"
  warn "$(t 'Потребуется перевыпустить конфиги ВСЕХ клиентов!' 'All client configs must be reissued!')"
  confirm "$(t 'Продолжить? (y/N): ' 'Continue? (y/N): ')" || { info "$(t 'Отмена' 'Cancelled')"; return 0; }
  local old_pub
  old_pub="$(cat "${SERVER_PUBLIC_KEY}" 2>/dev/null || true)"
  generate_server_keys
  local new_priv new_pub
  new_priv="$(cat "${SERVER_PRIVATE_KEY}")"
  new_pub="$(cat "${SERVER_PUBLIC_KEY}")"
  # заменить PrivateKey в wg0.conf
  sed -i "s/^PrivateKey = .*/PrivateKey = ${new_priv}/" "${WG_CONF}"
  info "$(t "Старый ключ: ${old_pub:0:20}..." "Old key: ${old_pub:0:20}...")"
  info "$(t "Новый ключ: ${new_pub}" "New key: ${new_pub}")"
  # обновить PublicKey сервера в конфигах клиентов
  if [[ -d "${CLIENTS_DIR}" ]]; then
    local f
    for f in "${CLIENTS_DIR}"/*.conf; do
      [[ -f "${f}" ]] || continue
      sed -i "s/^PublicKey = .*/PublicKey = ${new_pub}/" "${f}"
      # Endpoint не менялся
    done
    info "$(t "Обновлены конфиги клиентов в ${CLIENTS_DIR}" "Updated client configs in ${CLIENTS_DIR}")"
  fi
  apply_config || true
  info "$(t 'Ротация завершена. Передайте клиентам новые конфиги.' 'Rotation done. Distribute new client configs.')"
  log INFO "rotate_server_keys: ${new_pub}"
}

# ==================== БЭКАП ====================

BACKUP_DIR_DEFAULT="/var/backups/wg-admin"

# backup_create — создание бэкапа (9.1)
backup_create() {
  section "$(t 'Создание бэкапа' 'Create backup')"
  printf '  1) %s\n' "$(t 'Только конфиги' 'Configs only')"
  printf '  2) %s\n' "$(t 'Конфиги + база сроков' 'Configs + expiry DB')"
  printf '  3) %s\n' "$(t 'Полный (конфиги, ключи, настройки, лог)' 'Full (configs, keys, settings, log)')"
  printf '  4) %s\n' "$(t 'На удалённый сервер (scp)' 'To remote server (scp)')"
  local ch mode="conf"
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    2) mode="conf+expiry" ;;
    3) mode="full" ;;
    4) mode="remote" ;;
    1) mode="conf" ;;
    *) return 0 ;;
  esac
  mkdir -p "${BACKUP_DIR_DEFAULT}" 2>/dev/null || true
  local ts archive list
  ts="$(date +%Y%m%d-%H%M%S)"
  archive="${BACKUP_DIR_DEFAULT}/wg-backup-${ts}.tar.gz"
  list=("${WG_CONF}")
  [[ -d "${CLIENTS_DIR}" ]] && list+=("${CLIENTS_DIR}")
  if [[ "${mode}" == "conf+expiry" || "${mode}" == "full" || "${mode}" == "remote" ]]; then
    [[ -f "${EXPIRY_DB}" ]] && list+=("${EXPIRY_DB}")
  fi
  if [[ "${mode}" == "full" || "${mode}" == "remote" ]]; then
    [[ -f "${SERVER_PRIVATE_KEY}" ]] && list+=("${SERVER_PRIVATE_KEY}")
    [[ -f "${SERVER_PUBLIC_KEY}" ]] && list+=("${SERVER_PUBLIC_KEY}")
    [[ -f "${SETTINGS_FILE}" ]] && list+=("${SETTINGS_FILE}")
    [[ -f /etc/sysctl.d/99-wireguard.conf ]] && list+=("/etc/sysctl.d/99-wireguard.conf")
    [[ -f "${LOG_FILE}" ]] && list+=("${LOG_FILE}")
  fi
  local existing=()
  local p
  for p in "${list[@]}"; do
    [[ -e "${p}" ]] && existing+=("${p}")
  done
  if (( ${#existing[@]} == 0 )); then
    warn "$(t 'Нечего архивировать' 'Nothing to archive')"
    return 1
  fi
  tar -czf "${archive}" -C / "${existing[@]#/}" 2>/dev/null \
    || die "$(t 'Не удалось создать архив' 'Archive creation failed')"
  chmod 600 "${archive}"
  info "$(t "Бэкап: ${archive}" "Backup: ${archive}")"
  log INFO "backup_create: ${archive} mode=${mode}"
  if [[ "${mode}" == "remote" ]]; then
    local dest
    dest="$(prompt_value "$(t 'Удалённый путь (user@host:/path)' 'Remote path (user@host:/path)')" "")"
    [[ -n "${dest}" ]] || return 0
    if scp -- "${archive}" "${dest}"; then
      info "$(t "Отправлено: ${dest}" "Sent: ${dest}")"
    else
      warn "$(t 'scp завершился с ошибкой' 'scp failed')"
    fi
  fi
}

# backup_restore — восстановление из бэкапа (9.2)
backup_restore() {
  section "$(t 'Восстановление из бэкапа' 'Restore from backup')"
  backup_list
  local archive
  archive="$(prompt_value "$(t 'Путь к архиву' 'Archive path')" "")"
  [[ -f "${archive}" ]] || die "$(t "Файл не найден: ${archive}" "Not found: ${archive}")"
  warn "$(t 'Текущие конфиги будут перезаписаны' 'Current configs will be overwritten')"
  confirm "$(t 'Восстановить? (y/N): ' 'Restore? (y/N): ')" || { info "$(t 'Отмена' 'Cancelled')"; return 0; }
  # локальный бэкап текущего состояния
  local safety
  safety="${BACKUP_DIR_DEFAULT}/pre-restore-$(date +%s).tar.gz"
  mkdir -p "${BACKUP_DIR_DEFAULT}"
  tar -czf "${safety}" -C / "etc/wireguard" 2>/dev/null || true
  tar -xzf "${archive}" -C / || die "$(t 'Распаковка не удалась' 'Extract failed')"
  chmod 700 "${WG_DIR}" "${CLIENTS_DIR}" 2>/dev/null || true
  chmod 600 "${WG_CONF}" 2>/dev/null || true
  [[ -f "${SERVER_PRIVATE_KEY}" ]] && chmod 600 "${SERVER_PRIVATE_KEY}"
  info "$(t 'Восстановление завершено' 'Restore complete')"
  info "$(t "Копия прежнего состояния: ${safety}" "Previous state saved to: ${safety}")"
  if confirm "$(t 'Применить конфиг? (y/N): ' 'Apply config? (y/N): ')"; then
    apply_config
  fi
  log INFO "backup_restore: ${archive}"
}

# backup_list — список бэкапов (9.4)
backup_list() {
  section "$(t 'Список бэкапов' 'Backup list')"
  if [[ ! -d "${BACKUP_DIR_DEFAULT}" ]]; then
    info "$(t "Каталог ${BACKUP_DIR_DEFAULT} пуст" "${BACKUP_DIR_DEFAULT} is empty")"
    return 0
  fi
  local f
  local found=0
  for f in "${BACKUP_DIR_DEFAULT}"/*; do
    [[ -f "${f}" ]] || continue
    printf '  %s  %s\n' "$(date -r "${f}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')" "${f}"
    found=$((found + 1))
  done
  (( found == 0 )) && info "$(t 'Бэкапов нет' 'No backups')"
  return 0
}

# backup_schedule — автобэкап по расписанию (9.3)
backup_schedule() {
  section "$(t 'Автобэкап' 'Scheduled backup')"
  printf '  1) %s\n' "$(t 'Ежедневно' 'Daily')"
  printf '  2) %s\n' "$(t 'Еженедельно' 'Weekly')"
  printf '  3) %s\n' "$(t 'Отключить' 'Disable')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  local marker="# wg-admin-autobackup"
  local script_path="/usr/local/bin/wg-admin-backup.sh"
  if [[ "${ch}" == "3" ]]; then
    if crontab -l 2>/dev/null | grep -qF "${marker}"; then
      local tmp
      tmp="$(make_temp)"
      crontab -l 2>/dev/null | grep -vF "${marker}" | grep -vF "${script_path}" >"${tmp}"
      crontab "${tmp}" || true
      info "$(t 'Автобэкап отключён' 'Scheduled backup disabled')"
    fi
    rm -f -- "${script_path}" 2>/dev/null || true
    return 0
  fi
  cat >"${script_path}" <<'BKPEOF'
#!/usr/bin/env bash
# wg-admin-backup.sh — автоматический бэкап WireGuard
set -o pipefail
BACKUP_DIR="${BACKUP_DIR:-/var/backups/wg-admin}"
WG_DIR="${WG_DIR:-/etc/wireguard}"
mkdir -p "${BACKUP_DIR}"
ts="$(date +%Y%m%d-%H%M%S)"
tar -czf "${BACKUP_DIR}/wg-backup-${ts}.tar.gz" -C / "etc/wireguard" 2>/dev/null || true
chmod 600 "${BACKUP_DIR}/wg-backup-${ts}.tar.gz" 2>/dev/null || true
# хранить не более 30 архивов
ls -1t "${BACKUP_DIR}"/wg-backup-*.tar.gz 2>/dev/null | tail -n +31 | xargs -r rm -f
BKPEOF
  chmod 700 "${script_path}"
  local cron_line
  case "${ch}" in
    1) cron_line="17 3 * * * ${script_path} ${marker}" ;;
    2) cron_line="17 3 * * 0 ${script_path} ${marker}" ;;
  esac
  if crontab -l 2>/dev/null | grep -qF "${marker}"; then
    local tmp
    tmp="$(make_temp)"
    crontab -l 2>/dev/null | grep -vF "${marker}" | grep -vF "${script_path}" >"${tmp}"
    printf '%s\n' "${cron_line}" >>"${tmp}"
    crontab "${tmp}"
  else
    ( crontab -l 2>/dev/null; printf '%s\n' "${cron_line}" ) | crontab -
  fi
  info "$(t "Автобэкап запланирован: ${cron_line}" "Scheduled backup: ${cron_line}")"
  log INFO "backup_schedule: choice=${ch}"
}

# ==================== ОБСЛУЖИВАНИЕ ====================

# check_updates — проверка обновлений WireGuard (10.1)
check_updates() {
  section "$(t 'Обновления WireGuard' 'WireGuard updates')"
  apt-get update -qq 2>/dev/null || true
  local cur cand
  cur="$(dpkg -s wireguard-tools 2>/dev/null | awk -F': ' '/^Version:/ {print $2}')"
  cand="$(apt-cache policy wireguard-tools 2>/dev/null | awk '/Candidate:/ {print $2}')"
  printf '  installed: %s\n' "${cur:-—}"
  printf '  candidate: %s\n' "${cand:-—}"
  if [[ -n "${cur}" && -n "${cand}" && "${cur}" != "${cand}" ]]; then
    info "$(t 'Доступно обновление' 'Update available')"
    if confirm "$(t 'Обновить сейчас? (y/N): ' 'Update now? (y/N): ')"; then
      update_wireguard
    fi
  else
    info "$(t 'Обновлений нет' 'No updates')"
  fi
}

# clean_inactive — очистить неактивных клиентов (10.2)
clean_inactive() {
  section "$(t 'Очистка неактивных клиентов' 'Clean inactive clients')"
  info "$(t 'Неактивные = без handshake более N дней (не отключаются автоматически)' 'Inactive = no handshake for N days (not auto-disabled)')"
  local days name pub ts now cutoff
  days="$(prompt_value "$(t 'Порог дней без handshake' 'Days without handshake')" "30")"
  [[ "${days}" =~ ^[0-9]+$ ]] || days=30
  now="$(date +%s)"
  cutoff=$(( now - days * 86400 ))
  local candidates=()
  while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    peer_is_disabled "${name}" && continue
    pub="$(peer_field "${name}" PublicKey)"
    [[ -z "${pub}" ]] && continue
    ts="$(wg show "${WG_IF}" latest-handshakes 2>/dev/null | awk -v p="${pub}" '$1==p {print $2}')"
    ts="${ts:-0}"
    if (( ts == 0 || ts < cutoff )); then
      candidates+=("${name}")
      printf '  %-18s last=%s\n' "${name}" "$( (( ts > 0 )) && fmt_ts "${ts}" || echo 'никогда/never')"
    fi
  done < <(peer_names)
  if (( ${#candidates[@]} == 0 )); then
    info "$(t 'Таких клиентов нет' 'No such clients')"
    return 0
  fi
  printf '%s\n' "$(t 'Что сделать с найденными?' 'What to do with found?')"
  printf '  1) %s\n' "$(t 'Только показать (уже показано)' 'Just list (already listed)')"
  printf '  2) %s\n' "$(t 'Отключить' 'Disable')"
  printf '  3) %s\n' "$(t 'Удалить' 'Delete')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    2)
      local n
      for n in "${candidates[@]}"; do
        comment_peer_lines "${n}"
      done
      apply_config || true
      ;;
    3)
      confirm "$(t 'Удалить безвозвратно? (y/N): ' 'Delete permanently? (y/N): ')" || return 0
      local n
      for n in "${candidates[@]}"; do
        remove_peer_block "${n}"
        rm -f -- "${CLIENTS_DIR}/${n}.conf" 2>/dev/null || true
        if [[ -f "${EXPIRY_DB}" ]]; then
          local tmp
          tmp="$(make_temp)"
          awk -F: -v x="${n}" '$1!=x' "${EXPIRY_DB}" >"${tmp}" && mv -- "${tmp}" "${EXPIRY_DB}"
        fi
        info "$(t "Удалён: ${n}" "Removed: ${n}")"
      done
      apply_config || true
      ;;
  esac
  log INFO "clean_inactive: threshold=${days}d candidates=${#candidates[@]}"
}

# remove_expired — удалить истёкших (10.3)
remove_expired() {
  section "$(t 'Удаление истёкших клиентов' 'Remove expired clients')"
  local name found=()
  while IFS= read -r name; do
    [[ -z "${name}" ]] && continue
    if peer_is_expired "${name}"; then
      found+=("${name}")
    fi
  done < <(peer_names)
  if (( ${#found[@]} == 0 )); then
    info "$(t 'Истёкших нет' 'No expired clients')"
    return 0
  fi
  info "$(t "Истёкшие: ${found[*]}" "Expired: ${found[*]}")"
  confirm "$(t 'Удалить? (y/N): ' 'Delete? (y/N): ')" || return 0
  local n
  for n in "${found[@]}"; do
    remove_peer_block "${n}"
    rm -f -- "${CLIENTS_DIR}/${n}.conf" 2>/dev/null || true
    if [[ -f "${EXPIRY_DB}" ]]; then
      local tmp
      tmp="$(make_temp)"
      awk -F: -v x="${n}" '$1!=x' "${EXPIRY_DB}" >"${tmp}" && mv -- "${tmp}" "${EXPIRY_DB}"
    fi
    info "$(t "Удалён: ${n}" "Removed: ${n}")"
    log INFO "remove_expired: ${n}"
  done
  apply_config || true
}

# reset_counters — сброс счётчиков трафика (10.4)
reset_counters() {
  section "$(t 'Сброс счётчиков трафика' 'Reset traffic counters')"
  if ip link show "${WG_IF}" >/dev/null 2>&1; then
    # сброс достигается пересозданием интерфейса; wg не имеет reset counters
    warn "$(t 'WireGuard не поддерживает сброс счётчиков без пересоздания интерфейса' 'WireGuard cannot reset counters without recreating the interface')"
    if confirm "$(t 'Пересоздать интерфейс (краткий разрыв)? (y/N): ' 'Recreate interface (brief drop)? (y/N): ')"; then
      wg-quick down "${WG_IF}" 2>/dev/null || true
      wg-quick up "${WG_IF}" || die "$(t 'Не удалось поднять интерфейс' 'Failed to bring interface up')"
      info "$(t 'Счётчики обнулены' 'Counters reset')"
    fi
  else
    warn "$(t "Интерфейс ${WG_IF} не поднят" "Interface ${WG_IF} is down")"
  fi
}

# ==================== ДИАГНОСТИКА ====================

# check_forwarding — проверка IP-форвардинга (11.1)
check_forwarding() {
  section "$(t 'IP-форвардинг' 'IP forwarding')"
  local v4 v6
  v4="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '?')"
  v6="$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo '?')"
  printf '  net.ipv4.ip_forward = %s\n' "${v4}"
  printf '  net.ipv6.conf.all.forwarding = %s\n' "${v6}"
  if [[ "${v4}" == "1" ]]; then
    info "$(t 'IPv4-форвардинг включён' 'IPv4 forwarding is on')"
  else
    warn "$(t 'IPv4-форвардинг выключен' 'IPv4 forwarding is off')"
    return 1
  fi
}

# check_nat — проверка NAT (11.2)
check_nat() {
  section "$(t 'Проверка NAT' 'NAT check')"
  local net
  net="$(vpn_network "${VPN_SUBNET}")"
  printf '%s\n' "$(t 'MASQUERADE-правила:' 'MASQUERADE rules:')"
  iptables -t nat -L POSTROUTING -n -v | grep -E "MASQUERADE|${net%%/*}" || true
  printf '\n%s\n' "$(t 'FORWARD-правила для wg:' 'FORWARD rules for wg:')"
  iptables -L FORWARD -n -v | grep "${WG_IF}" || true
  if iptables -t nat -C POSTROUTING -s "${net}" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -L POSTROUTING -n | grep -q MASQUERADE; then
    info "$(t 'NAT настроен' 'NAT is configured')"
  else
    warn "$(t 'MASQUERADE не найден' 'MASQUERADE not found')"
    return 1
  fi
}

# check_port — проверка порта извне (11.3)
check_port() {
  section "$(t 'Проверка порта извне' 'External port check')"
  local port ip
  port="$(awk -F'= ' '/^ListenPort/ {print $2; exit}' "${WG_CONF}" 2>/dev/null || echo "${WG_PORT}")"
  ip="$(external_ip)"
  info "$(t "Сервер: ${ip}:${port}" "Server: ${ip}:${port}")"
  if command -v nc >/dev/null 2>&1; then
    info "$(t 'Прослушивание UDP:' 'UDP listeners:')"
    ss -ulnp 2>/dev/null | grep -E "wg|${port}" || netstat -ulnp 2>/dev/null | grep "${port}" || true
  fi
  # внешняя проверка через icanhazip/tcp не покажет UDP — инструкция
  printf '%s\n' "$(t 'Проверьте порт с внешней машины:' 'From an external host run:')"
  printf '  nc -u -v -w 3 %s %s\n' "${ip}" "${port}"
  printf '  echo ping | nc -u -w 1 %s %s\n' "${ip}" "${port}"
  info "$(t 'WireGuard молчит на неизвестные пакеты — успешный тест = нет ICMP unreachable' 'WireGuard ignores unknown packets — success = no ICMP unreachable')"
}

# check_dns — проверка DNS через туннель (11.5)
check_dns() {
  section "$(t 'Проверка DNS через туннель' 'DNS check via tunnel')"
  local target
  target="$(prompt_value "$(t 'DNS-сервер для проверки' 'DNS server to test')" "${DNS_DEFAULT}")"
  printf '%s\n' "$(t 'Тест с сервера (напрямую):' 'Test from server (direct):')"
  if command -v dig >/dev/null 2>&1; then
    dig "@${target}" example.com +time=3 +tries=1 || true
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup example.com "${target}" || true
  else
    getent hosts example.com || true
  fi
  printf '\n%s\n' "$(t 'С VPN-клиента выполните:' 'From a VPN client run:')"
  printf '  dig @%s example.com\n' "${target}"
  printf '  nslookup example.com %s\n' "${target}"
}

# test_iperf — iperf3 между пирами (11.6)
test_iperf() {
  section "$(t 'iperf3 между пирами' 'iperf3 between peers')"
  if ! command -v iperf3 >/dev/null 2>&1; then
    warn "$(t 'iperf3 не установлен' 'iperf3 is not installed')"
    if confirm "$(t 'Установить iperf3? (y/N): ' 'Install iperf3? (y/N): ')"; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get install -y -qq iperf3 || die "$(t 'Не удалось установить iperf3' 'iperf3 install failed')"
    else
      return 0
    fi
  fi
  printf '  1) %s\n' "$(t 'Сервер (слушать)' 'Server (listen)')"
  printf '  2) %s\n' "$(t 'Клиент (тест к пиру)' 'Client (test to peer)')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1)
      info "$(t 'Ctrl+C для остановки' 'Ctrl+C to stop')"
      iperf3 -s
      ;;
    2)
      local ip
      ip="$(prompt_value "$(t 'VPN IP пира' 'Peer VPN IP')" "")"
      validate_ip "${ip}" || die "$(t 'Некорректный IP' 'Invalid IP')"
      iperf3 -c "${ip}" -t 10
      ;;
  esac
}

# collect_report — отчёт для поддержки (11.7)
collect_report() {
  section "$(t 'Отчёт для поддержки' 'Support report')"
  local out
  out="$(prompt_value "$(t 'Файл отчёта' 'Report file')" "./wg-support-report-$(date +%Y%m%d-%H%M%S).txt")"
  {
    printf '=== wg-admin.sh support report ===\n'
    printf 'Date: %s\n' "$(date -R)"
    printf 'Version: %s\n' "${VERSION}"
    printf '\n=== OS ===\n'
    cat /etc/os-release 2>/dev/null || true
    uname -a 2>/dev/null || true
    printf '\n=== packages ===\n'
    dpkg -l wireguard wireguard-tools qrencode iptables 2>/dev/null || true
    printf '\n=== interfaces ===\n'
    ip -br addr 2>/dev/null || true
    printf '\n=== wg show ===\n'
    wg show 2>/dev/null || true
    printf '\n=== wg0.conf (без приватных ключей) ===\n'
    if [[ -f "${WG_CONF}" ]]; then
      sed 's/^PrivateKey = .*/PrivateKey = [REDACTED]/' "${WG_CONF}"
    fi
    printf '\n=== sysctl ===\n'
    sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding 2>/dev/null || true
    printf '\n=== iptables NAT ===\n'
    iptables -t nat -L -n -v 2>/dev/null || true
    printf '\n=== iptables FORWARD ===\n'
    iptables -L FORWARD -n -v 2>/dev/null || true
    printf '\n=== systemd ===\n'
    systemctl status "wg-quick@${WG_IF}" --no-pager 2>/dev/null || true
    printf '\n=== recent log (last 100) ===\n'
    tail -n 100 "${LOG_FILE}" 2>/dev/null || true
  } >"${out}"
  chmod 600 "${out}"
  info "$(t "Отчёт сохранён: ${out}" "Report saved: ${out}")"
  info "$(t 'Приватные ключи в отчёте скрыты' 'Private keys are redacted')"
  log INFO "collect_report: ${out}"
}

# ==================== НАСТРОЙКИ ====================

# settings_menu — настройки скрипта (12.x)
settings_menu() {
  while true; do
    section "$(t 'Настройки скрипта' 'Script settings')"
    printf '  1) %s : %s\n' "$(t 'VPN-подсеть по умолчанию' 'Default VPN subnet')" "${VPN_SUBNET}"
    printf '  2) %s : %s\n' "$(t 'Порт по умолчанию' 'Default port')" "${WG_PORT}"
    printf '  3) %s : %s\n' "$(t 'DNS по умолчанию' 'Default DNS')" "${DNS_DEFAULT}"
    printf '  4) %s : %s\n' "$(t 'Путь к конфигам' 'Config directory')" "${WG_DIR}"
    local color_label
    if [[ "${USE_COLOR}" -eq 1 ]]; then color_label="$(t 'вкл' 'on')"; else color_label="$(t 'выкл' 'off')"; fi
    printf '  5) %s : %s\n' "$(t 'Цветной вывод' 'Color output')" "${color_label}"
    printf '  6) %s : %s\n' "$(t 'Уровень логирования' 'Log level')" "${LOG_LEVEL}"
    printf '  7) %s : %s\n' "$(t 'Язык интерфейса' 'Interface language')" "${LANG_UI}"
    printf '  8) %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1)
        local v
        v="$(prompt_value "$(t 'VPN-подсеть (CIDR)' 'VPN subnet (CIDR)')" "${VPN_SUBNET}")"
        validate_cidr "${v}" || { warn "$(t 'Некорректный CIDR' 'Invalid CIDR')"; continue; }
        VPN_SUBNET="${v}"
        save_settings
        ;;
      2)
        local v
        v="$(prompt_value "$(t 'Порт' 'Port')" "${WG_PORT}")"
        validate_port "${v}" || { warn "$(t 'Некорректный порт' 'Invalid port')"; continue; }
        WG_PORT="${v}"
        save_settings
        ;;
      3)
        local v
        v="$(prompt_value "$(t 'DNS' 'DNS')" "${DNS_DEFAULT}")"
        validate_ip "${v}" || { warn "$(t 'Некорректный DNS' 'Invalid DNS')"; continue; }
        DNS_DEFAULT="${v}"
        save_settings
        ;;
      4)
        local v
        v="$(prompt_value "$(t 'Путь к конфигам' 'Config directory')" "${WG_DIR}")"
        [[ -n "${v}" ]] || continue
        WG_DIR="${v}"
        WG_CONF="${WG_DIR}/${WG_IF}.conf"
        CLIENTS_DIR="${WG_DIR}/clients"
        EXPIRY_DB="${WG_DIR}/expiry.db"
        SETTINGS_FILE="${WG_DIR}/wg-admin.conf"
        SERVER_PRIVATE_KEY="${WG_DIR}/server_private.key"
        SERVER_PUBLIC_KEY="${WG_DIR}/server_public.key"
        mkdir -p "${WG_DIR}" "${CLIENTS_DIR}" 2>/dev/null || true
        save_settings
        ;;
      5)
        if [[ "${USE_COLOR}" -eq 1 ]]; then USE_COLOR=0; else USE_COLOR=1; fi
        init_colors
        save_settings
        ;;
      6)
        printf '  DEBUG | INFO | WARN | ERROR\n'
        local v
        v="$(prompt_value "$(t 'Уровень' 'Level')" "${LOG_LEVEL}")"
        case "${v}" in
          DEBUG|INFO|WARN|ERROR) LOG_LEVEL="${v}"; save_settings ;;
          *) warn "$(t 'Неизвестный уровень' 'Unknown level')" ;;
        esac
        ;;
      7)
        local v
        v="$(prompt_value "$(t 'Язык (ru/en)' 'Language (ru/en)')" "${LANG_UI}")"
        case "${v}" in
          ru|en) LANG_UI="${v}"; save_settings ;;
          *) warn "$(t 'Поддерживаются ru и en' 'Only ru and en supported')" ;;
        esac
        ;;
      8) break ;;
    esac
  done
}

# ==================== УДАЛЕНИЕ ====================

# uninstall_wg — удаление WireGuard и настроек (13.x)
uninstall_wg() {
  section "$(t 'Удаление WireGuard' 'Uninstall WireGuard')"
  printf '  1) %s\n' "$(t 'Остановить и отключить сервис' 'Stop and disable service')"
  printf '  2) %s\n' "$(t 'Удалить пакеты' 'Remove packages')"
  printf '  3) %s\n' "$(t 'Удалить конфиги и ключи' 'Remove configs and keys')"
  printf '  4) %s\n' "$(t 'Удалить iptables и sysctl' 'Remove iptables and sysctl')"
  printf '  5) %s\n' "$(t 'Полное удаление' 'Full uninstall')"
  printf '  6) %s\n' "$(t 'Назад' 'Back')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1|5)
      systemctl disable --now "wg-quick@${WG_IF}" 2>/dev/null || true
      systemctl disable --now wg-expire.timer 2>/dev/null || true
      info "$(t 'Сервис остановлен и отключён' 'Service stopped and disabled')"
      [[ "${ch}" == "1" ]] && return 0
      ;;&
    2|5)
      export DEBIAN_FRONTEND=noninteractive
      apt-get purge -y -qq wireguard wireguard-tools 2>/dev/null || true
      apt-get autoremove -y -qq 2>/dev/null || true
      info "$(t 'Пакеты удалены' 'Packages removed')"
      [[ "${ch}" == "2" ]] && return 0
      ;;&
    3|5)
      if [[ -d "${WG_DIR}" ]]; then
        warn "$(t "Будет удалён ${WG_DIR}" "${WG_DIR} will be deleted")"
        confirm "$(t 'Удалить конфиги и ключи? (y/N): ' 'Delete configs and keys? (y/N): ')" || return 0
        rm -rf -- "${WG_DIR}"
        info "$(t 'Конфиги удалены' 'Configs removed')"
      fi
      rm -f -- "${EXPIRE_CHECK_SCRIPT}" 2>/dev/null || true
      rm -f /usr/local/bin/wg-admin-backup.sh 2>/dev/null || true
      [[ "${ch}" == "3" ]] && return 0
      ;;&
    4|5)
      local ext_if net
      ext_if="$(detect_interface)"
      net="$(vpn_network "${VPN_SUBNET}")"
      iptables -t nat -D POSTROUTING -s "${net}" -o "${ext_if}" -j MASQUERADE 2>/dev/null || true
      while iptables -D FORWARD -i "${WG_IF}" -j ACCEPT 2>/dev/null; do :; done
      while iptables -D FORWARD -o "${WG_IF}" -j ACCEPT 2>/dev/null; do :; done
      rm -f /etc/sysctl.d/99-wireguard.conf
      sysctl --system >/dev/null 2>&1 || true
      if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
      fi
      info "$(t 'iptables и sysctl очищены' 'iptables and sysctl cleaned')"
      ;;
  esac
  log INFO "uninstall_wg: choice=${ch}"
}

# ==================== О СКРИПТЕ ====================

# about_menu — информация о скрипте (14.x)
about_menu() {
  while true; do
    section "$(t 'О скрипте' 'About')"
    printf '  1) %s\n' "$(t 'Версия' 'Version')"
    printf '  2) %s\n' "$(t 'Автор / репозиторий' 'Author / repository')"
    printf '  3) %s\n' "$(t 'Лицензия' 'License')"
    printf '  4) %s\n' "$(t 'Проверить обновления скрипта' 'Check for script updates')"
    printf '  5) %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1)
        printf '  wg-admin.sh v%s\n' "${VERSION}"
        ;;
      2)
        printf '  wg-admin.sh — WireGuard admin (Hub-and-Spoke)\n'
        printf '  https://github.com/StarLeG/wg-admin-bash\n'
        ;;
      3)
        printf '  MIT License\n'
        ;;
      4)
        info "$(t 'Проверка обновлений через GitHub' 'Checking GitHub for updates')"
        if command -v curl >/dev/null 2>&1; then
          local remote
          remote="$(curl -fsSL --max-time 8 \
            https://raw.githubusercontent.com/StarLeG/wg-admin-bash/main/wg-admin.sh 2>/dev/null \
            | awk -F'"' '/^VERSION=/ {print $2; exit}')"
          if [[ -z "${remote}" ]]; then
            warn "$(t 'Не удалось получить версию с GitHub' 'Cannot fetch version from GitHub')"
          elif [[ "${remote}" == "${VERSION}" ]]; then
            info "$(t "Актуальная версия: ${VERSION}" "Up to date: ${VERSION}")"
          else
            info "$(t "Доступна версия: ${remote} (локальная: ${VERSION})" "Available: ${remote} (local: ${VERSION})")"
          fi
        else
          warn "$(t 'curl не установлен' 'curl is not installed')"
        fi
        ;;
      5) break ;;
    esac
    [[ "${ch}" == "5" ]] && break
    pause
  done
}

# ==================== МЕНЮ ====================

# clients_menu — управление клиентами (3)
clients_menu() {
  while true; do
    section "$(t 'Управление клиентами' 'Client management')"
    printf '  3.1 %s\n' "$(t 'Добавить клиента' 'Add client')"
    printf '  3.2 %s\n' "$(t 'Список клиентов' 'List clients')"
    printf '  3.3 %s\n' "$(t 'Редактировать клиента' 'Edit client')"
    printf '  3.4 %s\n' "$(t 'Удалить клиента' 'Remove client')"
    printf '  3.5 %s\n' "$(t 'Отключить / включить клиента' 'Disable / enable client')"
    printf '  3.6 %s\n' "$(t 'Управление сроком действия' 'Expiry management')"
    printf '  3.7 %s\n' "$(t 'Показать конфиг клиента' 'Show client config')"
    printf '  3.8 %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1|3.1) add_client ;;
      2|3.2) list_clients ;;
      3|3.3) edit_client ;;
      4|3.4) remove_client ;;
      5|3.5) toggle_client ;;
      6|3.6)
        section "$(t 'Срок действия' 'Expiry')"
        printf '  1) %s\n' "$(t 'Установить срок' 'Set expiry')"
        printf '  2) %s\n' "$(t 'Продлить срок' 'Extend expiry')"
        printf '  3) %s\n' "$(t 'Сбросить срок (бессрочно)' 'Reset expiry (never)')"
        printf '  4) %s\n' "$(t 'Показать истекающие / истёкшие' 'Show expiring / expired')"
        printf '  5) %s\n' "$(t 'Автопроверка (cron / systemd)' 'Auto-check (cron / systemd)')"
        local ech
        read -r -p "$(t 'Выбор: ' 'Choice: ')" ech || exit 0
        case "${ech}" in
          1) set_expiry ;;
          2) extend_expiry ;;
          3) reset_expiry ;;
          4) show_expiring ;;
          5) install_expiry_check ;;
        esac
        ;;
      7|3.7) show_client_config ;;
      8|3.8) break ;;
    esac
    [[ "${ch}" == "8" || "${ch}" == "3.8" ]] && break
    pause
  done
}

# monitor_menu — мониторинг (4)
monitor_menu() {
  while true; do
    section "$(t 'Мониторинг и статистика' 'Monitoring and statistics')"
    printf '  4.1 %s\n' "$(t 'wg show (активные / молчащие / потерянные)' 'wg show (active / silent / lost)')"
    printf '  4.2 %s\n' "$(t 'Трафик по клиентам' 'Traffic per client')"
    printf '  4.3 %s\n' "$(t 'Состояние systemd-сервиса' 'systemd service status')"
    printf '  4.4 %s\n' "$(t 'Ping всех пиров' 'Ping all peers')"
    printf '  4.5 %s\n' "$(t 'Публичный ключ сервера' 'Server public key')"
    printf '  4.6 %s\n' "$(t 'Внешний IP сервера' 'Server external IP')"
    printf '  4.7 %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1|4.1) show_status ;;
      2|4.2) show_traffic ;;
      3|4.3) systemctl status "wg-quick@${WG_IF}" --no-pager || true ;;
      4|4.4) ping_peers ;;
      5|4.5) show_server_pubkey ;;
      6|4.6) show_server_ip ;;
      7|4.7) break ;;
    esac
    [[ "${ch}" == "7" || "${ch}" == "4.7" ]] && break
    pause
  done
}

# service_menu — управление сервисом (5)
service_menu() {
  while true; do
    section "$(t 'Управление сервисом' 'Service management')"
    printf '  5.1 %s\n' "$(t 'Запустить' 'Start')"
    printf '  5.2 %s\n' "$(t 'Остановить' 'Stop')"
    printf '  5.3 %s\n' "$(t 'Перезапустить' 'Restart')"
    printf '  5.4 %s\n' "$(t 'Включить автозапуск' 'Enable autostart')"
    printf '  5.5 %s\n' "$(t 'Отключить автозапуск' 'Disable autostart')"
    printf '  5.6 %s\n' "$(t 'Перезагрузить конфиг без разрыва' 'Reload config without downtime')"
    printf '  5.7 %s\n' "$(t 'Показать journalctl' 'Show journalctl')"
    printf '  5.8 %s\n' "$(t 'Назад' 'Back')"
    local ch unit="wg-quick@${WG_IF}"
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1|5.1) systemctl start "${unit}" && info "$(t 'Запущен' 'Started')" ;;
      2|5.2) systemctl stop "${unit}" && info "$(t 'Остановлен' 'Stopped')" ;;
      3|5.3) systemctl restart "${unit}" && info "$(t 'Перезапущен' 'Restarted')" ;;
      4|5.4) systemctl enable "${unit}" && info "$(t 'Автозапуск включён' 'Autostart enabled')" ;;
      5|5.5) systemctl disable "${unit}" && info "$(t 'Автозапуск отключён' 'Autostart disabled')" ;;
      6|5.6) reload_config ;;
      7|5.7) show_journal ;;
      8|5.8) break ;;
    esac
    [[ "${ch}" == "8" || "${ch}" == "5.8" ]] && break
    pause
  done
}

# config_menu — редактирование конфига (6)
config_menu() {
  while true; do
    section "$(t 'Редактирование конфигурации' 'Configuration')"
    printf '  6.1 %s\n' "$(t 'Открыть wg0.conf в nano' 'Open wg0.conf in nano')"
    printf '  6.2 %s\n' "$(t 'Проверить синтаксис' 'Check syntax')"
    printf '  6.3 %s\n' "$(t 'Изменить внешний интерфейс' 'Change external interface')"
    printf '  6.4 %s\n' "$(t 'Изменить порт' 'Change port')"
    printf '  6.5 %s\n' "$(t 'Изменить VPN-подсеть' 'Change VPN subnet')"
    printf '  6.6 %s\n' "$(t 'Управление iptables' 'iptables management')"
    printf '  6.7 %s\n' "$(t 'Управление sysctl' 'sysctl management')"
    printf '  6.8 %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1|6.1) edit_config ;;
      2|6.2) check_config_syntax ;;
      3|6.3) change_external_interface ;;
      4|6.4) change_port ;;
      5|6.5) change_subnet ;;
      6|6.6) manage_iptables ;;
      7|6.7) manage_sysctl ;;
      8|6.8) break ;;
    esac
    [[ "${ch}" == "8" || "${ch}" == "6.8" ]] && break
    pause
  done
}

# routing_menu — маршрутизация (7)
routing_menu() {
  while true; do
    section "$(t 'Маршрутизация' 'Routing')"
    printf '  7.1 %s\n' "$(t 'Доступ клиентов к LAN сервера' 'Client access to server LAN')"
    printf '  7.2 %s\n' "$(t 'Доступ к LAN за клиентом' 'Access to LAN behind client')"
    printf '  7.3 %s\n' "$(t 'Site-to-Site' 'Site-to-Site')"
    printf '  7.4 %s\n' "$(t 'DNS (dnsmasq / AdGuardHome)' 'DNS (dnsmasq / AdGuardHome)')"
    printf '  7.5 %s\n' "$(t 'Ограничение скорости (tc)' 'Rate limiting (tc)')"
    printf '  7.6 %s\n' "$(t 'Split-tunnel' 'Split-tunnel')"
    printf '  7.7 %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1|7.1) allow_lan_access ;;
      2|7.2) allow_client_lan ;;
      3|7.3) setup_site_to_site ;;
      4|7.4) setup_dns ;;
      5|7.5) setup_rate_limit ;;
      6|7.6) setup_split_tunnel ;;
      7|7.7) break ;;
    esac
    [[ "${ch}" == "7" || "${ch}" == "7.7" ]] && break
    pause
  done
}

# setup_rate_limit — ограничение скорости через tc (7.5)
setup_rate_limit() {
  section "$(t 'Ограничение скорости (tc)' 'Rate limiting (tc)')"
  if ! command -v tc >/dev/null 2>&1; then
    warn "$(t 'tc не найден (iproute2)' 'tc not found (iproute2)')"
    return 1
  fi
  printf '  1) %s\n' "$(t 'Установить лимит' 'Set limit')"
  printf '  2) %s\n' "$(t 'Снять лимиты' 'Clear limits')"
  local ch
  read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
  case "${ch}" in
    1)
      local rate
      rate="$(prompt_value "$(t 'Лимит (например 10mbit)' 'Rate (e.g. 10mbit)')" "10mbit")"
      # удаляем старые qdisc
      tc qdisc del dev "${WG_IF}" root 2>/dev/null || true
      tc qdisc add dev "${WG_IF}" root handle 1: htb default 10
      tc class add dev "${WG_IF}" parent 1: classid 1:10 htb rate "${rate}"
      info "$(t "Лимит ${rate} на ${WG_IF}" "Limit ${rate} on ${WG_IF}")"
      warn "$(t 'Лимит действует до перезагрузки / wg-quick down' 'Limit lasts until reboot / wg-quick down')"
      ;;
    2)
      tc qdisc del dev "${WG_IF}" root 2>/dev/null || true
      info "$(t 'Лимиты сняты' 'Limits cleared')"
      ;;
  esac
  log INFO "setup_rate_limit: choice=${ch}"
}

# security_menu — безопасность (8)
security_menu() {
  while true; do
    section "$(t 'Безопасность' 'Security')"
    printf '  8.1 %s\n' "$(t 'Firewall (ufw / iptables)' 'Firewall (ufw / iptables)')"
    printf '  8.2 %s\n' "$(t 'Fail2ban для WireGuard' 'Fail2ban for WireGuard')"
    printf '  8.3 %s\n' "$(t 'Ограничение по IP' 'IP restriction')"
    printf '  8.4 %s\n' "$(t 'Аудит подключений' 'Connection audit')"
    printf '  8.5 %s\n' "$(t 'Ротация ключей сервера' 'Rotate server keys')"
    printf '  8.6 %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1|8.1) setup_firewall ;;
      2|8.2) setup_fail2ban ;;
      3|8.3) restrict_by_ip ;;
      4|8.4) audit_connections ;;
      5|8.5) rotate_server_keys ;;
      6|8.6) break ;;
    esac
    [[ "${ch}" == "6" || "${ch}" == "8.6" ]] && break
    pause
  done
}

# backup_menu — бэкап (9)
backup_menu() {
  while true; do
    section "$(t 'Бэкап / Восстановление' 'Backup / Restore')"
    printf '  9.1 %s\n' "$(t 'Создать бэкап' 'Create backup')"
    printf '  9.2 %s\n' "$(t 'Восстановить из бэкапа' 'Restore from backup')"
    printf '  9.3 %s\n' "$(t 'Автобэкап по расписанию' 'Scheduled backup')"
    printf '  9.4 %s\n' "$(t 'Список бэкапов' 'Backup list')"
    printf '  9.5 %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1|9.1) backup_create ;;
      2|9.2) backup_restore ;;
      3|9.3) backup_schedule ;;
      4|9.4) backup_list ;;
      5|9.5) break ;;
    esac
    [[ "${ch}" == "5" || "${ch}" == "9.5" ]] && break
    pause
  done
}

# maintenance_menu — обслуживание (10)
maintenance_menu() {
  while true; do
    section "$(t 'Обслуживание' 'Maintenance')"
    printf '  10.1 %s\n' "$(t 'Проверить обновления WireGuard' 'Check WireGuard updates')"
    printf '  10.2 %s\n' "$(t 'Очистить неактивных клиентов' 'Clean inactive clients')"
    printf '  10.3 %s\n' "$(t 'Удалить истёкших' 'Remove expired')"
    printf '  10.4 %s\n' "$(t 'Сбросить счётчики трафика' 'Reset traffic counters')"
    printf '  10.5 %s\n' "$(t 'Reboot через VPN' 'Reboot via VPN')"
    printf '  10.6 %s\n' "$(t 'Диагностика проблем' 'Problem diagnostics')"
    printf '  10.7 %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1|10.1) check_updates ;;
      2|10.2) clean_inactive ;;
      3|10.3) remove_expired ;;
      4|10.4) reset_counters ;;
      5|10.5)
        warn "$(t 'Сервер будет перезагружен' 'Server will reboot')"
        confirm "$(t 'Перезагрузить? (y/N): ' 'Reboot? (y/N): ')" || continue
        log WARN "maintenance: reboot requested"
        systemctl reboot
        ;;
      6|10.6) diagnostic_menu ;;
      7|10.7) break ;;
    esac
    [[ "${ch}" == "7" || "${ch}" == "10.7" ]] && break
    pause
  done
}

# diagnostic_menu — диагностика (11)
diagnostic_menu() {
  while true; do
    section "$(t 'Диагностика' 'Diagnostics')"
    printf '  11.1 %s\n' "$(t 'Проверить IP-форвардинг' 'Check IP forwarding')"
    printf '  11.2 %s\n' "$(t 'Проверить NAT' 'Check NAT')"
    printf '  11.3 %s\n' "$(t 'Проверить порт извне' 'Check external port')"
    printf '  11.4 %s\n' "$(t 'Ping всех пиров' 'Ping all peers')"
    printf '  11.5 %s\n' "$(t 'Проверка DNS через туннель' 'DNS check via tunnel')"
    printf '  11.6 %s\n' "$(t 'iperf3 между пирами' 'iperf3 between peers')"
    printf '  11.7 %s\n' "$(t 'Собрать отчёт для поддержки' 'Collect support report')"
    printf '  11.8 %s\n' "$(t 'Назад' 'Back')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1|11.1) check_forwarding ;;
      2|11.2) check_nat ;;
      3|11.3) check_port ;;
      4|11.4) ping_peers ;;
      5|11.5) check_dns ;;
      6|11.6) test_iperf ;;
      7|11.7) collect_report ;;
      8|11.8) break ;;
    esac
    [[ "${ch}" == "8" || "${ch}" == "11.8" ]] && break
    pause
  done
}

# uninstall_menu — удаление (13)
uninstall_menu() {
  uninstall_wg
  pause
}

# main_menu — главное меню (1)
main_menu() {
  while true; do
    init_colors
    printf '\n%b╔══════════════════════════════════════════╗%b\n' "${BLUE}" "${NC}"
    printf '%b║%b  wg-admin.sh v%-28s%b║%b\n' "${BLUE}" "${NC}" "${VERSION}" "${BLUE}" "${NC}"
    printf '%b║%b  %-39s%b║%b\n' "${BLUE}" "${NC}" \
      "$(t 'WireGuard Hub-and-Spoke администратор' 'WireGuard Hub-and-Spoke admin')" "${BLUE}" "${NC}"
    printf '%b╚══════════════════════════════════════════╝%b\n' "${BLUE}" "${NC}"
    printf '  1)  %s\n' "$(t '📦 Установка WireGuard' '📦 Install WireGuard')"
    printf '  2)  %s\n' "$(t '⚙️  Инициализация сервера' '⚙️  Server initialization')"
    printf '  3)  %s\n' "$(t '👥 Управление клиентами' '👥 Client management')"
    printf '  4)  %s\n' "$(t '📊 Мониторинг и статистика' '📊 Monitoring and statistics')"
    printf '  5)  %s\n' "$(t '🔧 Управление сервисом' '🔧 Service management')"
    printf '  6)  %s\n' "$(t '📝 Редактирование конфигурации' '📝 Edit configuration')"
    printf '  7)  %s\n' "$(t '🌐 Маршрутизация' '🌐 Routing')"
    printf '  8)  %s\n' "$(t '🛡️  Безопасность' '🛡️  Security')"
    printf '  9)  %s\n' "$(t '💾 Бэкап / Восстановление' '💾 Backup / Restore')"
    printf '  10) %s\n' "$(t '🔄 Обслуживание' '🔄 Maintenance')"
    printf '  11) %s\n' "$(t '🧪 Диагностика' '🧪 Diagnostics')"
    printf '  12) %s\n' "$(t '⚙️  Настройки скрипта' '⚙️  Script settings')"
    printf '  13) %s\n' "$(t '🚫 Удаление WireGuard' '🚫 Uninstall WireGuard')"
    printf '  14) %s\n' "$(t 'ℹ️  О скрипте' 'ℹ️  About')"
    printf '  0)  %s\n' "$(t '🚪 Выход' '🚪 Exit')"
    local ch
    read -r -p "$(t 'Выбор: ' 'Choice: ')" ch || exit 0
    case "${ch}" in
      1)
        section "$(t 'Установка' 'Install')"
        printf '  1) %s\n' "$(t 'Установить компоненты' 'Install components')"
        printf '  2) %s\n' "$(t 'Проверить установленные компоненты' 'Check installed components')"
        printf '  3) %s\n' "$(t 'Обновить WireGuard' 'Update WireGuard')"
        printf '  4) %s\n' "$(t 'Назад' 'Back')"
        local ich
        read -r -p "$(t 'Выбор: ' 'Choice: ')" ich || exit 0
        case "${ich}" in
          1) install_wireguard ;;
          2) check_installed ;;
          3) update_wireguard ;;
        esac
        ;;
      2) init_server ;;
      3) clients_menu ;;
      4) monitor_menu ;;
      5) service_menu ;;
      6) config_menu ;;
      7) routing_menu ;;
      8) security_menu ;;
      9) backup_menu ;;
      10) maintenance_menu ;;
      11) diagnostic_menu ;;
      12) settings_menu ;;
      13) uninstall_menu ;;
      14) about_menu ;;
      0) info "$(t 'Выход' 'Exit')"; log INFO "exit"; exit 0 ;;
      *)
        warn "$(t "Неизвестный пункт: ${ch}" "Unknown choice: ${ch}")"
        ;;
    esac
    pause
  done
}

# ==================== ТОЧКА ВХОДА ====================

# main — запуск скрипта
main() {
  case "${1:-}" in
    --help|-h)
      printf '%s\n' "wg-admin.sh v${VERSION} — $(t 'управление WireGuard (Hub-and-Spoke)' 'WireGuard admin (Hub-and-Spoke)')"
      printf '%s\n' "$(t 'Запуск: sudo bash wg-admin.sh' 'Run: sudo bash wg-admin.sh')"
      printf '%s\n' "$(t 'ОС: Debian 11/12, Ubuntu 20.04/22.04/24.04' 'OS: Debian 11/12, Ubuntu 20.04/22.04/24.04')"
      exit 0
      ;;
    --version|-V)
      printf '%s\n' "${VERSION}"
      exit 0
      ;;
  esac
  check_root
  check_os
  load_settings
  init_colors
  init_log
  main_menu
}

# Запуск только при прямом вызове (не при source — для тестов)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi

# ==================== ИСПОЛЬЗОВАНИЕ ====================
#
# Установка и первый запуск:
#   sudo apt install wireguard wireguard-tools qrencode iptables
#   sudo bash wg-admin.sh
#   → [2] Инициализация сервера (подсеть, порт, ключи, NAT, systemd)
#   → [3] Управление клиентами → 3.1 Добавить клиента (имя, IP, срок, QR)
#
# Повседневная работа:
#   [4] Мониторинг — wg show, трафик, ping пиров
#   [5] Сервис — старт/стоп/перезагрузка конфига без разрыва (wg syncconf)
#   [9] Бэкап — архивы конфигов, восстановление, автобэкап по cron
#
# Проверка скрипта:
#   bash -n wg-admin.sh
#   $ shellcheck ./wg-admin.sh
#
# Поддерживаемые ОС: Debian 11/12, Ubuntu 20.04/22.04/24.04 (x86_64, arm64)
# Требования: root, bash >= 4.4. Лицензия: MIT.

