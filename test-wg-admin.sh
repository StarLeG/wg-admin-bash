#!/usr/bin/env bash
# test-wg-admin.sh — тесты для wg-admin.sh (unit + интеграционные)
# Запуск: sudo bash test-wg-admin.sh
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WG_ADMIN="${SCRIPT_DIR}/wg-admin.sh"

PASS=0
FAIL=0
ERRORS=()

# ---------- ассерты ----------
ok() {
  PASS=$((PASS + 1))
  printf '  %b✔%b %s\n' "${GREEN:-}" "${NC:-}" "$1"
}

fail() {
  FAIL=$((FAIL + 1))
  ERRORS+=("$1")
  printf '  %b✖%b %s\n' "${RED:-}" "${NC:-}" "$1"
}

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    ok "${desc}"
  else
    fail "${desc}: ожидалось '${expected}', получено '${actual}'"
  fi
}

assert_ok() {
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    ok "${desc}"
  else
    fail "${desc}: команда не прошла"
  fi
}

assert_fail() {
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "${desc}: ожидался отказ, но команда прошла"
  else
    ok "${desc}"
  fi
}

assert_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    ok "${desc}"
  else
    fail "${desc}: не найдено '${needle}'"
  fi
}

# ---------- подготовка изолированного окружения ----------
TEST_ROOT="$(mktemp -d)"
export WG_IF="wg0"
export WG_DIR="${TEST_ROOT}/wireguard"
export WG_CONF="${WG_DIR}/wg0.conf"
export CLIENTS_DIR="${WG_DIR}/clients"
export EXPIRY_DB="${WG_DIR}/expiry.db"
export SETTINGS_FILE="${WG_DIR}/wg-admin.conf"
export SERVER_PRIVATE_KEY="${WG_DIR}/server_private.key"
export SERVER_PUBLIC_KEY="${WG_DIR}/server_public.key"
export LOG_FILE="${TEST_ROOT}/wg-admin.log"
mkdir -p "${CLIENTS_DIR}"

# shellcheck source=/dev/null
source "${WG_ADMIN}"

# пере-установить пути после source (константы перезаписали переменные)
WG_IF="wg0"
WG_DIR="${TEST_ROOT}/wireguard"
WG_CONF="${WG_DIR}/wg0.conf"
CLIENTS_DIR="${WG_DIR}/clients"
EXPIRY_DB="${WG_DIR}/expiry.db"
SETTINGS_FILE="${WG_DIR}/wg-admin.conf"
SERVER_PRIVATE_KEY="${WG_DIR}/server_private.key"
SERVER_PUBLIC_KEY="${WG_DIR}/server_public.key"
LOG_FILE="${TEST_ROOT}/wg-admin.log"
VPN_SUBNET="10.8.0.0/24"
SERVER_VPN_IP="10.8.0.1"
WG_PORT="51820"

printf '%s\n' "=== UNIT: валидаторы ==="

assert_ok   "validate_name: pc3" validate_name "pc3"
assert_ok   "validate_name: laptop-ivan" validate_name "laptop-ivan"
assert_ok   "validate_name: a_b-1" validate_name "a_b-1"
assert_fail "validate_name: пусто" validate_name ""
assert_fail "validate_name: пробел" validate_name "pc 3"
assert_fail "validate_name: слэш" validate_name "a/b"
assert_fail "validate_name: точка" validate_name "a.b"
assert_fail "validate_name: инъекция" validate_name 'a;rm -rf /'

assert_ok   "validate_ip: 10.8.0.1" validate_ip "10.8.0.1"
assert_ok   "validate_ip: 255.255.255.255" validate_ip "255.255.255.255"
assert_fail "validate_ip: 256.0.0.1" validate_ip "256.0.0.1"
assert_fail "validate_ip: 1.2.3" validate_ip "1.2.3"
assert_fail "validate_ip: abc" validate_ip "abc"
assert_fail "validate_ip: 10.8.0.1;id" validate_ip "10.8.0.1;id"

assert_ok   "validate_cidr: 10.8.0.0/24" validate_cidr "10.8.0.0/24"
assert_ok   "validate_cidr: 0.0.0.0/0" validate_cidr "0.0.0.0/0"
assert_fail "validate_cidr: 10.8.0.0" validate_cidr "10.8.0.0"
assert_fail "validate_cidr: 10.8.0.0/33" validate_cidr "10.8.0.0/33"
assert_fail "validate_cidr: 10.8.0.0/-1" validate_cidr "10.8.0.0/-1"

assert_ok   "validate_port: 51820" validate_port "51820"
assert_ok   "validate_port: 1" validate_port "1"
assert_ok   "validate_port: 65535" validate_port "65535"
assert_fail "validate_port: 0" validate_port "0"
assert_fail "validate_port: 65536" validate_port "65536"
assert_fail "validate_port: abc" validate_port "abc"

printf '%s\n' "=== UNIT: parse_duration ==="

now="$(date +%s)"
ts="$(parse_duration never)"
assert_eq "parse_duration never → 0" "0" "${ts}"

ts="$(parse_duration 30d)"
assert_eq "parse_duration 30d ≈ now+30d" "$(( now + 30 * 86400 ))" "${ts}"

ts="$(parse_duration 12h)"
assert_eq "parse_duration 12h ≈ now+12h" "$(( now + 12 * 3600 ))" "${ts}"

ts="$(parse_duration 2099-12-31)"
assert_ok "parse_duration YYYY-MM-DD → число" bash -c "[[ '${ts}' =~ ^[0-9]+$ ]]"

ts="$(parse_duration 1735689600)"
assert_eq "parse_duration unix ts" "1735689600" "${ts}"

assert_fail "parse_duration: мусор" parse_duration "abc"

printf '%s\n' "=== UNIT: vpn_network ==="

assert_eq "vpn_network 10.8.0.5/24" "10.8.0.0/24" "$(vpn_network '10.8.0.5/24')"
assert_eq "vpn_network 192.168.1.100/16" "192.168.0.0/16" "$(vpn_network '192.168.1.100/16')"

printf '%s\n' "=== UNIT: peer-блоки в wg0.conf ==="

cat >"${WG_CONF}" <<'EOF'
[Interface]
Address = 10.8.0.1/32
ListenPort = 51820
PrivateKey = SERVERPRIV
EOF

append_peer_block "pc1" "PUBKEY1" "10.8.0.2/32" "25" "0"
append_peer_block "pc2" "PUBKEY2" "10.8.0.3/32" "25" "1893456000"

names="$(peer_names | tr '\n' ' ')"
assert_eq "peer_names после добавления" "pc1 pc2 " "${names}"
assert_ok   "peer_exists pc1" peer_exists "pc1"
assert_fail "peer_exists pc3" peer_exists "pc3"

assert_eq "peer_field pc1 AllowedIPs" "10.8.0.2/32" "$(peer_field pc1 AllowedIPs)"
assert_eq "peer_field pc1 PublicKey" "PUBKEY1" "$(peer_field pc1 PublicKey)"
assert_eq "peer_field pc2 EXPIRES" "1893456000" "$(peer_field pc2 EXPIRES)"

# disable
comment_peer_lines "pc1"
assert_ok "peer_is_disabled pc1" peer_is_disabled "pc1"
assert_contains "disable: PublicKey закомментирован" "$(extract_peer_block pc1)" "# PublicKey = PUBKEY1"
assert_contains "disable: маркер DISABLED" "$(extract_peer_block pc1)" "# DISABLED 1"
assert_contains "disable: [Peer] на месте" "$(extract_peer_block pc1)" "[Peer]"
assert_fail "pc2 не отключён" peer_is_disabled "pc2"

# enable
uncomment_peer_lines "pc1"
assert_fail "peer_is_disabled pc1 после enable" peer_is_disabled "pc1"
assert_contains "enable: PublicKey раскомментирован" "$(extract_peer_block pc1)" "PublicKey = PUBKEY1"
assert_fail "enable: маркер DISABLED удалён" bash -c "extract_peer_block pc1 | grep -q '^# DISABLED'"

# изменение полей
set_peer_allowed_ips "pc1" "10.8.0.99/32"
assert_eq "set_peer_allowed_ips" "10.8.0.99/32" "$(peer_field pc1 AllowedIPs)"
set_peer_pubkey "pc1" "NEWPUB1"
assert_eq "set_peer_pubkey" "NEWPUB1" "$(peer_field pc1 PublicKey)"

# удаление
remove_peer_block "pc1"
assert_fail "remove_peer_block: pc1 удалён" peer_exists "pc1"
assert_ok   "remove_peer_block: pc2 жив" peer_exists "pc2"

printf '%s\n' "=== UNIT: expiry ==="

expiry_set "pc2" "1893456000"
assert_eq "expiry_set/get" "1893456000" "$(expiry_get pc2)"
assert_fail "peer_is_expired pc2 (2030)" peer_is_expired "pc2"

expiry_set "pc2" "$(( now - 100 ))"
assert_ok "peer_is_expired pc2 (в прошлом)" peer_is_expired "pc2"

expiry_set "pc2" "0"
assert_fail "peer_is_expired pc2 (бессрочно)" peer_is_expired "pc2"

printf '%s\n' "=== UNIT: next_free_ip ==="

ip="$(next_free_ip)"
assert_eq "next_free_ip не занят сервером" "10.8.0.2" "${ip}"

printf '%s\n' "=== UNIT: логирование ==="

log INFO "тестовая запись"
assert_contains "log пишет в файл" "$(cat "${LOG_FILE}")" "тестовая запись"
assert_contains "log содержит timestamp" "$(cat "${LOG_FILE}")" "[INFO]"

printf '%s\n' "=== CLI: --help / --version / root-check ==="

out="$(bash "${WG_ADMIN}" --version 2>&1)"
assert_eq "--version" "1.0.0" "${out}"

out="$(bash "${WG_ADMIN}" --help 2>&1)"
assert_contains "--help упоминает запуск" "${out}" "wg-admin.sh"

# root-check: от имени пользователя (uid != 0)
if [[ "${EUID}" -eq 0 ]]; then
  out="$(setpriv --reuid=1000 --regid=1000 --clear-groups bash "${WG_ADMIN}" 2>&1 || true)"
  assert_contains "root-check отклоняет uid=1000" "${out}" "root"
else
  out="$(bash "${WG_ADMIN}" 2>&1 || true)"
  assert_contains "root-check отклоняет не-root" "${out}" "root"
fi

printf '%s\n' "=== CLI: меню (smoke) ==="

out="$(echo 0 | bash "${WG_ADMIN}" 2>&1)"
assert_contains "меню: заголовок" "${out}" "wg-admin.sh"
assert_contains "меню: пункт 1" "${out}" "Установка WireGuard"
assert_contains "меню: пункт 14" "${out}" "О скрипте"
assert_contains "меню: выход по 0" "${out}" "Выход"

out="$(echo 0 | bash "${WG_ADMIN}" 2>&1 | tail -1)"
assert_contains "меню: последняя строка — выход" "${out}" "Выход"

# EOF не должен крутиться вечно
out="$(timeout 5 bash -c 'bash "'"${WG_ADMIN}"'" </dev/null' 2>&1)"
rc=$?
assert_eq "EOF завершает скрипт (timeout=0)" "0" "${rc}"

printf '%s\n' "=== ИНТЕГРАЦИЯ: init/add/list/toggle ==="

# Работаем в изолированном WG_DIR, который уже настроен выше.
# init_server через pipe: дефолты + подтверждение перезаписи не требуется (конфига нет).
# Внешний интерфейс определяется автоматически.
export VPN_SUBNET="10.8.0.0/24"
export WG_PORT="51820"
export DNS_DEFAULT="1.1.1.1"

# Сгенерируем ключи «сервера» и минимальный конфиг, как это делает init_server,
# без вызова apt/systemctl (в WSL systemctl wg-quick может отсутствовать как сервис).
generate_server_keys
assert_ok   "server_private.key создан" test -f "${SERVER_PRIVATE_KEY}"
assert_ok   "server_public.key создан" test -f "${SERVER_PUBLIC_KEY}"
mode="$(stat -c '%a' "${SERVER_PRIVATE_KEY}")"
assert_eq "приватный ключ 600" "600" "${mode}"

cat >"${WG_CONF}" <<EOF
[Interface]
Address = ${SERVER_VPN_IP}/32
ListenPort = ${WG_PORT}
PrivateKey = $(cat "${SERVER_PRIVATE_KEY}")
SaveConfig = false
EOF
chmod 600 "${WG_CONF}"

# add_client логика без интерактива — через append + write_client_config
read -r cpriv cpub <<<"$(generate_client_keys)"
assert_ok "generate_client_keys выдал пару" bash -c "[[ -n '${cpriv}' && -n '${cpub}' ]]"

conf="$(write_client_config "pc1" "${cpriv}" "$(cat "${SERVER_PUBLIC_KEY}")" \
  "203.0.113.5:51820" "10.8.0.2" "${VPN_SUBNET}" "1.1.1.1" "25" "")"
assert_ok "write_client_config создал файл" test -f "${conf}"
mode="$(stat -c '%a' "${conf}")"
assert_eq "конфиг клиента 600" "600" "${mode}"
assert_contains "конфиг: PrivateKey" "$(cat "${conf}")" "PrivateKey = ${cpriv}"
assert_contains "конфиг: Endpoint" "$(cat "${conf}")" "Endpoint = 203.0.113.5:51820"
assert_contains "конфиг: AllowedIPs" "$(cat "${conf}")" "AllowedIPs = 10.8.0.0/24"

append_peer_block "pc1" "${cpub}" "10.8.0.2/32" "25" "0"
expiry_set "pc1" "0"
assert_ok "пир pc1 добавлен" peer_exists "pc1"

read -r cpriv2 cpub2 <<<"$(generate_client_keys)"
conf2="$(write_client_config "pc2" "${cpriv2}" "$(cat "${SERVER_PUBLIC_KEY}")" \
  "203.0.113.5:51820" "10.8.0.3" "${VPN_SUBNET}" "1.1.1.1" "25" "")"
assert_ok "write_client_config создал pc2.conf" test -f "${conf2}"
append_peer_block "pc2" "${cpub2}" "10.8.0.3/32" "25" "0"
expiry_set "pc2" "$(( now - 10 ))"

assert_ok "peer_is_expired pc2" peer_is_expired "pc2"

# сценарий «отключение истёкшего» (как делает wg-expire-check / toggle)
comment_peer_lines "pc2"
assert_ok "истёкший pc2 отключён" peer_is_disabled "pc2"
assert_ok "wg0.conf валиден после отключения" bash -c "grep -q 'PublicKey = ${cpub}' '${WG_CONF}'"

# продление включает обратно
extend_ok=1
expiry_set "pc2" "$(( now + 86400 ))"
uncomment_peer_lines "pc2"
if peer_is_disabled "pc2"; then extend_ok=0; fi
assert_eq "продление срока включает пира" "1" "${extend_ok}"

# идемпотентность append + дубликат имён
assert_ok "повторный append не рушит файл" bash -c "grep -q '^\[Interface\]' '${WG_CONF}'"

# сохранение/загрузка настроек
VPN_SUBNET="10.9.0.0/24"
WG_PORT="51821"
DNS_DEFAULT="8.8.8.8"
LANG_UI="en"
save_settings
VPN_SUBNET="0.0.0.0/0"
WG_PORT="1"
DNS_DEFAULT="1.2.3.4"
LANG_UI="ru"
load_settings
assert_eq "save/load VPN_SUBNET" "10.9.0.0/24" "${VPN_SUBNET}"
assert_eq "save/load WG_PORT" "51821" "${WG_PORT}"
assert_eq "save/load DNS_DEFAULT" "8.8.8.8" "${DNS_DEFAULT}"
assert_eq "save/load LANG_UI" "en" "${LANG_UI}"

printf '\n'
printf '%s\n' "======================================"
printf 'ИТОГО: %s passed, %s failed\n' "${PASS}" "${FAIL}"
if (( FAIL > 0 )); then
  printf '%s\n' "Провалы:"
  for e in "${ERRORS[@]}"; do
    printf '  - %s\n' "${e}"
  done
  rm -rf "${TEST_ROOT}"
  exit 1
fi
rm -rf "${TEST_ROOT}"
printf '%s\n' "ВСЕ ТЕСТЫ ПРОШЛИ"
exit 0
