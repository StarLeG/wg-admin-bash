#!/usr/bin/env bash
# live-smoke.sh — живой прогон init_server + add_client через меню wg-admin.sh
# Учитывает pause после каждого действия меню.
set -o pipefail
S=/mnt/d/VPN/wg-admin.sh
OUT=/tmp/wg-live.out
IN=/tmp/wg-live.in

# чистое состояние
rm -rf /etc/wireguard
rm -f /var/log/wg-admin.log

{
  echo 2          # главноe меню → инициализация сервера
  echo            # внешний интерфейс (авто)
  echo            # VPN-подсеть (дефолт)
  echo            # VPN IP сервера
  echo            # порт
  echo            # DNS
  echo            # MTU
  echo            # pause после init
  echo 3          # → управление клиентами
  echo 3.1        # → добавить клиента
  echo pc1        # имя
  echo            # VPN IP (дефолт)
  echo            # публичный ключ (сгенерировать)
  echo            # внешний адрес (авто)
  echo            # порт
  echo 1          # режим: только VPN-сеть
  echo            # DNS
  echo            # keepalive
  echo            # MTU
  echo never      # срок
  echo smoke      # комментарий
  echo n          # QR
  echo            # pause после add_client
  echo 3.8        # назад из клиентов
  echo            # pause после выхода из клиентов
  echo 0          # выход
} >"${IN}"

timeout 30 bash "${S}" <"${IN}" >"${OUT}" 2>&1
echo "RC:$?"
echo "--- output ---"
cat "${OUT}"
echo "--- wg0.conf ---"
cat /etc/wireguard/wg0.conf 2>/dev/null
echo "--- client pc1.conf ---"
cat /etc/wireguard/clients/pc1.conf 2>/dev/null
echo "--- perms ---"
stat -c '%a %n' /etc/wireguard/server_private.key /etc/wireguard/clients/pc1.conf 2>/dev/null
echo "--- expiry.db ---"
cat /etc/wireguard/expiry.db 2>/dev/null
echo "--- log ---"
grep -E 'add_client|init_server|Создан|Файл клиента' /var/log/wg-admin.log 2>/dev/null
