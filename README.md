# wg-admin-bash

Интерактивные скрипты администрирования WireGuard-сервера (топология
Hub-and-Spoke) с меню. Объединяют до 6 ПК в единую VPN-сеть.

Два порта с одинаковой функциональностью:

| Скрипт | Платформа | Запуск |
|---|---|---|
| [`wg-admin.sh`](wg-admin.sh) | Debian 11/12, Ubuntu 20.04/22.04/24.04 | `sudo bash wg-admin.sh` |
| [`wg-admin.ps1`](wg-admin.ps1) | Windows 10/11, Server 2016+ | `powershell -ExecutionPolicy Bypass -File wg-admin.ps1` |

## Возможности

Установка WireGuard, инициализация сервера, управление клиентами (добавление,
срок действия, отключение без удаления), мониторинг трафика, управление
сервисом, редактирование конфига, маршрутизация (LAN, site-to-site,
split-tunnel), безопасность, бэкап/восстановление, обслуживание, диагностика,
ru/en интерфейс.

## Быстрый старт

1. Установите WireGuard (пункт меню **[1]** или вручную).
2. Запустите скрипт от администратора/root.
3. **[2] Инициализация сервера** — подсеть, порт, ключи, NAT, Firewall.
4. **[3] Управление клиентами → Добавить клиента** — конфиг и QR-код.

### Linux (`wg-admin.sh`)

```bash
sudo apt install wireguard wireguard-tools qrencode iptables
sudo bash wg-admin.sh
```

Конфиги: `/etc/wireguard/wg0.conf`, клиенты в `/etc/wireguard/clients/`.
Лог: `/var/log/wg-admin.log`.

### Windows (`wg-admin.ps1`)

```powershell
powershell -ExecutionPolicy Bypass -File wg-admin.ps1
```

Нужны права Администратора. Конфиги: `C:\ProgramData\wg-admin\`.
Туннель: `wireguard.exe /installtunnelservice`. NAT и Firewall настраиваются
скриптом автоматически.

## Проверка

```bash
# Linux
bash -n wg-admin.sh && shellcheck wg-admin.sh
sudo bash test-wg-admin.sh        # unit-тесты
sudo bash live-smoke.sh           # живой прогон init + add client
```

```powershell
# Windows
powershell -NoProfile -ExecutionPolicy Bypass -File test-wg-admin.ps1
```

## Лицензия

MIT
