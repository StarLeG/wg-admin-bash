# test-wg-admin.ps1 — тесты для wg-admin.ps1 (unit + интеграционные)
# Запуск: powershell -NoProfile -ExecutionPolicy Bypass -File test-wg-admin.ps1
#Requires -Version 5.1

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 2.0

$script:Pass = 0
$script:Fail = 0
$script:Errors = @()

function Ok([string]$Desc) {
    $script:Pass++
    Write-Host "  [OK] $Desc" -ForegroundColor Green
}

function Fail([string]$Desc) {
    $script:Fail++
    $script:Errors += $Desc
    Write-Host "  [--] $Desc" -ForegroundColor Red
}

function Assert-Eq([string]$Desc, $Expected, $Actual) {
    if ("$Expected" -eq "$Actual") { Ok $Desc }
    else { Fail "${Desc}: ожидалось '$Expected', получено '$Actual'" }
}

function Assert-True([string]$Desc, [bool]$Cond) {
    if ($Cond) { Ok $Desc } else { Fail $Desc }
}

function Assert-False([string]$Desc, [bool]$Cond) {
    if (-not $Cond) { Ok $Desc } else { Fail "${Desc}: ожидался false" }
}

# ---------- изолированное окружение ----------
$TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wg-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TestRoot -Force | Out-Null

$WgAdmin = Join-Path $PSScriptRoot 'wg-admin.ps1'
. $WgAdmin

# переопределить пути на изолированные
$script:WgIf         = 'wg0'
$script:WgDir        = $TestRoot
$script:ServerConf   = Join-Path $TestRoot 'server.conf'
$script:ClientsDir   = Join-Path $TestRoot 'clients'
$script:ExpiryDb     = Join-Path $TestRoot 'expiry.db'
$script:SettingsFile = Join-Path $TestRoot 'wg-admin.conf'
$script:LogDir       = Join-Path $TestRoot 'logs'
$script:LogFile      = Join-Path $TestRoot 'logs\wg-admin.log'
$script:ServerPrivKey = Join-Path $TestRoot 'server_private.key'
$script:ServerPubKey  = Join-Path $TestRoot 'server_public.key'
$script:VpnSubnet    = '10.8.0.0/24'
$script:ServerVpnIp  = '10.8.0.1'
$script:WgPort       = '51820'
$script:UseColor     = $false
New-Item -ItemType Directory -Path $script:ClientsDir -Force | Out-Null
New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null

Write-Host '=== UNIT: валидаторы ==='
Assert-True  'Test-ClientName: pc3' (Test-ClientName 'pc3')
Assert-True  'Test-ClientName: laptop-ivan' (Test-ClientName 'laptop-ivan')
Assert-True  'Test-ClientName: a_b-1' (Test-ClientName 'a_b-1')
Assert-False 'Test-ClientName: пусто' (Test-ClientName '')
Assert-False 'Test-ClientName: пробел' (Test-ClientName 'pc 3')
Assert-False 'Test-ClientName: слэш' (Test-ClientName 'a/b')
Assert-False 'Test-ClientName: инъекция' (Test-ClientName 'a;rm -rf /')

Assert-True  'Test-IpAddress: 10.8.0.1' (Test-IpAddress '10.8.0.1')
Assert-True  'Test-IpAddress: 255.255.255.255' (Test-IpAddress '255.255.255.255')
Assert-False 'Test-IpAddress: 256.0.0.1' (Test-IpAddress '256.0.0.1')
Assert-False 'Test-IpAddress: 1.2.3' (Test-IpAddress '1.2.3')
Assert-False 'Test-IpAddress: abc' (Test-IpAddress 'abc')

Assert-True  'Test-Cidr: 10.8.0.0/24' (Test-Cidr '10.8.0.0/24')
Assert-True  'Test-Cidr: 0.0.0.0/0' (Test-Cidr '0.0.0.0/0')
Assert-False 'Test-Cidr: 10.8.0.0' (Test-Cidr '10.8.0.0')
Assert-False 'Test-Cidr: 10.8.0.0/33' (Test-Cidr '10.8.0.0/33')

Assert-True  'Test-Port: 51820' (Test-Port '51820')
Assert-True  'Test-Port: 65535' (Test-Port '65535')
Assert-False 'Test-Port: 0' (Test-Port '0')
Assert-False 'Test-Port: 65536' (Test-Port '65536')
Assert-False 'Test-Port: abc' (Test-Port 'abc')

Write-Host '=== UNIT: ConvertFrom-Duration ==='
Assert-Eq 'never -> 0' '0' (ConvertFrom-Duration 'never')
Assert-Eq 'пусто -> 0' '0' (ConvertFrom-Duration '')
$now = Get-UnixNow
$ts = ConvertFrom-Duration '30d'
Assert-True '30d ≈ now+30d' ([math]::Abs($ts - ($now + 30 * 86400)) -lt 5)
$ts = ConvertFrom-Duration '12h'
Assert-True '12h ≈ now+12h' ([math]::Abs($ts - ($now + 12 * 3600)) -lt 5)
$ts = ConvertFrom-Duration '2099-12-31'
Assert-True 'YYYY-MM-DD -> число' ($ts -gt $now)
Assert-Eq 'unix ts' '1735689600' (ConvertFrom-Duration '1735689600')
Assert-True 'мусор -> null' ($null -eq (ConvertFrom-Duration 'abc'))

Write-Host '=== UNIT: Get-VpnNetwork ==='
Assert-Eq '10.8.0.5/24 -> 10.8.0.0/24' '10.8.0.0/24' (Get-VpnNetwork '10.8.0.5/24')
Assert-Eq '192.168.1.100/16 -> 192.168.0.0/16' '192.168.0.0/16' (Get-VpnNetwork '192.168.1.100/16')

Write-Host '=== UNIT: peer-блоки ==='
@'
[Interface]
Address = 10.8.0.1/32
ListenPort = 51820
PrivateKey = SERVERPRIV
'@ | Set-Content $script:ServerConf -Encoding ASCII

Add-PeerBlock -Name 'pc1' -PubKey 'PUBKEY1' -AllowedIps '10.8.0.2/32' -Keepalive '25' -Expires '0'
Add-PeerBlock -Name 'pc2' -PubKey 'PUBKEY2' -AllowedIps '10.8.0.3/32' -Keepalive '25' -Expires '1893456000'

$names = Get-PeerNames
Assert-Eq 'Get-PeerNames count' '2' $names.Count
Assert-True 'Test-PeerExists pc1' (Test-PeerExists 'pc1')
Assert-False 'Test-PeerExists pc3' (Test-PeerExists 'pc3')

Assert-Eq 'Get-PeerField pc1 AllowedIPs' '10.8.0.2/32' (Get-PeerField 'pc1' 'AllowedIPs')
Assert-Eq 'Get-PeerField pc1 PublicKey' 'PUBKEY1' (Get-PeerField 'pc1' 'PublicKey')
Assert-Eq 'Get-PeerField pc2 EXPIRES' '1893456000' (Get-PeerField 'pc2' 'EXPIRES')

Disable-Peer 'pc1'
Assert-True 'Disable-Peer: pc1 disabled' (Test-PeerDisabled 'pc1')
$block = Get-PeerBlock 'pc1'
Assert-True 'disable: PublicKey закомментирован' (($block -join "`n") -match '# PublicKey = PUBKEY1')
Assert-True 'disable: маркер DISABLED' (($block -join "`n") -match '# DISABLED 1')
Assert-True 'disable: [Peer] на месте' (($block -join "`n") -match '\[Peer\]')
Assert-False 'pc2 не отключён' (Test-PeerDisabled 'pc2')

Enable-Peer 'pc1'
Assert-False 'Enable-Peer: pc1 enabled' (Test-PeerDisabled 'pc1')
$block = Get-PeerBlock 'pc1'
Assert-True 'enable: PublicKey раскомментирован' (($block -join "`n") -match 'PublicKey = PUBKEY1')
Assert-False 'enable: маркер DISABLED удалён' (($block -join "`n") -match '# DISABLED 1')

Set-PeerField -Name 'pc1' -Field 'AllowedIPs' -Value '10.8.0.99/32'
Assert-Eq 'Set-PeerField AllowedIPs' '10.8.0.99/32' (Get-PeerField 'pc1' 'AllowedIPs')
Set-PeerField -Name 'pc1' -Field 'PublicKey' -Value 'NEWPUB1'
Assert-Eq 'Set-PeerField PublicKey' 'NEWPUB1' (Get-PeerField 'pc1' 'PublicKey')

Remove-PeerBlock 'pc1'
Assert-False 'Remove-PeerBlock: pc1 удалён' (Test-PeerExists 'pc1')
Assert-True 'Remove-PeerBlock: pc2 жив' (Test-PeerExists 'pc2')

Write-Host '=== UNIT: expiry ==='
Set-Expiry -Name 'pc2' -Ts '1893456000'
Assert-Eq 'Set-Expiry/Get-Expiry' '1893456000' (Get-Expiry 'pc2')
Assert-False 'Test-PeerExpired pc2 (2030)' (Test-PeerExpired 'pc2')

Set-Expiry -Name 'pc2' -Ts "$((Get-UnixNow) - 100)"
Assert-True 'Test-PeerExpired pc2 (в прошлом)' (Test-PeerExpired 'pc2')

Set-Expiry -Name 'pc2' -Ts '0'
Assert-False 'Test-PeerExpired pc2 (бессрочно)' (Test-PeerExpired 'pc2')

Write-Host '=== UNIT: Get-NextFreeIp ==='
$ip = Get-NextFreeIp
Assert-Eq 'Get-NextFreeIp не занят сервером' '10.8.0.2' $ip

Write-Host '=== UNIT: логирование ==='
Write-Log -Level INFO -Message 'тестовая запись'
$log = Get-Content $script:LogFile -Raw
Assert-True 'Write-Log пишет в файл' ($log -match 'тестовая запись')
Assert-True 'Write-Log содержит [INFO]' ($log -match '\[INFO\]')

Write-Host '=== UNIT: Save/Load-Settings ==='
$script:VpnSubnet = '10.9.0.0/24'
$script:WgPort = '51821'
$script:DnsDefault = '8.8.8.8'
$script:LangUi = 'en'
Save-Settings
$script:VpnSubnet = '0.0.0.0/0'
$script:WgPort = '1'
$script:DnsDefault = '1.2.3.4'
$script:LangUi = 'ru'
Load-Settings
Assert-Eq 'Save/Load VpnSubnet' '10.9.0.0/24' $script:VpnSubnet
Assert-Eq 'Save/Load WgPort' '51821' $script:WgPort
Assert-Eq 'Save/Load DnsDefault' '8.8.8.8' $script:DnsDefault
Assert-Eq 'Save/Load LangUi' 'en' $script:LangUi
$script:LangUi = 'ru'

Write-Host '=== UNIT: t() локализация ==='
$script:LangUi = 'ru'
Assert-Eq 't ru' 'Продолжить' (t 'Продолжить' 'Continue')
$script:LangUi = 'en'
Assert-Eq 't en' 'Continue' (t 'Продолжить' 'Continue')
$script:LangUi = 'ru'

Write-Host '=== CLI: -Help / -Version ==='
$out = & powershell -NoProfile -ExecutionPolicy Bypass -File $WgAdmin -Version 2>&1 | Out-String
Assert-True 'CLI -Version' ($out.Trim() -eq '1.0.0')
$out = & powershell -NoProfile -ExecutionPolicy Bypass -File $WgAdmin -Help 2>&1 | Out-String
Assert-True 'CLI -Help упоминает wg-admin.ps1' ($out -match 'wg-admin.ps1')

Write-Host '=== UNIT: Get-StrippedConfig ==='
@'
# comment
[Interface]
Address = 10.8.0.1/32
ListenPort = 51820
PrivateKey = PRIVKEY
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = PEERPUB
AllowedIPs = 10.8.0.2/32
'@ | Set-Content $script:ServerConf -Encoding ASCII
$stripped = Get-StrippedConfig -ConfPath $script:ServerConf
$sw = $stripped -join "`n"
Assert-True 'strip: ListenPort оставлен' ($sw -match 'ListenPort = 51820')
Assert-True 'strip: PrivateKey оставлен' ($sw -match 'PrivateKey = PRIVKEY')
Assert-False 'strip: Address отброшен' ($sw -match 'Address =')
Assert-False 'strip: DNS отброшен' ($sw -match 'DNS =')
Assert-False 'strip: MTU отброшен' ($sw -match 'MTU =')
Assert-True 'strip: пир оставлен' ($sw -match 'PEERPUB')
Assert-False 'strip: комментарии отброшены' ($sw -match '# comment')

Write-Host ''
Write-Host '======================================'
Write-Host "ИТОГО: $($script:Pass) passed, $($script:Fail) failed"
if ($script:Fail -gt 0) {
    Write-Host 'Провалы:'
    foreach ($e in $script:Errors) { Write-Host "  - $e" }
    Remove-Item $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}
Remove-Item $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'ВСЕ ТЕСТЫ ПРОШЛИ'
exit 0
