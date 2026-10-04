# wg-admin.ps1 — Управление WireGuard сервером (Hub-and-Spoke) для Windows
# Версия: 1.0.0
# Лицензия: MIT
# Требуется: Windows 10/11 или Server 2016+, PowerShell 5.1+, WireGuard для Windows, права Администратора.
#
# Использование:
#   powershell -ExecutionPolicy Bypass -File wg-admin.ps1
#   powershell -File wg-admin.ps1 -Help
# Первый запуск: [2] Инициализация сервера → [3] Управление клиентами → Добавить клиента.

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Help,
    [switch]$Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# ==================== КОНСТАНТЫ ====================
$script:WgIf           = 'wg0'
$script:WgDir          = 'C:\ProgramData\wg-admin'
$script:ServerConf     = Join-Path $script:WgDir 'server.conf'
$script:ClientsDir     = Join-Path $script:WgDir 'clients'
$script:ExpiryDb       = Join-Path $script:WgDir 'expiry.db'
$script:SettingsFile   = Join-Path $script:WgDir 'wg-admin.conf'
$script:LogDir         = Join-Path $script:WgDir 'logs'
$script:LogFile        = Join-Path $script:LogDir 'wg-admin.log'
$script:ServerPrivKey  = Join-Path $script:WgDir 'server_private.key'
$script:ServerPubKey   = Join-Path $script:WgDir 'server_public.key'
$script:BackupDir      = Join-Path $script:WgDir 'backups'
$script:AppVersion        = '1.0.0'
$script:ServerVpnIp    = '10.8.0.1'
$script:VpnSubnet      = '10.8.0.0/24'
$script:WgPort         = '51820'
$script:DnsDefault     = '1.1.1.1'
$script:MtuDefault     = ''
$script:ClientKeepalive = '25'
$script:WgExe          = 'C:\Program Files\WireGuard\wg.exe'
$script:WireguardExe   = 'C:\Program Files\WireGuard\wireguard.exe'
$script:ExpireCheckPs1 = Join-Path $script:WgDir 'wg-expire-check.ps1'

# ==================== СОСТОЯНИЕ ====================
$script:UseColor = $true
$script:LogLevel = 'INFO'   # DEBUG | INFO | WARN | ERROR
$script:LangUi   = 'ru'     # ru | en

# ==================== ЛОКАЛИЗАЦИЯ ====================
function t {
    param([string]$Ru, [string]$En)
    if ($script:LangUi -eq 'en') { return $En }
    return $Ru
}

# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    param([string]$Level = 'INFO', [string]$Message)
    $levels = @{ DEBUG = 0; INFO = 1; WARN = 2; ERROR = 3 }
    $cur = 1
    if ($levels.ContainsKey($script:LogLevel)) { $cur = $levels[$script:LogLevel] }
    $lvl = 1
    if ($levels.ContainsKey($Level)) { $lvl = $levels[$Level] }
    if ($lvl -lt $cur) { return }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = '[{0}] [{1}] {2}' -f $ts, $Level, $Message
    try {
        if (-not (Test-Path $script:LogDir)) {
            New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
        }
        Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
    } catch { }
}

function Write-Info {
    param([string]$Message)
    if ($script:UseColor) {
        Write-Host "[INFO] $Message" -ForegroundColor Green
    } else {
        Write-Host "[INFO] $Message"
    }
    Write-Log -Level INFO -Message $Message
}

function Write-WarningMsg {
    param([string]$Message)
    if ($script:UseColor) {
        Write-Host "[WARN] $Message" -ForegroundColor Yellow
    } else {
        Write-Host "[WARN] $Message"
    }
    Write-Log -Level WARN -Message $Message
}

function Exit-WithError {
    param([string]$Message)
    if ($script:UseColor) {
        Write-Host "[ERROR] $Message" -ForegroundColor Red
    } else {
        Write-Host "[ERROR] $Message"
    }
    Write-Log -Level ERROR -Message $Message
    exit 1
}

function Show-Section {
    param([string]$Title)
    Write-Host ''
    if ($script:UseColor) {
        Write-Host "=== $Title ===" -ForegroundColor Cyan
    } else {
        Write-Host "=== $Title ==="
    }
}

function Pause-Menu {
    $msg = t 'Нажмите Enter для продолжения...' 'Press Enter to continue...'
    try {
        Read-Host -Prompt $msg | Out-Null
    } catch {
        exit 0
    }
}

function Read-Value {
    param([string]$Prompt, [string]$Default = '')
    try {
        if ($Default -ne '') {
            $ans = Read-Host -Prompt "$Prompt [$Default]"
            if ([string]::IsNullOrWhiteSpace($ans)) { return $Default }
            return $ans.Trim()
        }
        $ans = Read-Host -Prompt $Prompt
        if ($null -eq $ans) { Exit-WithError (t 'Ввод закрыт' 'Input closed') }
        return $ans.Trim()
    } catch {
        Exit-WithError (t 'Ввод закрыт' 'Input closed')
    }
}

function Read-YesNo {
    param([string]$Prompt)
    $ans = Read-Host -Prompt "$Prompt (y/N)"
    return ($ans -match '^[Yy]$')
}

function Confirm-Action {
    param([string]$Prompt = '')
    if ($Prompt -eq '') { $Prompt = t 'Продолжить? (y/N): ' 'Continue? (y/N): ' }
    return (Read-YesNo $Prompt)
}

# ---------- валидация ----------
function Test-ClientName {
    param([string]$Name)
    return ($Name -match '^[a-zA-Z0-9_-]+$')
}

function Test-IpAddress {
    param([string]$Ip)
    if ($Ip -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { return $false }
    foreach ($o in $Ip.Split('.')) {
        $n = 0
        if (-not [int]::TryParse($o, [ref]$n)) { return $false }
        if ($n -lt 0 -or $n -gt 255) { return $false }
    }
    return $true
}

function Test-Cidr {
    param([string]$Cidr)
    if ($Cidr -notmatch '/') { return $false }
    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) { return $false }
    if (-not (Test-IpAddress $parts[0])) { return $false }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix)) { return $false }
    return ($prefix -ge 0 -and $prefix -le 32)
}

function Test-Port {
    param([string]$Port)
    $n = 0
    if (-not [int]::TryParse($Port, [ref]$n)) { return $false }
    return ($n -ge 1 -and $n -le 65535)
}

function Test-InterfaceExists {
    param([string]$Name)
    return [bool](Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue)
}

# ---------- сеть ----------
function Get-DetectInterface {
    # интерфейс с шлюзом по умолчанию
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1
    if ($route) {
        $if = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        if ($if) { return $if.InterfaceAlias }
    }
    return ''
}

function Get-ExternalIp {
    foreach ($url in @('https://ifconfig.me/ip', 'https://api.ipify.org', 'https://icanhazip.com')) {
        try {
            $ip = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5).Content.Trim()
            if (Test-IpAddress $ip) { return $ip }
        } catch { }
    }
    return ''
}

function Get-VpnNetwork {
    param([string]$Cidr)
    $parts = $Cidr.Split('/')
    $ip = $parts[0]; $prefix = [int]$parts[1]
    $oct = $ip.Split('.') | ForEach-Object { [int]$_ }
    $n = ($oct[0] -shl 24) -bor ($oct[1] -shl 16) -bor ($oct[2] -shl 8) -bor $oct[3]
    if ($prefix -eq 0) { $mask = 0 } else { $mask = -bnot ((1 -shl (32 - $prefix)) - 1) }
    # PowerShell -shl может дать Int64; маскируем 32 бита
    $mask = $mask -band 0xFFFFFFFF
    $n = $n -band $mask
    $a = ($n -shr 24) -band 255
    $b = ($n -shr 16) -band 255
    $c = ($n -shr 8) -band 255
    $d = $n -band 255
    return "$a.$b.$c.$d/$prefix"
}

# ---------- сроки действия ----------
function ConvertFrom-Duration {
    param([string]$Text)
    $now = [int][double]::Parse((Get-Date -UFormat %s))
    switch -Regex ($Text) {
        '^(never|NEVER|Never|)$' { return 0 }
        '^(\d+)d$' { return [int64]($now + ([int64]$Matches[1] * 86400)) }
        '^(\d+)h$' { return [int64]($now + ([int64]$Matches[1] * 3600)) }
        '^\d{4}-\d{2}-\d{2}$' {
            $dt = [datetime]::ParseExact($Text, 'yyyy-MM-dd', $null)
            return [int64][double]::Parse(($dt.AddHours(23).AddMinutes(59).AddSeconds(59) | Get-Date -UFormat %s))
        }
        '^\d+$' { return [int64]$Text }
        default { return $null }
    }
}

function Format-Ts {
    param([string]$Ts)
    if ([string]::IsNullOrWhiteSpace($Ts) -or $Ts -eq '0') {
        return (t 'бессрочно' 'never')
    }
    try {
        $dt = [DateTimeOffset]::FromUnixTimeSeconds([int64]$Ts).LocalDateTime
        return $dt.ToString('yyyy-MM-dd HH:mm')
    } catch { return $Ts }
}

function Get-UnixNow {
    return [int64][double]::Parse((Get-Date -UFormat %s))
}

# ---------- настройки ----------
function Load-Settings {
    if (-not (Test-Path $script:SettingsFile)) { return }
    foreach ($line in Get-Content $script:SettingsFile) {
        if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
        $k, $v = $line.Split('=', 2)
        switch ($k.Trim()) {
            'VpnSubnet'  { $script:VpnSubnet = $v.Trim() }
            'WgPort'     { $script:WgPort = $v.Trim() }
            'DnsDefault' { $script:DnsDefault = $v.Trim() }
            'UseColor'   { $script:UseColor = ($v.Trim() -eq '1') }
            'LogLevel'   { $script:LogLevel = $v.Trim() }
            'LangUi'     { $script:LangUi = $v.Trim() }
        }
    }
}

function Save-Settings {
    if (-not (Test-Path $script:WgDir)) {
        New-Item -ItemType Directory -Path $script:WgDir -Force | Out-Null
    }
    $lines = @(
        '# wg-admin.ps1 settings',
        "VpnSubnet=$($script:VpnSubnet)",
        "WgPort=$($script:WgPort)",
        "DnsDefault=$($script:DnsDefault)",
        "UseColor=$(if ($script:UseColor) { '1' } else { '0' })",
        "LogLevel=$($script:LogLevel)",
        "LangUi=$($script:LangUi)"
    )
    Set-Content -Path $script:SettingsFile -Value $lines -Encoding UTF8
}

# ==================== ПАРСИНГ server.conf ====================

function Get-PeerNames {
    if (-not (Test-Path $script:ServerConf)) { return @() }
    $names = @()
    foreach ($line in Get-Content $script:ServerConf) {
        if ($line -match '^# ([A-Za-z0-9_-]+)$') {
            $n = $Matches[1]
            if ($n -notin @('EXPIRES', 'DISABLED')) { $names += $n }
        }
    }
    return $names
}

function Test-PeerExists {
    param([string]$Name)
    return ($Name -in (Get-PeerNames))
}

function Get-PeerBlock {
    param([string]$Name)
    if (-not (Test-Path $script:ServerConf)) { return @() }
    $block = @()
    $inBlock = $false
    foreach ($line in Get-Content $script:ServerConf) {
        if ($line -ceq "# $Name") { $inBlock = $true; $block += $line; continue }
        if ($inBlock) {
            if ($line -match '^# [A-Za-z0-9_-]+$' -and $line -cne "# $Name") { break }
            if ($line -eq '[Interface]') { break }
            $block += $line
        }
    }
    return $block
}

function Get-PeerField {
    param([string]$Name, [string]$Field)
    foreach ($line in (Get-PeerBlock $Name)) {
        $l = $line -replace '^[# ]+', ''
        if ($l -match "^$Field\s*=") {
            return ($l -replace "^[^=]*=\s*", '')
        }
        if ($l -match "^$Field\s+(\d+)$") {
            return $Matches[1]
        }
    }
    return ''
}

function Set-PeerField {
    param([string]$Name, [string]$Field, [string]$Value)
    $lines = Get-Content $script:ServerConf
    $out = New-Object System.Collections.Generic.List[string]
    $inBlock = $false
    foreach ($line in $lines) {
        if ($line -ceq "# $Name") { $inBlock = $true; $out.Add($line); continue }
        if ($inBlock) {
            if ($line -match '^# [A-Za-z0-9_-]+$' -and $line -cne "# $Name") { $inBlock = $false }
            elseif ($line -eq '[Interface]') { $inBlock = $false }
            elseif ($line -match "^[# ]*$Field\s*=") {
                if ($Value -ne '') { $out.Add("$Field = $Value") }
                continue
            }
        }
        $out.Add($line)
    }
    Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
}

function Disable-Peer {
    param([string]$Name)
    $lines = Get-Content $script:ServerConf
    $out = New-Object System.Collections.Generic.List[string]
    $inBlock = $false
    $marked = $false
    foreach ($line in $lines) {
        if ($line -ceq "# $Name") { $inBlock = $true; $out.Add($line); continue }
        if ($inBlock) {
            if ($line -match '^# [A-Za-z0-9_-]+$' -and $line -cne "# $Name") {
                if (-not $marked) { $out.Add('# DISABLED 1'); $marked = $true }
                $inBlock = $false
            } elseif ($line -eq '[Interface]') {
                if (-not $marked) { $out.Add('# DISABLED 1'); $marked = $true }
                $inBlock = $false
            } elseif ($line -eq '[Peer]') {
                $out.Add($line)
                $out.Add('# DISABLED 1')
                $marked = $true
                continue
            } elseif ($line -match '^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)\s*=') {
                $out.Add("# $line")
                continue
            }
        }
        $out.Add($line)
    }
    if ($inBlock -and -not $marked) { $out.Add('# DISABLED 1') }
    Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
    Write-Log -Message (t "Клиент $Name отключён" "Client $Name disabled")
}

function Enable-Peer {
    param([string]$Name)
    $lines = Get-Content $script:ServerConf
    $out = New-Object System.Collections.Generic.List[string]
    $inBlock = $false
    foreach ($line in $lines) {
        if ($line -ceq "# $Name") { $inBlock = $true; $out.Add($line); continue }
        if ($inBlock) {
            if ($line -match '^# [A-Za-z0-9_-]+$' -and $line -cne "# $Name") { $inBlock = $false }
            elseif ($line -eq '[Interface]') { $inBlock = $false }
            elseif ($line -match '^# DISABLED 1') { continue }
            elseif ($line -match '^# (PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)\s*=') {
                $out.Add($line.Substring(2))
                continue
            }
        }
        $out.Add($line)
    }
    Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
    Write-Log -Message (t "Клиент $Name включён" "Client $Name enabled")
}

function Remove-PeerBlock {
    param([string]$Name)
    $lines = Get-Content $script:ServerConf
    $out = New-Object System.Collections.Generic.List[string]
    $inBlock = $false
    foreach ($line in $lines) {
        if ($line -ceq "# $Name") { $inBlock = $true; continue }
        if ($inBlock) {
            if ($line -match '^# [A-Za-z0-9_-]+$' -and $line -cne "# $Name") { $inBlock = $false }
            elseif ($line -eq '[Interface]') { $inBlock = $false }
            else { continue }
        }
        $out.Add($line)
    }
    Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
}

function Add-PeerBlock {
    param([string]$Name, [string]$PubKey, [string]$AllowedIps, [string]$Keepalive = '', [string]$Expires = '0')
    $block = @('', "# $Name", '[Peer]', "PublicKey = $PubKey", "AllowedIPs = $AllowedIps")
    if ($Keepalive -ne '') { $block += "PersistentKeepalive = $Keepalive" }
    if ($Expires -ne '0' -and $Expires -ne '') { $block += "# EXPIRES $Expires" }
    Add-Content -Path $script:ServerConf -Value $block -Encoding UTF8
}

# ---------- expiry.db ----------
function Get-Expiry {
    param([string]$Name)
    if (-not (Test-Path $script:ExpiryDb)) { return '' }
    foreach ($line in Get-Content $script:ExpiryDb) {
        $p = $line.Split(':', 2)
        if ($p.Count -eq 2 -and $p[0] -eq $Name) { return $p[1] }
    }
    return ''
}

function Set-Expiry {
    param([string]$Name, [string]$Ts)
    $rows = @()
    if (Test-Path $script:ExpiryDb) {
        foreach ($line in Get-Content $script:ExpiryDb) {
            $p = $line.Split(':', 2)
            if ($p.Count -eq 2 -and $p[0] -ne $Name) { $rows += $line }
        }
    }
    $rows += "$Name`:$Ts"
    Set-Content -Path $script:ExpiryDb -Value $rows -Encoding UTF8
    # синхронизация комментария в server.conf
    if ((Test-Path $script:ServerConf) -and (Test-PeerExists $Name)) {
        $lines = Get-Content $script:ServerConf
        $out = New-Object System.Collections.Generic.List[string]
        $inBlock = $false
        $hasExpires = $false
        $done = $false
        foreach ($line in $lines) {
            if ($line -ceq "# $Name") { $inBlock = $true; $out.Add($line); continue }
            if ($inBlock) {
                if ($line -match '^# EXPIRES ') {
                    $hasExpires = $true
                    if ($Ts -eq '0') { continue }
                    $out.Add("# EXPIRES $Ts")
                    $done = $true
                    continue
                }
                if ($line -match '^# [A-Za-z0-9_-]+$' -and $line -cne "# $Name") {
                    if (-not $done -and -not $hasExpires -and $Ts -ne '0') {
                        $out.Add("# EXPIRES $Ts")
                        $done = $true
                    }
                    $inBlock = $false
                } elseif ($line -eq '[Interface]') {
                    if (-not $done -and -not $hasExpires -and $Ts -ne '0') {
                        $out.Add("# EXPIRES $Ts")
                        $done = $true
                    }
                    $inBlock = $false
                }
            }
            $out.Add($line)
        }
        if ($inBlock -and -not $done -and $Ts -ne '0') { $out.Add("# EXPIRES $Ts") }
        Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
    }
}

function Test-PeerDisabled {
    param([string]$Name)
    return ((Get-PeerBlock $Name) -contains '# DISABLED 1')
}

function Test-PeerExpired {
    param([string]$Name)
    $ts = Get-Expiry $Name
    if ([string]::IsNullOrWhiteSpace($ts) -or $ts -eq '0') { return $false }
    return ([int64]$ts -lt (Get-UnixNow))
}

# ==================== УСТАНОВКА ====================

function Test-WireGuardInstalled {
    Show-Section (t 'Проверка компонентов' 'Component check')
    $items = @(
        @{ Name = 'wg.exe';          Path = $script:WgExe },
        @{ Name = 'wireguard.exe';   Path = $script:WireguardExe }
    )
    foreach ($i in $items) {
        if (Test-Path $i.Path) {
            Write-Host ("  [OK] {0}  {1}" -f $i.Name, $i.Path)
        } else {
            Write-Host ("  [--] {0}  {1}" -f $i.Name, (t 'не найден' 'not found'))
        }
    }
    $svc = Get-Service -Name 'WireGuard*' -ErrorAction SilentlyContinue
    if ($svc) {
        foreach ($s in $svc) {
            Write-Host ("  [OK] service {0}  {1}" -f $s.Name, $s.Status)
        }
    } else {
        Write-Host ("  [--] {0}" -f (t 'туннель-сервисы не установлены' 'no tunnel services'))
    }
}

function Install-WireGuard {
    Show-Section (t 'Установка WireGuard' 'Installing WireGuard')
    if ((Test-Path $script:WgExe) -and (Test-Path $script:WireguardExe)) {
        Write-Info (t 'WireGuard уже установлен' 'WireGuard is already installed')
        Test-WireGuardInstalled
        return
    }
    Write-Info (t 'Скачиваю установщик WireGuard для Windows...' 'Downloading WireGuard for Windows installer...')
    $tmp = Join-Path $env:TEMP 'wireguard-installer.exe'
    # актуальный x64-установщик
    $url = 'https://download.wireguard.com/windows-client/wireguard-installer.exe'
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    } catch {
        Exit-WithError (t "Не удалось скачать установщик: $($_.Exception.Message)" "Failed to download installer: $($_.Exception.Message)")
    }
    Write-Info (t 'Запускаю установку (тихий режим)...' 'Running silent install...')
    Start-Process -FilePath $tmp -ArgumentList '/quiet' -Wait
    if (Test-Path $script:WgExe) {
        Write-Info (t 'Установка завершена' 'Installation complete')
    } else {
        Write-WarningMsg (t 'Установщик отработал, но wg.exe не найден — установите вручную' 'Installer finished but wg.exe not found — install manually')
    }
    Write-Log -Message 'Install-WireGuard: done'
}

function Update-WireGuard {
    Show-Section (t 'Обновление WireGuard' 'Updating WireGuard')
    Write-Info (t 'Обновление выполняется переустановкой последней версии' 'Update is done by reinstalling the latest version')
    if (Confirm-Action (t 'Скачать и запустить установщик? (y/N): ' 'Download and run installer? (y/N): ')) {
        Install-WireGuard
    }
}

# ==================== ИНИЦИАЛИЗАЦИЯ ====================

function New-ServerKeys {
    if (-not (Test-Path $script:WgDir)) {
        New-Item -ItemType Directory -Path $script:WgDir -Force | Out-Null
    }
    $priv = (& $script:WgExe genkey) | Out-String
    $priv = $priv.Trim()
    if (-not $priv) { Exit-WithError (t 'Не удалось сгенерировать приватный ключ' 'Failed to generate private key') }
    $pub = ($priv | & $script:WgExe pubkey) | Out-String
    $pub = $pub.Trim()
    Set-Content -Path $script:ServerPrivKey -Value $priv -Encoding ASCII -NoNewline
    # ограничить доступ: только Администраторы и SYSTEM
    icacls $script:ServerPrivKey /inheritance:r /grant:r "Administrators:F" "SYSTEM:F" | Out-Null
    Set-Content -Path $script:ServerPubKey -Value $pub -Encoding ASCII
    Write-Log -Message "New-ServerKeys: written to $($script:WgDir)"
}

function Enable-IpForwarding {
    # глобальный форвардинг + NAT через NetNat
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -Value 1 -Type DWord
    try {
        Restart-Service RemoteAccess -Force -ErrorAction SilentlyContinue
    } catch { }
    Write-Log -Message 'Enable-IpForwarding: IPEnableRouter=1'
}

function New-WgNat {
    param([string]$Network)
    # удалить старые правила с тем же именем
    Get-NetNat -Name 'WG-Nat' -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue
    try {
        New-NetNat -Name 'WG-Nat' -InternalIPInterfaceAddressPrefix $Network | Out-Null
        Write-Log -Message "New-WgNat: $Network"
    } catch {
        Write-WarningMsg (t "Не удалось создать NAT: $($_.Exception.Message)" "Failed to create NAT: $($_.Exception.Message)")
    }
}

function New-WgFirewallRule {
    param([string]$Port)
    Get-NetFirewallRule -DisplayName 'wg-admin UDP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'wg-admin UDP' -Direction Inbound -Action Allow -Protocol UDP `
        -LocalPort ([int]$Port) -Profile Any | Out-Null
    Write-Log -Message "New-WgFirewallRule: udp/$Port"
}

# strip-конфиг для wg syncconf: только ключи, значимые для драйвера
function Get-StrippedConfig {
    param([string]$ConfPath)
    $out = New-Object System.Collections.Generic.List[string]
    $section = ''
    foreach ($line in Get-Content $ConfPath) {
        $l = $line.Trim()
        if ($l -eq '[Interface]') { $section = 'iface'; $out.Add($line); continue }
        if ($l -eq '[Peer]')      { $section = 'peer';  $out.Add($line); continue }
        if ($l.StartsWith('['))   { $section = ''; $out.Add($line); continue }
        if ($l.StartsWith('#') -or $l -eq '') {
            # комментарии отбрасываем — они не нужны драйверу, кроме как нам для парсинга
            continue
        }
        if ($section -eq 'iface') {
            if ($l -match '^(ListenPort|PrivateKey|FwMark)\s*=') { $out.Add($line) }
            continue
        }
        # peer-секция целиком
        $out.Add($line)
    }
    return $out
}

function Invoke-ApplyConfig {
    if (-not (Test-Path $script:ServerConf)) {
        Write-WarningMsg (t 'server.conf не найден' 'server.conf not found')
        return $false
    }
    if (-not (Test-Path $script:WgExe)) {
        Write-WarningMsg (t 'wg.exe не найден — конфиг не применён' 'wg.exe not found — config not applied')
        return $false
    }
    # проверка: драйвер поднял интерфейс?
    $iface = Get-NetAdapter -Name $script:WgIf -ErrorAction SilentlyContinue
    if ($iface) {
        $tmp = Join-Path $env:TEMP ("wg-strip-{0}.conf" -f ([guid]::NewGuid().ToString('N')))
        try {
            Get-StrippedConfig -ConfPath $script:ServerConf | Set-Content -Path $tmp -Encoding ASCII
            & $script:WgExe syncconf $script:WgIf $tmp 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Info (t 'Конфиг применён (wg syncconf, без разрыва)' 'Config applied (wg syncconf, no downtime)')
                Write-Log -Message 'Invoke-ApplyConfig: syncconf ok'
                return $true
            }
            Write-WarningMsg (t 'wg syncconf не удался, пересоздаю туннель' 'wg syncconf failed, recreating tunnel')
        } finally {
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
    }
    # (пере)создание туннельного сервиса
    & $script:WireguardExe /uninstalltunnelservice $script:ServerConf 2>&1 | Out-Null
    & $script:WireguardExe /installtunnelservice $script:ServerConf 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Info (t "Туннель $($script:WgIf) запущен" "Tunnel $($script:WgIf) started")
        Write-Log -Message 'Invoke-ApplyConfig: installtunnelservice ok'
        return $true
    }
    Write-WarningMsg (t 'Не удалось применить конфиг' 'Failed to apply config')
    return $false
}

function Initialize-Server {
    Show-Section (t 'Инициализация сервера' 'Server initialization')
    if (Test-Path $script:ServerConf) {
        Write-WarningMsg (t "Конфиг $($script:ServerConf) уже существует" "$($script:ServerConf) already exists")
        if (-not (Confirm-Action (t 'Перезаписать конфигурацию? (y/N): ' 'Overwrite configuration? (y/N): '))) {
            Write-Info (t 'Инициализация отменена' 'Initialization cancelled')
            return
        }
        Copy-Item $script:ServerConf "$($script:ServerConf).bak.$(Get-Date -Format yyyyMMddHHmmss)" -ErrorAction SilentlyContinue
    }

    $defIf = Get-DetectInterface
    $extIf = Read-Value (t 'Внешний интерфейс' 'External interface') $defIf
    if (-not (Test-InterfaceExists $extIf)) {
        Exit-WithError (t "Интерфейс $extIf не найден" "Interface $extIf not found")
    }
    $vpnNet = Read-Value (t 'VPN-подсеть' 'VPN subnet') $script:VpnSubnet
    if (-not (Test-Cidr $vpnNet)) { Exit-WithError (t "Некорректная подсеть: $vpnNet" "Invalid subnet: $vpnNet") }
    $vpnIp = Read-Value (t 'VPN IP сервера' 'Server VPN IP') $script:ServerVpnIp
    if (-not (Test-IpAddress $vpnIp)) { Exit-WithError (t "Некорректный IP: $vpnIp" "Invalid IP: $vpnIp") }
    $port = Read-Value (t 'Порт UDP' 'UDP port') $script:WgPort
    if (-not (Test-Port $port)) { Exit-WithError (t "Некорректный порт: $port" "Invalid port: $port") }
    $dns = Read-Value (t 'DNS' 'DNS') $script:DnsDefault
    if (-not (Test-IpAddress $dns)) { Exit-WithError (t "Некорректный DNS: $dns" "Invalid DNS: $dns") }
    $mtu = Read-Value (t 'MTU (пусто = авто)' 'MTU (empty = auto)') $script:MtuDefault

    if (-not (Test-Path $script:ClientsDir)) {
        New-Item -ItemType Directory -Path $script:ClientsDir -Force | Out-Null
    }
    New-ServerKeys
    $priv = (Get-Content $script:ServerPrivKey -Raw).Trim()

    $lines = @(
        "# wg-admin.ps1 v$($script:AppVersion)",
        "# Создан: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "# Внешний интерфейс: $extIf",
        '',
        '[Interface]',
        "Address = $vpnIp/32",
        "ListenPort = $port",
        "PrivateKey = $priv",
        'SaveConfig = false'
    )
    if ($mtu -ne '') { $lines += "MTU = $mtu" }
    Set-Content -Path $script:ServerConf -Value $lines -Encoding ASCII

    Enable-IpForwarding
    $net = Get-VpnNetwork $vpnNet
    New-WgNat -Network $net
    New-WgFirewallRule -Port $port

    Invoke-ApplyConfig | Out-Null

    $script:VpnSubnet = $vpnNet
    $script:WgPort = $port
    $script:DnsDefault = $dns
    $script:ServerVpnIp = $vpnIp
    Save-Settings

    $pub = (Get-Content $script:ServerPubKey -Raw).Trim()
    Write-Info (t 'Сервер инициализирован' 'Server initialized')
    Write-Info (t "Публичный ключ: $pub" "Public key: $pub")
    $extIp = Get-ExternalIp
    if ($extIp) {
        Write-Info (t "Внешний адрес: ${extIp}:$port" "External endpoint: ${extIp}:$port")
    }
    Write-Log -Message "Initialize-Server: iface=$extIf net=$vpnNet port=$port"
}

# ==================== УПРАВЛЕНИЕ КЛИЕНТАМИ ====================

function New-ClientKeys {
    $priv = ((& $script:WgExe genkey) | Out-String).Trim()
    $pub  = (($priv | & $script:WgExe pubkey) | Out-String).Trim()
    return @{ Priv = $priv; Pub = $pub }
}

function New-ClientConfig {
    param([string]$Name, [string]$ClientPriv, [string]$ServerPub, [string]$Endpoint,
          [string]$ClientIp, [string]$Allowed, [string]$Dns, [string]$Keepalive, [string]$Mtu)
    if (-not (Test-Path $script:ClientsDir)) {
        New-Item -ItemType Directory -Path $script:ClientsDir -Force | Out-Null
    }
    $path = Join-Path $script:ClientsDir "$Name.conf"
    $lines = @(
        "# wg-admin.ps1 client: $Name",
        "# Создан: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        '',
        '[Interface]',
        "PrivateKey = $ClientPriv",
        "Address = $ClientIp/32"
    )
    if ($Dns -ne '')  { $lines += "DNS = $Dns" }
    if ($Mtu -ne '')  { $lines += "MTU = $Mtu" }
    $lines += @(
        '',
        '[Peer]',
        "PublicKey = $ServerPub",
        "AllowedIPs = $Allowed",
        "Endpoint = $Endpoint"
    )
    if ($Keepalive -ne '') { $lines += "PersistentKeepalive = $Keepalive" }
    Set-Content -Path $path -Value $lines -Encoding ASCII
    icacls $path /inheritance:r /grant:r "Administrators:F" "SYSTEM:F" | Out-Null
    return $path
}

function Get-NextFreeIp {
    $parts = $script:VpnSubnet.Split('/')
    $oct = $parts[0].Split('.') | ForEach-Object { [int]$_ }
    $prefix = [int]$parts[1]
    $n = ($oct[0] -shl 24) -bor ($oct[1] -shl 16) -bor ($oct[2] -shl 8) -bor $oct[3]
    if ($prefix -eq 0) { $mask = 0 } else { $mask = (-bnot ((1 -shl (32 - $prefix)) - 1)) -band 0xFFFFFFFF }
    $n = $n -band $mask
    $used = @()
    if (Test-Path $script:ServerConf) {
        $used += (Select-String -Path $script:ServerConf -Pattern '(\d{1,3}\.){3}\d{1,3}' -AllMatches).Matches.Value
    }
    if (Test-Path $script:ClientsDir) {
        Get-ChildItem $script:ClientsDir -Filter *.conf -ErrorAction SilentlyContinue | ForEach-Object {
            $used += (Select-String -Path $_.FullName -Pattern 'Address = ((\d{1,3}\.){3}\d{1,3})' -AllMatches).Matches |
                ForEach-Object { $_.Groups[1].Value }
        }
    }
    for ($i = 2; $i -lt 254; $i++) {
        $a = ($n -shr 24) -band 255; $b = ($n -shr 16) -band 255
        $c = ($n -shr 8) -band 255; $d = $i
        $cand = "$a.$b.$c.$d"
        if ($cand -eq $script:ServerVpnIp) { continue }
        if ($used -notcontains $cand) { return $cand }
    }
    return ''
}

function Add-Client {
    Show-Section (t 'Добавление клиента' 'Add client')
    if (-not (Test-Path $script:ServerConf)) {
        Exit-WithError (t 'Сначала выполните инициализацию сервера (пункт 2)' 'Initialize the server first (menu 2)')
    }

    while ($true) {
        $name = Read-Value (t 'Имя клиента (pc1, laptop-ivan, ...)' 'Client name (pc1, laptop-ivan, ...)') ''
        if (Test-ClientName $name) {
            if (Test-PeerExists $name) {
                Write-WarningMsg (t "Клиент $name уже существует" "Client $name already exists")
                continue
            }
            if (Test-Path (Join-Path $script:ClientsDir "$name.conf")) {
                Write-WarningMsg (t "Файл $name.conf уже есть" "$name.conf already exists")
                continue
            }
            break
        }
        Write-WarningMsg (t 'Недопустимое имя (разрешены буквы, цифры, _ и -)' 'Invalid name (letters, digits, _ and - allowed)')
    }

    $defIp = Get-NextFreeIp
    while ($true) {
        $clientIp = Read-Value (t 'VPN IP клиента' 'Client VPN IP') $defIp
        if (-not (Test-IpAddress $clientIp)) { Write-WarningMsg (t 'Некорректный IP' 'Invalid IP'); continue }
        if ($clientIp -eq $script:ServerVpnIp) {
            Write-WarningMsg (t 'IP сервера занят — выберите другой' 'Server IP is taken — choose another')
            continue
        }
        if ((Select-String -Path $script:ServerConf -Pattern "AllowedIPs = $clientIp/32" -Quiet)) {
            Write-WarningMsg (t "IP $clientIp уже назначен другому пиру" "IP $clientIp is already assigned")
            continue
        }
        break
    }

    $pubKey = Read-Value (t 'Публичный ключ (пусто = сгенерировать)' 'Public key (empty = generate)') ''
    $clientPriv = ''
    if ($pubKey -eq '') {
        $keys = New-ClientKeys
        $clientPriv = $keys.Priv
        $pubKey = $keys.Pub
    } elseif ($pubKey -notmatch '^[A-Za-z0-9+/]{42,44}=$') {
        Exit-WithError (t 'Некорректный публичный ключ' 'Invalid public key')
    }

    $defExt = Get-ExternalIp
    $extAddr = Read-Value (t 'Внешний адрес сервера' 'Server external address') $defExt
    $port = Read-Value (t 'Порт сервера' 'Server port') $script:WgPort
    if (-not (Test-Port $port)) { Exit-WithError (t "Некорректный порт: $port" "Invalid port: $port") }

    Write-Host (t 'Режим маршрутизации:' 'Routing mode:')
    $vpnLabel = t "Только VPN-сеть ($($script:VpnSubnet))" "VPN network only ($($script:VpnSubnet))"
    $defLabel = t 'по умолчанию' 'default'
    Write-Host "  1) $vpnLabel  -> $defLabel"
    Write-Host "  2) $(t 'Весь трафик через VPN (0.0.0.0/0)' 'All traffic via VPN (0.0.0.0/0)')"
    Write-Host "  3) $(t 'VPN + указанные подсети' 'VPN + specified subnets')"
    Write-Host "  4) $(t 'Свой вариант (CIDR вручную)' 'Custom (manual CIDR)')"
    $mode = Read-Value (t 'Выбор' 'Choice') '1'
    $allowed = $script:VpnSubnet
    switch ($mode) {
        '2' { $allowed = '0.0.0.0/0' }
        '3' {
            $extra = Read-Value (t 'Дополнительные подсети через запятую' 'Extra subnets, comma-separated') ''
            $list = @($script:VpnSubnet)
            foreach ($s in ($extra -split ',')) {
                $s = $s.Trim()
                if ($s -eq '') { continue }
                if (-not (Test-Cidr $s)) { Exit-WithError (t "Некорректный CIDR: $s" "Invalid CIDR: $s") }
                $list += $s
            }
            $allowed = $list -join ', '
        }
        '4' {
            $allowed = Read-Value (t 'AllowedIPs (CIDR через запятую)' 'AllowedIPs (comma-separated CIDR)') $script:VpnSubnet
        }
    }

    $dns = Read-Value (t 'DNS' 'DNS') $script:DnsDefault
    $ka = Read-Value (t 'PersistentKeepalive' 'PersistentKeepalive') $script:ClientKeepalive
    if ($ka -notmatch '^\d+$') { $ka = $script:ClientKeepalive }
    $mtu = Read-Value (t 'MTU (пусто = авто)' 'MTU (empty = auto)') ''
    $expStr = Read-Value (t 'Срок действия (30d / 12h / never / YYYY-MM-DD)' 'Expiry (30d / 12h / never / YYYY-MM-DD)') 'never'
    $expTs = ConvertFrom-Duration $expStr
    if ($null -eq $expTs) { Exit-WithError (t "Не удалось разобрать срок: $expStr" "Cannot parse expiry: $expStr") }
    $comment = Read-Value (t 'Комментарий (описание)' 'Comment (description)') ''
    $wantQr = Read-YesNo (t 'Показать QR-код?' 'Show QR code?')

    $serverPub = (Get-Content $script:ServerPubKey -Raw).Trim()
    $endpoint = "${extAddr}:$port"

    $confPath = ''
    if ($clientPriv -ne '') {
        $confPath = New-ClientConfig -Name $name -ClientPriv $clientPriv -ServerPub $serverPub `
            -Endpoint $endpoint -ClientIp $clientIp -Allowed $allowed -Dns $dns `
            -Keepalive $ka -Mtu $mtu
        Write-Info (t "Файл клиента: $confPath" "Client config: $confPath")
    } else {
        Write-WarningMsg (t 'Приватный ключ не сгенерирован — конфиг клиента не сохранён (импорт ключа)' 'No private key generated — client config not saved (key import)')
    }

    Add-PeerBlock -Name $name -PubKey $pubKey -AllowedIps "$clientIp/32" -Keepalive $ka -Expires "$expTs"
    if ($comment -ne '') {
        $lines = Get-Content $script:ServerConf
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($line in $lines) {
            $out.Add($line)
            if ($line -ceq "# $name") { $out.Add("# COMMENT $comment") }
        }
        Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
    }
    Set-Expiry -Name $name -Ts "$expTs"
    Invoke-ApplyConfig | Out-Null

    Write-Info (t "Создан клиент: $name ($clientIp/32)" "Client created: $name ($clientIp/32)")
    if ("$expTs" -ne '0') {
        Write-Info (t "Срок действия: $(Format-Ts "$expTs")" "Expires: $(Format-Ts "$expTs")")
    }
    if ($wantQr -and $confPath -and (Test-Path $confPath)) {
        $qrencode = Get-Command qrencode -ErrorAction SilentlyContinue
        if ($qrencode) {
            Get-Content $confPath -Raw | & $qrencode -t ansiutf8
        } else {
            Write-WarningMsg (t 'qrencode не найден — QR недоступен (установите или используйте мобильное приложение)' 'qrencode not found — QR unavailable (install it or use a mobile app)')
        }
    }
    Write-Log -Message "Add-Client: name=$name ip=$clientIp expires=$expTs"
}

function Get-ClientList {
    Show-Section (t 'Список клиентов' 'Client list')
    if (-not (Test-Path $script:ServerConf)) {
        Write-WarningMsg (t 'Конфиг сервера не найден' 'Server config not found')
        return
    }
    Write-Host (t 'Фильтр: 1) все  2) активные  3) отключённые  4) истёкшие' 'Filter: 1) all  2) active  3) disabled  4) expired')
    $flt = Read-Value (t 'Выбор' 'Choice') '1'
    $rows = @()
    foreach ($name in (Get-PeerNames)) {
        $ip = (Get-PeerField $name 'AllowedIPs') -replace '/32$', ''
        $exp = Get-Expiry $name
        if ($exp -eq '') { $exp = Get-PeerField $name 'EXPIRES' }
        $comment = ''
        foreach ($line in (Get-PeerBlock $name)) {
            if ($line -match '^# COMMENT (.+)$') { $comment = $Matches[1]; break }
        }
        $status = 'active'
        if (Test-PeerDisabled $name) { $status = 'disabled' }
        elseif (Test-PeerExpired $name) { $status = 'expired' }
        switch ($flt) {
            '2' { if ($status -ne 'active') { continue } }
            '3' { if ($status -ne 'disabled') { continue } }
            '4' { if ($status -ne 'expired') { continue } }
        }
        $rows += [pscustomobject]@{
            Name = $name; Ip = $ip; Status = $status
            Expires = (Format-Ts $exp); Comment = $comment; RawExpires = $exp
        }
    }
    Write-Host ('{0,-18} {1,-16} {2,-12} {3,-18} {4}' -f
        (t 'Имя' 'Name'), (t 'IP' 'IP'), (t 'Статус' 'Status'), (t 'Срок' 'Expires'), (t 'Комментарий' 'Comment'))
    Write-Host ('-' * 70)
    foreach ($r in $rows) {
        Write-Host ('{0,-18} {1,-16} {2,-12} {3,-18} {4}' -f $r.Name, $r.Ip, $r.Status, $r.Expires, $r.Comment)
    }
    Write-Host ('-' * 70)
    Write-Info (t "Всего: $($rows.Count)" "Total: $($rows.Count)")
    if (Read-YesNo (t 'Экспортировать в CSV?' 'Export to CSV?')) {
        $out = Read-Value (t 'Файл для экспорта' 'Export file') '.\wg-clients.csv'
        $rows | Select-Object Name, Ip, Status, RawExpires, Comment |
            Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
        Write-Info (t "CSV: $out" "CSV: $out")
    }
}

function Edit-Client {
    Show-Section (t 'Редактирование клиента' 'Edit client')
    $name = Read-Value (t 'Имя клиента' 'Client name') ''
    if (-not (Test-ClientName $name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
    if (-not (Test-PeerExists $name)) { Exit-WithError (t "Клиент $name не найден" "Client $name not found") }

    $curIp = Get-PeerField $name 'AllowedIPs'
    $curPub = Get-PeerField $name 'PublicKey'
    $curKa = Get-PeerField $name 'PersistentKeepalive'
    $curExp = Get-Expiry $name
    $curComment = ''
    foreach ($line in (Get-PeerBlock $name)) {
        if ($line -match '^# COMMENT (.+)$') { $comment = $Matches[1]; $curComment = $comment; break }
    }

    Write-Info (t "Текущие данные ${name}:" "Current data ${name}:")
    Write-Host "  IP/AllowedIPs: $curIp"
    Write-Host "  PublicKey:     $curPub"
    Write-Host "  Keepalive:     $curKa"
    Write-Host "  Expires:       $(Format-Ts $curExp)"
    Write-Host "  Comment:       $curComment"
    Write-Host ''
    Write-Host "  1) $(t 'Изменить IP' 'Change IP')"
    Write-Host "  2) $(t 'Изменить публичный ключ' 'Change public key')"
    Write-Host "  3) $(t 'Изменить PersistentKeepalive' 'Change PersistentKeepalive')"
    Write-Host "  4) $(t 'Изменить срок действия' 'Change expiry')"
    Write-Host "  5) $(t 'Изменить комментарий' 'Change comment')"
    Write-Host "  6) $(t 'Перегенерировать ключи клиента' 'Regenerate client keys')"
    Write-Host "  7) $(t 'Назад' 'Back')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    switch ($ch) {
        '1' {
            $newIp = Read-Value (t 'Новый VPN IP' 'New VPN IP') ($curIp -replace '/32$', '')
            if (-not (Test-IpAddress $newIp)) { Exit-WithError (t 'Некорректный IP' 'Invalid IP') }
            Set-PeerField -Name $name -Field 'AllowedIPs' -Value "$newIp/32"
            $cpath = Join-Path $script:ClientsDir "$name.conf"
            if (Test-Path $cpath) {
                (Get-Content $cpath) -replace '^Address = .*', "Address = $newIp/32" |
                    Set-Content $cpath -Encoding ASCII
            }
            Write-Info (t "IP обновлён: $newIp" "IP updated: $newIp")
        }
        '2' {
            $newPub = Read-Value (t 'Новый публичный ключ' 'New public key') ''
            if ($newPub -notmatch '^[A-Za-z0-9+/]{42,44}=$') { Exit-WithError (t 'Некорректный ключ' 'Invalid key') }
            Set-PeerField -Name $name -Field 'PublicKey' -Value $newPub
            Write-Info (t 'Ключ обновлён' 'Key updated')
        }
        '3' {
            $newKa = Read-Value (t 'PersistentKeepalive (пусто = убрать)' 'PersistentKeepalive (empty = remove)') $curKa
            Set-PeerField -Name $name -Field 'PersistentKeepalive' -Value $newKa
            Write-Info (t 'Keepalive обновлён' 'Keepalive updated')
        }
        '4' { Set-ClientExpiry -Name $name }
        '5' {
            $newC = Read-Value (t 'Комментарий' 'Comment') $curComment
            $lines = Get-Content $script:ServerConf
            $out = New-Object System.Collections.Generic.List[string]
            $inBlock = $false
            $done = $false
            foreach ($line in $lines) {
                if ($line -ceq "# $name") { $inBlock = $true; $out.Add($line); continue }
                if ($inBlock) {
                    if ($line -match '^# COMMENT ') {
                        if (-not $done) {
                            if ($newC -ne '') { $out.Add("# COMMENT $newC") }
                            $done = $true
                        }
                        continue
                    }
                    if ($line -match '^# [A-Za-z0-9_-]+$' -and $line -cne "# $name") {
                        if (-not $done -and $newC -ne '') { $out.Add("# COMMENT $newC"); $done = $true }
                        $inBlock = $false
                    } elseif ($line -eq '[Interface]') {
                        if (-not $done -and $newC -ne '') { $out.Add("# COMMENT $newC"); $done = $true }
                        $inBlock = $false
                    }
                }
                $out.Add($line)
            }
            Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
            Write-Info (t 'Комментарий обновлён' 'Comment updated')
        }
        '6' {
            $keys = New-ClientKeys
            Set-PeerField -Name $name -Field 'PublicKey' -Value $keys.Pub
            $cpath = Join-Path $script:ClientsDir "$name.conf"
            if (Test-Path $cpath) {
                (Get-Content $cpath) -replace '^PrivateKey = .*', "PrivateKey = $($keys.Priv)" |
                    Set-Content $cpath -Encoding ASCII
            } else {
                Write-WarningMsg (t 'Файл конфига клиента не найден — создайте его заново' 'Client config file not found — recreate it')
            }
            Write-Info (t 'Ключи клиента перегенерированы' 'Client keys regenerated')
        }
    }
    Invoke-ApplyConfig | Out-Null
}

function Remove-Client {
    Show-Section (t 'Удаление клиента' 'Remove client')
    Write-Host "  1) $(t 'Один клиент' 'Single client')"
    Write-Host "  2) $(t 'Несколько клиентов (через пробел)' 'Several clients (space-separated)')"
    Write-Host "  3) $(t 'Все неактивные (отключённые/истёкшие)' 'All inactive (disabled/expired)')"
    Write-Host "  4) $(t 'Назад' 'Back')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    $toRemove = @()
    switch ($ch) {
        '1' {
            $name = Read-Value (t 'Имя клиента' 'Client name') ''
            if (-not (Test-ClientName $name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
            if (-not (Test-PeerExists $name)) { Exit-WithError (t "Клиент $name не найден" "Client $name not found") }
            $toRemove = @($name)
        }
        '2' {
            $names = Read-Value (t 'Имена через пробел' 'Names, space-separated') ''
            foreach ($n in ($names -split '\s+')) {
                if ($n -eq '') { continue }
                if (Test-PeerExists $n) { $toRemove += $n }
                else { Write-WarningMsg (t "Пропуск: $n не найден" "Skip: $n not found") }
            }
        }
        '3' {
            foreach ($n in (Get-PeerNames)) {
                if ((Test-PeerDisabled $n) -or (Test-PeerExpired $n)) { $toRemove += $n }
            }
        }
        default { return }
    }
    if ($toRemove.Count -eq 0) {
        Write-Info (t 'Нечего удалять' 'Nothing to remove')
        return
    }
    Write-Info (t "Будут удалены: $($toRemove -join ', ')" "Will remove: $($toRemove -join ', ')")
    if (-not (Confirm-Action (t 'Удалить? (y/N): ' 'Delete? (y/N): '))) {
        Write-Info (t 'Отмена' 'Cancelled')
        return
    }
    foreach ($name in $toRemove) {
        Remove-PeerBlock $name
        $cpath = Join-Path $script:ClientsDir "$name.conf"
        if (Test-Path $cpath) { Remove-Item $cpath -Force }
        if (Test-Path $script:ExpiryDb) {
            Get-Content $script:ExpiryDb | Where-Object { $_.Split(':', 2)[0] -ne $name } |
                Set-Content $script:ExpiryDb -Encoding UTF8
        }
        Write-Info (t "Удалён: $name" "Removed: $name")
        Write-Log -Message "Remove-Client: $name"
    }
    Invoke-ApplyConfig | Out-Null
}

function Toggle-Client {
    Show-Section (t 'Отключить / включить клиента' 'Disable / enable client')
    $name = Read-Value (t 'Имя клиента' 'Client name') ''
    if (-not (Test-ClientName $name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
    if (-not (Test-PeerExists $name)) { Exit-WithError (t "Клиент $name не найден" "Client $name not found") }
    if (Test-PeerDisabled $name) {
        Enable-Peer $name
        Write-Info (t "Клиент $name включён" "Client $name enabled")
    } else {
        Disable-Peer $name
        Write-Info (t "Клиент $name отключён" "Client $name disabled")
    }
    Invoke-ApplyConfig | Out-Null
}

function Show-ClientConfig {
    Show-Section (t 'Конфиг клиента' 'Client config')
    $name = Read-Value (t 'Имя клиента' 'Client name') ''
    if (-not (Test-ClientName $name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
    $conf = Join-Path $script:ClientsDir "$name.conf"
    if (-not (Test-Path $conf)) {
        Write-WarningMsg (t "Файл $conf не найден" "$conf not found")
        return
    }
    Write-Host "  1) $(t 'Показать в терминале' 'Print to terminal')"
    Write-Host "  2) $(t 'Показать QR-код' 'Show QR code')"
    Write-Host "  3) $(t 'Сохранить в файл' 'Save to file')"
    Write-Host "  4) $(t 'Назад' 'Back')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    switch ($ch) {
        '1' { Get-Content $conf | Write-Host }
        '2' {
            $qrencode = Get-Command qrencode -ErrorAction SilentlyContinue
            if ($qrencode) { Get-Content $conf -Raw | & $qrencode -t ansiutf8 }
            else { Write-WarningMsg (t 'qrencode не найден' 'qrencode is not found') }
        }
        '3' {
            $out = Read-Value (t 'Куда сохранить' 'Save as') ".\$name.conf"
            Copy-Item $conf $out -Force
            Write-Info (t "Сохранено: $out" "Saved: $out")
        }
    }
}

# ==================== СРОК ДЕЙСТВИЯ ====================

function Set-ClientExpiry {
    param([string]$Name = '')
    if ($Name -eq '') {
        Show-Section (t 'Установить срок действия' 'Set expiry')
        $Name = Read-Value (t 'Имя клиента' 'Client name') ''
        if (-not (Test-ClientName $Name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
    }
    if (-not (Test-PeerExists $Name)) { Exit-WithError (t "Клиент $Name не найден" "Client $Name not found") }
    $cur = Get-Expiry $Name
    Write-Info (t "Текущий срок: $(Format-Ts $cur)" "Current expiry: $(Format-Ts $cur)")
    $s = Read-Value (t 'Новый срок (30d / 12h / never / YYYY-MM-DD)' 'New expiry (30d / 12h / never / YYYY-MM-DD)') 'never'
    $ts = ConvertFrom-Duration $s
    if ($null -eq $ts) { Exit-WithError (t "Не удалось разобрать: $s" "Cannot parse: $s") }
    Set-Expiry -Name $Name -Ts "$ts"
    if ("$ts" -eq '0') {
        Write-Info (t 'Срок сброшен (бессрочно)' 'Expiry reset (never)')
        if (Test-PeerDisabled $Name) { Enable-Peer $Name }
    } else {
        Write-Info (t "Срок установлен: $(Format-Ts "$ts")" "Expiry set: $(Format-Ts "$ts")")
    }
    Invoke-ApplyConfig | Out-Null
    Write-Log -Message "Set-ClientExpiry: $Name -> $ts"
}

function Extend-ClientExpiry {
    Show-Section (t 'Продление срока' 'Extend expiry')
    $name = Read-Value (t 'Имя клиента' 'Client name') ''
    if (-not (Test-ClientName $name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
    if (-not (Test-PeerExists $name)) { Exit-WithError (t "Клиент $name не найден" "Client $name not found") }
    $days = Read-Value (t 'На сколько дней продлить' 'Extend by (days)') '30'
    if ($days -notmatch '^\d+$') { Exit-WithError (t "Некорректное число дней: $days" "Invalid days: $days") }
    $cur = Get-Expiry $name
    $now = Get-UnixNow
    $base = $now
    if (-not [string]::IsNullOrWhiteSpace($cur) -and $cur -ne '0' -and [int64]$cur -gt $now) {
        $base = [int64]$cur
    }
    $ts = $base + ([int]$days * 86400)
    Set-Expiry -Name $name -Ts "$ts"
    if (Test-PeerDisabled $name) {
        Enable-Peer $name
        Write-Info (t "Клиент $name включён (срок продлён)" "Client $name enabled (expiry extended)")
    }
    Write-Info (t "Новый срок: $(Format-Ts "$ts")" "New expiry: $(Format-Ts "$ts")")
    Invoke-ApplyConfig | Out-Null
    Write-Log -Message "Extend-ClientExpiry: $name +$days d -> $ts"
}

function Reset-ClientExpiry {
    Show-Section (t 'Сброс срока (бессрочно)' 'Reset expiry (never)')
    $name = Read-Value (t 'Имя клиента' 'Client name') ''
    if (-not (Test-ClientName $name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
    if (-not (Test-PeerExists $name)) { Exit-WithError (t "Клиент $name не найден" "Client $name not found") }
    Set-Expiry -Name $name -Ts '0'
    if (Test-PeerDisabled $name) { Enable-Peer $name }
    Write-Info (t "Клиент ${name}: бессрочно" "Client ${name}: never expires")
    Invoke-ApplyConfig | Out-Null
}

function Show-Expiring {
    Show-Section (t 'Сроки действия' 'Expirations')
    Write-Host "  1) $(t 'Истекающие в ближайшие N дней' 'Expiring within N days')"
    Write-Host "  2) $(t 'Уже истёкшие' 'Already expired')"
    Write-Host "  3) $(t 'Все со сроком' 'All with expiry')"
    $ch = Read-Value (t 'Выбор' 'Choice') '1'
    $days = 0
    if ($ch -eq '1') {
        $d = Read-Value (t 'Сколько дней вперёд' 'Days ahead') '7'
        if ($d -match '^\d+$') { $days = [int]$d }
    }
    $now = Get-UnixNow
    $found = 0
    foreach ($name in (Get-PeerNames)) {
        $ts = Get-Expiry $name
        if ([string]::IsNullOrWhiteSpace($ts) -or $ts -eq '0') { continue }
        switch ($ch) {
            '1' { if ([int64]$ts -lt $now -or [int64]$ts -gt $now + $days * 86400) { continue } }
            '2' { if ([int64]$ts -ge $now) { continue } }
        }
        Write-Host ('  {0,-18} {1}' -f $name, (Format-Ts $ts))
        $found++
    }
    if ($found -eq 0) { Write-Info (t 'Ничего не найдено' 'Nothing found') }
    else { Write-Info (t "Записей: $found" "Entries: $found") }
}

function Install-ExpiryCheck {
    Show-Section (t 'Автопроверка сроков' 'Expiry auto-check')
    Write-Host "  1) $(t 'Планировщик задач каждые 5 минут' 'Task Scheduler every 5 minutes')"
    Write-Host "  2) $(t 'Отключить автопроверку' 'Disable auto-check')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    $taskName = 'wg-admin-expire-check'
    if ($ch -eq '2') {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        if (Test-Path $script:ExpireCheckPs1) { Remove-Item $script:ExpireCheckPs1 -Force }
        Write-Info (t 'Автопроверка отключена' 'Auto-check disabled')
        return
    }
    if ($ch -ne '1') { return }
    $body = @'
# wg-expire-check.ps1 — автодействия по истечении срока клиентов wg-admin.ps1
$WgDir = 'C:\ProgramData\wg-admin'
$ServerConf = Join-Path $WgDir 'server.conf'
$ExpiryDb = Join-Path $WgDir 'expiry.db'
$LogFile = Join-Path $WgDir 'logs\wg-admin.log'
$WgExe = 'C:\Program Files\WireGuard\wg.exe'
$WireguardExe = 'C:\Program Files\WireGuard\wireguard.exe'
if (-not (Test-Path $ExpiryDb) -or -not (Test-Path $ServerConf)) { exit 0 }
$now = [int64][double]::Parse((Get-Date -UFormat %s))
foreach ($line in Get-Content $ExpiryDb) {
    $p = $line.Split(':', 2)
    if ($p.Count -ne 2) { continue }
    $name = $p[0]; $ts = $p[1]
    if ($ts -eq '0' -or [int64]$ts -ge $now) { continue }
    $lines = Get-Content $ServerConf
    $out = New-Object System.Collections.Generic.List[string]
    $inBlock = $false
    $already = $false
    $marked = $false
    foreach ($l in $lines) {
        if ($l -ceq "# $name") { $inBlock = $true; $out.Add($l); continue }
        if ($inBlock) {
            if ($l -match '^# DISABLED 1') { $already = $true }
            if ($l -match '^# [A-Za-z0-9_-]+$' -and $l -cne "# $name") {
                if (-not $marked -and -not $already) { $out.Add('# DISABLED 1'); $marked = $true }
                $inBlock = $false
            } elseif ($l -eq '[Interface]') {
                if (-not $marked -and -not $already) { $out.Add('# DISABLED 1'); $marked = $true }
                $inBlock = $false
            } elseif ($l -eq '[Peer]') {
                $out.Add($l)
                if (-not $already) { $out.Add('# DISABLED 1'); $marked = $true }
                continue
            } elseif ($l -match '^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)\s*=') {
                if (-not $already) { $out.Add("# $l") ; continue }
            }
        }
        $out.Add($l)
    }
    if (-not $already) {
        Set-Content -Path $ServerConf -Value $out -Encoding UTF8
        $tmp = Join-Path $env:TEMP 'wg-expire-strip.conf'
        # syncconf если интерфейс жив
        if (Get-NetAdapter -Name 'wg0' -ErrorAction SilentlyContinue) {
            $stripped = @()
            $sec = ''
            foreach ($l in Get-Content $ServerConf) {
                $t = $l.Trim()
                if ($t -eq '[Interface]') { $sec = 'iface'; $stripped += $l; continue }
                if ($t -eq '[Peer]') { $sec = 'peer'; $stripped += $l; continue }
                if ($t.StartsWith('#') -or $t -eq '') { continue }
                if ($sec -eq 'iface') {
                    if ($t -match '^(ListenPort|PrivateKey|FwMark)\s*=') { $stripped += $l }
                } else { $stripped += $l }
            }
            $stripped | Set-Content $tmp -Encoding ASCII
            & $WgExe syncconf wg0 $tmp 2>&1 | Out-Null
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
        Add-Content -Path $LogFile -Value ("[{0}] [INFO] expire-check: disabled {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $name) -Encoding UTF8
    }
}
'@
    Set-Content -Path $script:ExpireCheckPs1 -Value $body -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($script:ExpireCheckPs1)`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Force | Out-Null
    Write-Info (t 'Планировщик задач настроен (каждые 5 минут)' 'Task Scheduler job installed (every 5 minutes)')
    Write-Log -Message 'Install-ExpiryCheck: registered'
}

# ==================== МОНИТОРИНГ ====================

function Show-WgStatus {
    Show-Section (t 'wg show / статус пиров' 'wg show / peer status')
    if (-not (Get-NetAdapter -Name $script:WgIf -ErrorAction SilentlyContinue)) {
        Write-WarningMsg (t "Интерфейс $($script:WgIf) не поднят" "Interface $($script:WgIf) is down")
        return
    }
    & $script:WgExe show $script:WgIf
    Write-Host ''
    $now = Get-UnixNow
    $active = 0; $silent = 0; $lost = 0
    Write-Host (t 'Сводка пиров:' 'Peer summary:')
    $hs = @{}
    try {
        $raw = & $script:WgExe show $script:WgIf latest-handshakes 2>$null
        foreach ($line in $raw) {
            $p = $line -split '\s+'
            if ($p.Count -ge 2) { $hs[$p[0]] = [int64]$p[1] }
        }
    } catch { }
    foreach ($name in (Get-PeerNames)) {
        if (Test-PeerDisabled $name) { continue }
        $pub = Get-PeerField $name 'PublicKey'
        if ($pub -eq '') { continue }
        $ts = 0
        if ($hs.ContainsKey($pub)) { $ts = $hs[$pub] }
        if ($ts -eq 0) {
            Write-Host ('  {0,-18} {1}' -f $name, (t 'нет рукопожатия (молчит)' 'no handshake (silent)'))
            $silent++
        } else {
            $last = $now - $ts
            if ($last -lt 300) {
                Write-Host ('  {0,-18} {1} {2}' -f $name, (t 'активен' 'active'), (t "последний контакт ${last}s назад" "last seen ${last}s ago"))
                $active++
            } elseif ($last -lt 1800) {
                Write-Host ('  {0,-18} {1} {2}' -f $name, (t 'молчит' 'silent'), (t "последний контакт ${last}s назад" "last seen ${last}s ago"))
                $silent++
            } else {
                Write-Host ('  {0,-18} {1} {2}' -f $name, (t 'потерян' 'lost'), (t "последний контакт ${last}s назад" "last seen ${last}s ago"))
                $lost++
            }
        }
    }
    Write-Host ('-' * 40)
    Write-Host ('{0}: {1}  {2}: {3}  {4}: {5}' -f
        (t 'активные' 'active'), $active,
        (t 'молчащие' 'silent'), $silent,
        (t 'потерянные' 'lost'), $lost)
}

function Show-Traffic {
    Show-Section (t 'Трафик по клиентам' 'Traffic per client')
    if (-not (Get-NetAdapter -Name $script:WgIf -ErrorAction SilentlyContinue)) {
        Write-WarningMsg (t "Интерфейс $($script:WgIf) не поднят" "Interface $($script:WgIf) is down")
        return
    }
    Write-Host (t 'Сортировка: 1) по имени  2) по rx  3) по tx' 'Sort: 1) name  2) rx  3) tx')
    $sort = Read-Value (t 'Выбор' 'Choice') '1'
    $tx = @{}
    try {
        $raw = & $script:WgExe show $script:WgIf transfer 2>$null
        foreach ($line in $raw) {
            $p = $line -split '\s+'
            if ($p.Count -ge 3) {
                $tx[$p[0]] = @{ Rx = [int64]$p[1]; Tx = [int64]$p[2] }
            }
        }
    } catch { }
    $rows = @()
    foreach ($name in (Get-PeerNames)) {
        $pub = Get-PeerField $name 'PublicKey'
        $rx = 0; $t = 0
        if ($pub -ne '' -and $tx.ContainsKey($pub)) {
            $rx = $tx[$pub].Rx; $t = $tx[$pub].Tx
        }
        $rows += [pscustomobject]@{ Name = $name; Rx = $rx; Tx = $t }
    }
    switch ($sort) {
        '2' { $rows = $rows | Sort-Object Rx -Descending }
        '3' { $rows = $rows | Sort-Object Tx -Descending }
        default { $rows = $rows | Sort-Object Name }
    }
    foreach ($r in $rows) {
        Write-Host ('  {0,-18} rx={1,12}  tx={2,12}' -f $r.Name,
            ("{0:N0}" -f $r.Rx), ("{0:N0}" -f $r.Tx))
    }
    Write-Host ''
    Write-Host "  1) $(t 'Экспорт в CSV' 'Export CSV')"
    Write-Host "  2) $(t 'Сбросить счётчики' 'Reset counters')"
    Write-Host "  3) $(t 'Назад' 'Back')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    switch ($ch) {
        '1' {
            $out = Read-Value (t 'Файл' 'File') '.\wg-traffic.csv'
            $rows | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
            Write-Info (t "CSV: $out" "CSV: $out")
        }
        '2' { Reset-TrafficCounters }
    }
}

function Test-PeerPing {
    Show-Section (t 'Ping всех пиров' 'Ping all peers')
    $ok = 0; $fail = 0
    foreach ($name in (Get-PeerNames)) {
        if (Test-PeerDisabled $name) { continue }
        $ip = (Get-PeerField $name 'AllowedIPs') -replace '/32$', ''
        if ($ip -eq '') { continue }
        $r = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($r) {
            Write-Host ("  [OK] {0,-18} {1}" -f $name, $ip)
            $ok++
        } else {
            Write-Host ("  [--] {0,-18} {1}" -f $name, $ip)
            $fail++
        }
    }
    Write-Info (t "OK: $ok  FAIL: $fail" "OK: $ok  FAIL: $fail")
}

function Get-ServerPublicKey {
    Show-Section (t 'Публичный ключ сервера' 'Server public key')
    if (Test-Path $script:ServerPubKey) {
        Write-Host (Get-Content $script:ServerPubKey -Raw).Trim()
    } elseif (Get-NetAdapter -Name $script:WgIf -ErrorAction SilentlyContinue) {
        & $script:WgExe show $script:WgIf public-key
    } else {
        Write-WarningMsg (t "Файл $($script:ServerPubKey) не найден" "$($script:ServerPubKey) not found")
    }
}

function Get-ServerExternalIp {
    Show-Section (t 'Внешний IP сервера' 'Server external IP')
    $ip = Get-ExternalIp
    if ($ip) {
        Write-Host "  $ip"
        if (Test-Path $script:ServerConf) {
            $m = Select-String -Path $script:ServerConf -Pattern '^ListenPort = (\d+)' | Select-Object -First 1
            $port = $script:WgPort
            if ($m) { $port = $m.Matches[0].Groups[1].Value }
            Write-Host "  ${ip}:$port"
        }
    } else {
        Write-WarningMsg (t 'Не удалось определить внешний IP' 'Cannot detect external IP')
    }
}

# ==================== СЕРВИС ====================

function Get-TunnelServiceName {
    return "WireGuardTunnel`$$($script:WgIf)"
}

function Start-Tunnel {
    & $script:WireguardExe /installtunnelservice $script:ServerConf 2>&1 | Out-Null
    Write-Info (t 'Туннель запущен' 'Tunnel started')
    Write-Log -Message 'Start-Tunnel'
}

function Stop-Tunnel {
    & $script:WireguardExe /uninstalltunnelservice $script:ServerConf 2>&1 | Out-Null
    Write-Info (t 'Туннель остановлен' 'Tunnel stopped')
    Write-Log -Message 'Stop-Tunnel'
}

function Restart-Tunnel {
    Stop-Tunnel
    Start-Sleep -Seconds 1
    Start-Tunnel
}

function Set-TunnelAutostart {
    param([bool]$Enable = $true)
    $svcName = Get-TunnelServiceName
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-WarningMsg (t "Сервис $svcName не найден — сначала запустите туннель" "Service $svcName not found — start the tunnel first")
        return
    }
    if ($Enable) {
        Set-Service -Name $svcName -StartupType Automatic
        Write-Info (t 'Автозапуск включён' 'Autostart enabled')
    } else {
        Set-Service -Name $svcName -StartupType Manual
        Write-Info (t 'Автозапуск отключён' 'Autostart disabled')
    }
}

function Show-ServiceStatus {
    Show-Section (t 'Состояние сервиса' 'Service status')
    $svc = Get-Service -Name 'WireGuard*' -ErrorAction SilentlyContinue
    if ($svc) {
        $svc | Format-Table Name, Status, StartType -AutoSize | Out-String | Write-Host
    } else {
        Write-WarningMsg (t 'Туннель-сервисы не найдены' 'No tunnel services found')
    }
    if (Get-NetAdapter -Name $script:WgIf -ErrorAction SilentlyContinue) {
        Write-Host (t 'Интерфейс: поднят' 'Interface: up')
    } else {
        Write-Host (t 'Интерфейс: опущен' 'Interface: down')
    }
}

function Update-TunnelConfig {
    Show-Section (t 'Перезагрузка конфига без разрыва' 'Reload config without downtime')
    Invoke-ApplyConfig | Out-Null
}

function Show-TunnelLog {
    Show-Section (t 'Журнал WireGuard' 'WireGuard log')
    $lines = Read-Value (t 'Сколько строк' 'How many lines') '50'
    $n = 50
    if ($lines -match '^\d+$') { $n = [int]$lines }
    if (Test-Path $script:LogFile) {
        Get-Content $script:LogFile -Tail $n
    } else {
        Write-WarningMsg (t "Лог $($script:LogFile) не найден" "$($script:LogFile) not found")
    }
}

# ==================== КОНФИГ ====================

function Edit-ServerConfig {
    Show-Section (t 'Редактирование конфига' 'Edit config')
    if (-not (Test-Path $script:ServerConf)) {
        Exit-WithError (t "Файл $($script:ServerConf) не найден" "$($script:ServerConf) not found")
    }
    Start-Process notepad.exe -ArgumentList $script:ServerConf -Wait
    if (Confirm-Action (t 'Проверить синтаксис после правки? (y/N): ' 'Check syntax after edit? (y/N): ')) {
        Test-ConfigSyntax
    }
    if (Confirm-Action (t 'Применить конфиг? (y/N): ' 'Apply config? (y/N): ')) {
        Invoke-ApplyConfig | Out-Null
    }
}

function Test-ConfigSyntax {
    Show-Section (t 'Проверка синтаксиса' 'Syntax check')
    if (-not (Test-Path $script:ServerConf)) {
        Write-WarningMsg (t "Файл $($script:ServerConf) не найден" "$($script:ServerConf) not found")
        return
    }
    $content = Get-Content $script:ServerConf
    $hasIface = $false
    $privKey = $false
    $listen = $false
    $peerCount = 0
    $current = ''
    foreach ($line in $content) {
        $l = $line.Trim()
        if ($l -eq '[Interface]') { $hasIface = $true; $current = 'iface'; continue }
        if ($l -eq '[Peer]') { $peerCount++; $current = 'peer'; continue }
        if ($l.StartsWith('[')) { $current = ''; continue }
        if ($l.StartsWith('#') -or $l -eq '') { continue }
        if ($current -eq 'iface') {
            if ($l -match '^PrivateKey\s*=') { $privKey = $true }
            if ($l -match '^ListenPort\s*=') { $listen = $true }
        }
    }
    if ($hasIface) { Write-Info (t '[Interface] найден' '[Interface] found') }
    else { Write-WarningMsg (t 'Нет секции [Interface]' 'No [Interface] section') }
    if ($privKey) { Write-Info (t 'PrivateKey задан' 'PrivateKey is set') }
    else { Write-WarningMsg (t 'Нет PrivateKey' 'No PrivateKey') }
    if ($listen) { Write-Info (t 'ListenPort задан' 'ListenPort is set') }
    else { Write-WarningMsg (t 'Нет ListenPort' 'No ListenPort') }
    Write-Info (t "Пиров: $peerCount" "Peers: $peerCount")
    # дубликаты AllowedIPs
    $ips = Select-String -Path $script:ServerConf -Pattern '^\s*AllowedIPs\s*=\s*(.+)$' |
        ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
    $dups = $ips | Group-Object | Where-Object { $_.Count -gt 1 }
    foreach ($d in $dups) {
        Write-WarningMsg (t "Дубликаты AllowedIPs: $($d.Name)" "Duplicate AllowedIPs: $($d.Name)")
    }
}

function Set-ExternalInterface {
    Show-Section (t 'Внешний интерфейс' 'External interface')
    $def = Get-DetectInterface
    $new = Read-Value (t 'Новый внешний интерфейс' 'New external interface') $def
    if (-not (Test-InterfaceExists $new)) {
        Exit-WithError (t "Интерфейс $new не найден" "Interface $new not found")
    }
    $lines = Get-Content $script:ServerConf
    $out = foreach ($line in $lines) {
        if ($line -match '^# Внешний интерфейс: ') { "# Внешний интерфейс: $new" }
        else { $line }
    }
    Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
    $net = Get-VpnNetwork $script:VpnSubnet
    New-WgNat -Network $net
    Write-Info (t "Интерфейс изменён на $new" "Interface changed to $new")
    Invoke-ApplyConfig | Out-Null
}

function Set-ListenPort {
    Show-Section (t 'Порт сервера' 'Server port')
    $new = Read-Value (t 'Новый UDP-порт' 'New UDP port') $script:WgPort
    if (-not (Test-Port $new)) { Exit-WithError (t "Некорректный порт: $new" "Invalid port: $new") }
    $lines = Get-Content $script:ServerConf
    $out = foreach ($line in $lines) {
        if ($line -match '^ListenPort = ') { "ListenPort = $new" } else { $line }
    }
    Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
    $script:WgPort = $new
    Save-Settings
    New-WgFirewallRule -Port $new
    Write-Info (t "Порт изменён на $new" "Port changed to $new")
    Invoke-ApplyConfig | Out-Null
}

function Set-VpnSubnet {
    Show-Section (t 'VPN-подсеть' 'VPN subnet')
    Write-WarningMsg (t 'Смена подсети не обновляет адреса клиентов автоматически!' 'Subnet change does not rewrite client addresses automatically!')
    $new = Read-Value (t 'Новая подсеть (CIDR)' 'New subnet (CIDR)') $script:VpnSubnet
    if (-not (Test-Cidr $new)) { Exit-WithError (t "Некорректный CIDR: $new" "Invalid CIDR: $new") }
    $vpnIp = Read-Value (t 'VPN IP сервера' 'Server VPN IP') $script:ServerVpnIp
    if (-not (Test-IpAddress $vpnIp)) { Exit-WithError (t 'Некорректный IP' 'Invalid IP') }
    $lines = Get-Content $script:ServerConf
    $out = foreach ($line in $lines) {
        if ($line -match '^Address = ') { "Address = $vpnIp/32" } else { $line }
    }
    Set-Content -Path $script:ServerConf -Value $out -Encoding UTF8
    $script:VpnSubnet = $new
    $script:ServerVpnIp = $vpnIp
    Save-Settings
    $net = Get-VpnNetwork $new
    New-WgNat -Network $net
    Write-Info (t "Подсеть изменена: $new" "Subnet changed: $new")
    Invoke-ApplyConfig | Out-Null
}

# ==================== МАРШРУТИЗАЦИЯ ====================

function Set-LanAccess {
    Show-Section (t 'Доступ клиентов к LAN сервера' 'Client access to server LAN')
    $lanNet = Read-Value (t 'LAN-подсеть сервера (CIDR)' 'Server LAN subnet (CIDR)') '192.168.1.0/24'
    if (-not (Test-Cidr $lanNet)) { Exit-WithError (t "Некорректный CIDR: $lanNet" "Invalid CIDR: $lanNet") }
    # разрешить проброс между wg0 и LAN
    Get-NetFirewallRule -DisplayName 'wg-admin LAN' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'wg-admin LAN' -Direction Inbound -Action Allow `
        -InterfaceAlias $script:WgIf -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'wg-admin LAN out' -Direction Outbound -Action Allow `
        -InterfaceAlias $script:WgIf -Profile Any | Out-Null
    Write-Info (t "Разрешён доступ $($script:WgIf) → $lanNet" "Allowed $($script:WgIf) → $lanNet")
    Write-Info (t 'Добавьте LAN-подсеть в AllowedIPs клиентов, если нужен полный доступ' 'Add the LAN subnet to client AllowedIPs for full access')
}

function Set-ClientLanAccess {
    Show-Section (t 'Доступ к LAN за клиентом' 'Access to LAN behind client')
    $name = Read-Value (t 'Имя клиента' 'Client name') ''
    if (-not (Test-ClientName $name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
    if (-not (Test-PeerExists $name)) { Exit-WithError (t "Клиент $name не найден" "Client $name not found") }
    $clientLan = Read-Value (t 'LAN за клиентом (CIDR)' 'LAN behind client (CIDR)') '192.168.2.0/24'
    if (-not (Test-Cidr $clientLan)) { Exit-WithError (t "Некорректный CIDR: $clientLan" "Invalid CIDR: $clientLan") }
    $cur = Get-PeerField $name 'AllowedIPs'
    if ($cur -match [regex]::Escape($clientLan)) {
        Write-Info (t 'Уже добавлено' 'Already present')
    } else {
        Set-PeerField -Name $name -Field 'AllowedIPs' -Value "$cur, $clientLan"
        Write-Info (t "AllowedIPs ${name}: $cur, $clientLan" "AllowedIPs ${name}: $cur, $clientLan")
    }
    Invoke-ApplyConfig | Out-Null
}

function Set-SiteToSite {
    Show-Section (t 'Site-to-Site' 'Site-to-Site')
    Write-Info (t 'Соединяет две локальные сети через два WireGuard-узла' 'Connects two LANs via two WireGuard endpoints')
    $remotePub = Read-Value (t 'Публичный ключ удалённого узла' 'Remote peer public key') ''
    if ($remotePub -eq '') { Exit-WithError (t 'Ключ обязателен' 'Key is required') }
    $remoteAllowed = Read-Value (t 'Подсети за удалённым узлом (CIDR через запятую)' 'Remote subnets (comma-separated CIDR)') ''
    if ($remoteAllowed -eq '') { Exit-WithError (t 'Подсети обязательны' 'Subnets are required') }
    $remoteEndpoint = Read-Value (t 'Endpoint удалённого узла (ip:port)' 'Remote endpoint (ip:port)') ''
    if ($remoteEndpoint -eq '') { Exit-WithError (t 'Endpoint обязателен' 'Endpoint is required') }
    $name = Read-Value (t 'Имя пира (латиница)' 'Peer name (latin)') 'site2site'
    if (-not (Test-ClientName $name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
    if (Test-PeerExists $name) { Exit-WithError (t "Пир $name уже существует" "Peer $name already exists") }
    $block = @('', "# $name", '# COMMENT site-to-site', '[Peer]',
        "PublicKey = $remotePub", "AllowedIPs = $remoteAllowed",
        "Endpoint = $remoteEndpoint", 'PersistentKeepalive = 25')
    Add-Content -Path $script:ServerConf -Value $block -Encoding UTF8
    Write-Info (t "Site-to-Site пир $name добавлен" "Site-to-Site peer $name added")
    Write-Info (t 'Настройте зеркальный пир на удалённой стороне' 'Configure the mirror peer on the remote side')
    Invoke-ApplyConfig | Out-Null
}

function Set-Dns {
    Show-Section (t 'DNS (для клиентов)' 'DNS (for clients)')
    Write-Host "  1) $(t 'Указать DNS для клиентов (в новых конфигах)' 'Set DNS for clients (new configs)')"
    Write-Host "  2) $(t 'Назад' 'Back')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    if ($ch -eq '1') {
        $dns = Read-Value (t 'DNS для клиентов' 'DNS for clients') $script:DnsDefault
        if (-not (Test-IpAddress $dns)) { Exit-WithError (t 'Некорректный DNS' 'Invalid DNS') }
        $script:DnsDefault = $dns
        Save-Settings
        Write-Info (t "DNS по умолчанию: $dns" "Default DNS: $dns")
        Write-Info (t 'Новые клиенты получат этот DNS; для существующих — отредактируйте вручную' 'New clients will get this DNS; edit existing ones manually')
    }
}

function Set-SplitTunnel {
    Show-Section (t 'Split-tunnel' 'Split-tunnel')
    Write-Info (t 'Только указанные подсети идут через VPN' 'Only listed subnets go via VPN')
    $name = Read-Value (t 'Имя клиента' 'Client name') ''
    if (-not (Test-ClientName $name)) { Exit-WithError (t 'Некорректное имя' 'Invalid name') }
    if (-not (Test-PeerExists $name)) { Exit-WithError (t "Клиент $name не найден" "Client $name not found") }
    $subnets = Read-Value (t 'Подсети через запятую' 'Subnets, comma-separated') $script:VpnSubnet
    $list = @()
    foreach ($s in ($subnets -split ',')) {
        $s = $s.Trim()
        if ($s -eq '') { continue }
        if (-not (Test-Cidr $s)) { Exit-WithError (t "Некорректный CIDR: $s" "Invalid CIDR: $s") }
        $list += $s
    }
    if ($list.Count -eq 0) { Exit-WithError (t 'Нет валидных подсетей' 'No valid subnets') }
    $allowed = $list -join ', '
    Set-PeerField -Name $name -Field 'AllowedIPs' -Value $allowed
    $cpath = Join-Path $script:ClientsDir "$name.conf"
    if (Test-Path $cpath) {
        (Get-Content $cpath) -replace '^AllowedIPs = .*', "AllowedIPs = $allowed" |
            Set-Content $cpath -Encoding ASCII
    }
    Write-Info (t "Split-tunnel для ${name}: $allowed" "Split-tunnel for ${name}: $allowed")
    Invoke-ApplyConfig | Out-Null
}

function Set-RateLimit {
    Show-Section (t 'Ограничение скорости (tc)' 'Rate limiting (tc)')
    Write-WarningMsg (t 'На Windows нет tc — используйте QoS-политики Windows или лимиты маршрутизатора' 'No tc on Windows — use Windows QoS policies or router limits')
    Write-Info (t 'См.: New-NetQosPolicy, Get-NetQosPolicy' 'See: New-NetQosPolicy, Get-NetQosPolicy')
    Write-Info (t 'Пример: New-NetQosPolicy -Name wg-limit -ThrottleRateActionBitsPerSecond 10MB' 'Example: New-NetQosPolicy -Name wg-limit -ThrottleRateActionBitsPerSecond 10MB')
}

# ==================== БЕЗОПАСНОСТЬ ====================

function Set-Firewall {
    Show-Section (t 'Firewall (Windows Firewall)' 'Firewall (Windows Firewall)')
    Write-Host "  1) $(t 'Базовые правила WireGuard (порт + ICMP)' 'Basic WireGuard rules (port + ICMP)')"
    Write-Host "  2) $(t 'Только порт WireGuard и RDP' 'WireGuard port and RDP only')"
    Write-Host "  3) $(t 'Показать состояние' 'Show state')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    $port = $script:WgPort
    $m = Select-String -Path $script:ServerConf -Pattern '^ListenPort = (\d+)' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($m) { $port = $m.Matches[0].Groups[1].Value }
    switch ($ch) {
        '1' {
            New-WgFirewallRule -Port $port
            Get-NetFirewallRule -DisplayName 'wg-admin ICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName 'wg-admin ICMP' -Direction Inbound -Action Allow `
                -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
            Write-Info (t "Разрешены udp/$port и ICMP" "Allowed udp/$port and ICMP")
        }
        '2' {
            New-WgFirewallRule -Port $port
            Get-NetFirewallRule -DisplayName 'wg-admin RDP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName 'wg-admin RDP' -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort 3389 -Profile Any | Out-Null
            Write-Info (t "Разрешены udp/$port и RDP (3389/tcp)" "Allowed udp/$port and RDP (3389/tcp)")
        }
        '3' {
            Get-NetFirewallRule -DisplayName 'wg-admin*' -ErrorAction SilentlyContinue |
                Format-Table DisplayName, Direction, Action, Enabled -AutoSize | Out-String | Write-Host
        }
    }
}

function Set-IpRestriction {
    Show-Section (t 'Ограничение по IP' 'IP restriction')
    Write-Host "  1) $(t 'Разрешить подключение с указанных IP' 'Allow connections from listed IPs')"
    Write-Host "  2) $(t 'Убрать ограничения' 'Remove restrictions')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    $port = $script:WgPort
    $m = Select-String -Path $script:ServerConf -Pattern '^ListenPort = (\d+)' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($m) { $port = $m.Matches[0].Groups[1].Value }
    Get-NetFirewallRule -DisplayName 'wg-admin src-*' -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    if ($ch -eq '1') {
        $ips = Read-Value (t 'Разрешённые IP через запятую' 'Allowed IPs, comma-separated') ''
        if ($ips -eq '') { Write-WarningMsg (t 'Пустой список' 'Empty list'); return }
        foreach ($ip in ($ips -split ',')) {
            $ip = $ip.Trim()
            if ($ip -eq '') { continue }
            if (-not (Test-IpAddress $ip)) { Write-WarningMsg (t "Пропуск: $ip" "Skip: $ip"); continue }
            New-NetFirewallRule -DisplayName "wg-admin src-$ip" -Direction Inbound -Action Allow `
                -Protocol UDP -LocalPort ([int]$port) -RemoteAddress $ip -Profile Any | Out-Null
            Write-Info (t "Разрешён $ip → udp/$port" "Allowed $ip → udp/$port")
        }
        # запрет для остальных (если нужно — политика блокировки не включается автоматически)
        Write-WarningMsg (t 'Правила разрешения добавлены. Для жёсткого allow-list включите политику блокировки в Windows Firewall.' 'Allow rules added. Enable a block policy in Windows Firewall for a strict allow-list.')
    } elseif ($ch -eq '2') {
        Write-Info (t 'Ограничения сняты' 'Restrictions removed')
    }
}

function Show-ConnectionAudit {
    Show-Section (t 'Аудит подключений' 'Connection audit')
    Write-Host (t 'Последние действия из лога:' 'Recent actions from log:')
    if (Test-Path $script:LogFile) {
        Get-Content $script:LogFile -Tail 50
    } else {
        Write-WarningMsg (t "Лог $($script:LogFile) не найден" "$($script:LogFile) not found")
    }
    Write-Host ''
    Write-Host (t 'Активные handshake:' 'Active handshakes:')
    if (Get-NetAdapter -Name $script:WgIf -ErrorAction SilentlyContinue) {
        try {
            $raw = & $script:WgExe show $script:WgIf latest-handshakes 2>$null
            foreach ($line in $raw) {
                $p = $line -split '\s+'
                if ($p.Count -lt 2) { continue }
                $pub = $p[0]; $ts = [int64]$p[1]
                $who = '?'
                foreach ($n in (Get-PeerNames)) {
                    if ((Get-PeerField $n 'PublicKey') -eq $pub) { $who = $n; break }
                }
                $when = '-'
                if ($ts -gt 0) {
                    $when = [DateTimeOffset]::FromUnixTimeSeconds($ts).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
                Write-Host ('  {0,-18} {1}' -f $who, $when)
            }
        } catch { }
    }
}

function Rotate-ServerKeys {
    Show-Section (t 'Ротация ключей сервера' 'Rotate server keys')
    Write-WarningMsg (t 'Потребуется перевыпустить конфиги ВСЕХ клиентов!' 'All client configs must be reissued!')
    if (-not (Confirm-Action (t 'Продолжить? (y/N): ' 'Continue? (y/N): '))) {
        Write-Info (t 'Отмена' 'Cancelled')
        return
    }
    $oldPub = ''
    if (Test-Path $script:ServerPubKey) { $oldPub = (Get-Content $script:ServerPubKey -Raw).Trim() }
    New-ServerKeys
    $newPriv = (Get-Content $script:ServerPrivKey -Raw).Trim()
    $newPub = (Get-Content $script:ServerPubKey -Raw).Trim()
    $lines = Get-Content $script:ServerConf
    $out = foreach ($line in $lines) {
        if ($line -match '^PrivateKey = ') { "PrivateKey = $newPriv" } else { $line }
    }
    Set-Content -Path $script:ServerConf -Value $out -Encoding ASCII
    Write-Info (t "Старый ключ: $($oldPub.Substring(0, [Math]::Min(20, $oldPub.Length)))..." "Old key: $($oldPub.Substring(0, [Math]::Min(20, $oldPub.Length)))...")
    Write-Info (t "Новый ключ: $newPub" "New key: $newPub")
    if (Test-Path $script:ClientsDir) {
        Get-ChildItem $script:ClientsDir -Filter *.conf | ForEach-Object {
            (Get-Content $_.FullName) -replace '^PublicKey = .*', "PublicKey = $newPub" |
                Set-Content $_.FullName -Encoding ASCII
        }
        Write-Info (t "Обновлены конфиги клиентов в $($script:ClientsDir)" "Updated client configs in $($script:ClientsDir)")
    }
    Invoke-ApplyConfig | Out-Null
    Write-Info (t 'Ротация завершена. Передайте клиентам новые конфиги.' 'Rotation done. Distribute new client configs.')
}

# ==================== БЭКАП ====================

function New-WgBackup {
    Show-Section (t 'Создание бэкапа' 'Create backup')
    Write-Host "  1) $(t 'Только конфиги' 'Configs only')"
    Write-Host "  2) $(t 'Конфиги + база сроков' 'Configs + expiry DB')"
    Write-Host "  3) $(t 'Полный (конфиги, ключи, настройки, лог)' 'Full (configs, keys, settings, log)')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    if (-not (Test-Path $script:BackupDir)) {
        New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null
    }
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $stage = Join-Path $env:TEMP "wg-bak-$ts"
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-Item $script:ServerConf (Join-Path $stage 'server.conf') -ErrorAction SilentlyContinue
    if (Test-Path $script:ClientsDir) {
        Copy-Item $script:ClientsDir (Join-Path $stage 'clients') -Recurse -ErrorAction SilentlyContinue
    }
    if ($ch -in @('2', '3') -and (Test-Path $script:ExpiryDb)) {
        Copy-Item $script:ExpiryDb (Join-Path $stage 'expiry.db')
    }
    if ($ch -eq '3') {
        foreach ($f in @($script:ServerPrivKey, $script:ServerPubKey, $script:SettingsFile, $script:LogFile)) {
            if (Test-Path $f) { Copy-Item $f (Join-Path $stage (Split-Path $f -Leaf)) }
        }
    }
    $archive = Join-Path $script:BackupDir "wg-backup-$ts.zip"
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    Write-Info (t "Бэкап: $archive" "Backup: $archive")
    Write-Log -Message "New-WgBackup: $archive"
}

function Restore-WgBackup {
    Show-Section (t 'Восстановление из бэкапа' 'Restore from backup')
    Get-WgBackupList
    $archive = Read-Value (t 'Путь к архиву' 'Archive path') ''
    if (-not (Test-Path $archive)) { Exit-WithError (t "Файл не найден: $archive" "Not found: $archive") }
    Write-WarningMsg (t 'Текущие конфиги будут перезаписаны' 'Current configs will be overwritten')
    if (-not (Confirm-Action (t 'Восстановить? (y/N): ' 'Restore? (y/N): '))) {
        Write-Info (t 'Отмена' 'Cancelled')
        return
    }
    $safety = Join-Path $script:BackupDir "pre-restore-$(Get-Date -Format yyyyMMddHHmmss).zip"
    if (-not (Test-Path $script:BackupDir)) {
        New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null
    }
    Compress-Archive -Path (Join-Path $script:WgDir '*') -DestinationPath $safety -Force -ErrorAction SilentlyContinue
    $stage = Join-Path $env:TEMP "wg-restore-$(Get-Date -Format yyyyMMddHHmmss)"
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Expand-Archive -Path $archive -DestinationPath $stage -Force
    foreach ($item in Get-ChildItem $stage) {
        $dest = Join-Path $script:WgDir $item.Name
        if ($item.PSIsContainer) {
            Copy-Item $item.FullName $dest -Recurse -Force
        } else {
            Copy-Item $item.FullName $dest -Force
        }
    }
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    Write-Info (t 'Восстановление завершено' 'Restore complete')
    Write-Info (t "Копия прежнего состояния: $safety" "Previous state saved to: $safety")
    if (Confirm-Action (t 'Применить конфиг? (y/N): ' 'Apply config? (y/N): ')) {
        Invoke-ApplyConfig | Out-Null
    }
}

function Get-WgBackupList {
    Show-Section (t 'Список бэкапов' 'Backup list')
    if (-not (Test-Path $script:BackupDir)) {
        Write-Info (t "Каталог $($script:BackupDir) пуст" "$($script:BackupDir) is empty")
        return
    }
    Get-ChildItem $script:BackupDir -File | Sort-Object LastWriteTime | ForEach-Object {
        Write-Host ('  {0}  {1}' -f $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $_.FullName)
    }
}

function Set-BackupSchedule {
    Show-Section (t 'Автобэкап по расписанию' 'Scheduled backup')
    Write-Host "  1) $(t 'Ежедневно' 'Daily')"
    Write-Host "  2) $(t 'Еженедельно' 'Weekly')"
    Write-Host "  3) $(t 'Отключить' 'Disable')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    $taskName = 'wg-admin-backup'
    if ($ch -eq '3') {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Info (t 'Автобэкап отключён' 'Scheduled backup disabled')
        return
    }
    if ($ch -notin @('1', '2')) { return }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -Command `"Compress-Archive -Path 'C:\ProgramData\wg-admin\server.conf','C:\ProgramData\wg-admin\clients','C:\ProgramData\wg-admin\expiry.db' -DestinationPath ('C:\ProgramData\wg-admin\backups\wg-auto-' + (Get-Date -Format yyyyMMdd-HHmmss) + '.zip') -Force`""
    if ($ch -eq '1') {
        $trigger = New-ScheduledTaskTrigger -Daily -At 3:17am
    } else {
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3:17am
    }
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Force | Out-Null
    Write-Info (t 'Автобэкап запланирован' 'Scheduled backup registered')
}

# ==================== ОБСЛУЖИВАНИЕ ====================

function Reset-TrafficCounters {
    Show-Section (t 'Сброс счётчиков трафика' 'Reset traffic counters')
    Write-WarningMsg (t 'WireGuard не поддерживает сброс счётчиков без пересоздания интерфейса' 'WireGuard cannot reset counters without recreating the interface')
    if (Confirm-Action (t 'Пересоздать туннель (краткий разрыв)? (y/N): ' 'Recreate tunnel (brief drop)? (y/N): ')) {
        Restart-Tunnel
        Write-Info (t 'Счётчики обнулены' 'Counters reset')
    }
}

function Remove-InactiveClients {
    Show-Section (t 'Очистка неактивных клиентов' 'Clean inactive clients')
    Write-Info (t 'Неактивные = без handshake более N дней' 'Inactive = no handshake for N days')
    $days = Read-Value (t 'Порог дней без handshake' 'Days without handshake') '30'
    if ($days -notmatch '^\d+$') { $days = '30' }
    $now = Get-UnixNow
    $cutoff = $now - ([int]$days * 86400)
    $hs = @{}
    if (Get-NetAdapter -Name $script:WgIf -ErrorAction SilentlyContinue) {
        try {
            $raw = & $script:WgExe show $script:WgIf latest-handshakes 2>$null
            foreach ($line in $raw) {
                $p = $line -split '\s+'
                if ($p.Count -ge 2) { $hs[$p[0]] = [int64]$p[1] }
            }
        } catch { }
    }
    $candidates = @()
    foreach ($name in (Get-PeerNames)) {
        if (Test-PeerDisabled $name) { continue }
        $pub = Get-PeerField $name 'PublicKey'
        if ($pub -eq '') { continue }
        $ts = 0
        if ($hs.ContainsKey($pub)) { $ts = $hs[$pub] }
        if ($ts -eq 0 -or $ts -lt $cutoff) {
            $candidates += $name
            $last = t 'никогда/never' 'never/unknown'
            if ($ts -gt 0) { $last = Format-Ts "$ts" }
            Write-Host ('  {0,-18} last={1}' -f $name, $last)
        }
    }
    if ($candidates.Count -eq 0) {
        Write-Info (t 'Таких клиентов нет' 'No such clients')
        return
    }
    Write-Host "  1) $(t 'Только показать (уже показано)' 'Just list (already listed)')"
    Write-Host "  2) $(t 'Отключить' 'Disable')"
    Write-Host "  3) $(t 'Удалить' 'Delete')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    switch ($ch) {
        '2' {
            foreach ($n in $candidates) { Disable-Peer $n }
            Invoke-ApplyConfig | Out-Null
        }
        '3' {
            if (-not (Confirm-Action (t 'Удалить безвозвратно? (y/N): ' 'Delete permanently? (y/N): '))) { return }
            foreach ($n in $candidates) {
                Remove-PeerBlock $n
                $cpath = Join-Path $script:ClientsDir "$n.conf"
                if (Test-Path $cpath) { Remove-Item $cpath -Force }
                if (Test-Path $script:ExpiryDb) {
                    Get-Content $script:ExpiryDb | Where-Object { $_.Split(':', 2)[0] -ne $n } |
                        Set-Content $script:ExpiryDb -Encoding UTF8
                }
                Write-Info (t "Удалён: $n" "Removed: $n")
            }
            Invoke-ApplyConfig | Out-Null
        }
    }
}

function Remove-ExpiredClients {
    Show-Section (t 'Удаление истёкших клиентов' 'Remove expired clients')
    $found = @()
    foreach ($n in (Get-PeerNames)) {
        if (Test-PeerExpired $n) { $found += $n }
    }
    if ($found.Count -eq 0) {
        Write-Info (t 'Истёкших нет' 'No expired clients')
        return
    }
    Write-Info (t "Истёкшие: $($found -join ', ')" "Expired: $($found -join ', ')")
    if (-not (Confirm-Action (t 'Удалить? (y/N): ' 'Delete? (y/N): '))) { return }
    foreach ($n in $found) {
        Remove-PeerBlock $n
        $cpath = Join-Path $script:ClientsDir "$n.conf"
        if (Test-Path $cpath) { Remove-Item $cpath -Force }
        if (Test-Path $script:ExpiryDb) {
            Get-Content $script:ExpiryDb | Where-Object { $_.Split(':', 2)[0] -ne $n } |
                Set-Content $script:ExpiryDb -Encoding UTF8
        }
        Write-Info (t "Удалён: $n" "Removed: $n")
        Write-Log -Message "Remove-ExpiredClients: $n"
    }
    Invoke-ApplyConfig | Out-Null
}

# ==================== ДИАГНОСТИКА ====================

function Test-IpForwarding {
    Show-Section (t 'IP-форвардинг' 'IP forwarding')
    $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -ErrorAction SilentlyContinue
    Write-Host "  IPEnableRouter = $($reg.IPEnableRouter)"
    if ($reg.IPEnableRouter -eq 1) {
        Write-Info (t 'Форвардинг включён (реестр)' 'Forwarding is enabled (registry)')
    } else {
        Write-WarningMsg (t 'Форвардинг выключен' 'Forwarding is disabled')
    }
    Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.Forwarding -eq 'Enabled' } |
        Format-Table InterfaceAlias, InterfaceIndex, Forwarding -AutoSize | Out-String | Write-Host
}

function Test-Nat {
    Show-Section (t 'Проверка NAT' 'NAT check')
    $nat = Get-NetNat -Name 'WG-Nat' -ErrorAction SilentlyContinue
    if ($nat) {
        Write-Info (t 'NAT WG-Nat настроен' 'NAT WG-Nat is configured')
        $nat | Format-Table Name, InternalIPInterfaceAddressPrefix -AutoSize | Out-String | Write-Host
    } else {
        Write-WarningMsg (t 'NAT WG-Nat не найден' 'NAT WG-Nat not found')
    }
}

function Test-ExternalPort {
    Show-Section (t 'Проверка порта извне' 'External port check')
    $port = $script:WgPort
    $m = Select-String -Path $script:ServerConf -Pattern '^ListenPort = (\d+)' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($m) { $port = $m.Matches[0].Groups[1].Value }
    $ip = Get-ExternalIp
    Write-Info (t "Сервер: ${ip}:$port" "Server: ${ip}:$port")
    Write-Host (t 'Слушатели UDP:' 'UDP listeners:')
    Get-NetUDPEndpoint -LocalPort ([int]$port) -ErrorAction SilentlyContinue |
        Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize | Out-String | Write-Host
    Write-Host (t 'Проверьте порт с внешней машины:' 'From an external host run:')
    Write-Host "  Test-NetConnection -ComputerName $ip -Port $port"
    Write-Info (t 'WireGuard молчит на неизвестные пакеты — успешный тест = нет ICMP unreachable' 'WireGuard ignores unknown packets — success = no ICMP unreachable')
}

function Test-DnsThroughTunnel {
    Show-Section (t 'Проверка DNS' 'DNS check')
    $target = Read-Value (t 'DNS-сервер для проверки' 'DNS server to test') $script:DnsDefault
    Write-Host (t 'Тест с сервера (напрямую):' 'Test from server (direct):')
    try {
        Resolve-DnsName -Name example.com -Server $target -ErrorAction Stop | Format-Table -AutoSize | Out-String | Write-Host
    } catch {
        Write-WarningMsg (t "DNS-запрос не прошёл: $($_.Exception.Message)" "DNS query failed: $($_.Exception.Message)")
    }
    Write-Host (t 'С VPN-клиента выполните:' 'From a VPN client run:')
    Write-Host "  Resolve-DnsName example.com -Server $target"
}

function New-SupportReport {
    Show-Section (t 'Отчёт для поддержки' 'Support report')
    $out = Read-Value (t 'Файл отчёта' 'Report file') ".\wg-support-report-$(Get-Date -Format yyyyMMdd-HHmmss).txt"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=== wg-admin.ps1 support report ===')
    [void]$sb.AppendLine("Date: $(Get-Date -Format o)")
    [void]$sb.AppendLine("Version: $($script:AppVersion)")
    [void]$sb.AppendLine("`n=== OS ===")
    [void]$sb.AppendLine((Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | Out-String))
    [void]$sb.AppendLine("`n=== WireGuard ===")
    [void]$sb.AppendLine("wg.exe: $(Test-Path $script:WgExe)  wireguard.exe: $(Test-Path $script:WireguardExe)")
    [void]$sb.AppendLine("`n=== Adapters ===")
    [void]$sb.AppendLine((Get-NetAdapter | Select-Object Name, InterfaceDescription, Status | Out-String))
    [void]$sb.AppendLine("`n=== wg show (redacted keys) ===")
    if (Get-NetAdapter -Name $script:WgIf -ErrorAction SilentlyContinue) {
        $show = (& $script:WgExe show $script:WgIf 2>&1 | Out-String)
        $show = $show -replace '(?m)^\s*(public key|private key|preshared key):.*', '$1: [REDACTED]'
        [void]$sb.AppendLine($show)
    }
    [void]$sb.AppendLine("`n=== server.conf (без приватных ключей) ===")
    if (Test-Path $script:ServerConf) {
        foreach ($line in Get-Content $script:ServerConf) {
            if ($line -match '^(PrivateKey|PresharedKey)\s*=') {
                [void]$sb.AppendLine(($line -replace '=.*', '= [REDACTED]'))
            } else {
                [void]$sb.AppendLine($line)
            }
        }
    }
    [void]$sb.AppendLine("`n=== NAT ===")
    [void]$sb.AppendLine((Get-NetNat -ErrorAction SilentlyContinue | Out-String))
    [void]$sb.AppendLine("`n=== Firewall wg-admin* ===")
    [void]$sb.AppendLine((Get-NetFirewallRule -DisplayName 'wg-admin*' -ErrorAction SilentlyContinue | Out-String))
    [void]$sb.AppendLine("`n=== Services ===")
    [void]$sb.AppendLine((Get-Service -Name 'WireGuard*' -ErrorAction SilentlyContinue | Out-String))
    [void]$sb.AppendLine("`n=== recent log ===")
    if (Test-Path $script:LogFile) {
        [void]$sb.AppendLine((Get-Content $script:LogFile -Tail 100 | Out-String))
    }
    Set-Content -Path $out -Value $sb.ToString() -Encoding UTF8
    Write-Info (t "Отчёт сохранён: $out" "Report saved: $out")
    Write-Info (t 'Приватные ключи в отчёте скрыты' 'Private keys are redacted')
}

# ==================== НАСТРОЙКИ ====================

function Show-SettingsMenu {
    while ($true) {
        Show-Section (t 'Настройки скрипта' 'Script settings')
        $colorLabel = if ($script:UseColor) { t 'вкл' 'on' } else { t 'выкл' 'off' }
        Write-Host ("  1) {0} : {1}" -f (t 'VPN-подсеть по умолчанию' 'Default VPN subnet'), $script:VpnSubnet)
        Write-Host ("  2) {0} : {1}" -f (t 'Порт по умолчанию' 'Default port'), $script:WgPort)
        Write-Host ("  3) {0} : {1}" -f (t 'DNS по умолчанию' 'Default DNS'), $script:DnsDefault)
        Write-Host ("  4) {0} : {1}" -f (t 'Цветной вывод' 'Color output'), $colorLabel)
        Write-Host ("  5) {0} : {1}" -f (t 'Уровень логирования' 'Log level'), $script:LogLevel)
        Write-Host ("  6) {0} : {1}" -f (t 'Язык интерфейса' 'Interface language'), $script:LangUi)
        Write-Host ("  7) {0}" -f (t 'Назад' 'Back'))
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1' {
                $v = Read-Value (t 'VPN-подсеть (CIDR)' 'VPN subnet (CIDR)') $script:VpnSubnet
                if (Test-Cidr $v) { $script:VpnSubnet = $v; Save-Settings }
                else { Write-WarningMsg (t 'Некорректный CIDR' 'Invalid CIDR') }
            }
            '2' {
                $v = Read-Value (t 'Порт' 'Port') $script:WgPort
                if (Test-Port $v) { $script:WgPort = $v; Save-Settings }
                else { Write-WarningMsg (t 'Некорректный порт' 'Invalid port') }
            }
            '3' {
                $v = Read-Value (t 'DNS' 'DNS') $script:DnsDefault
                if (Test-IpAddress $v) { $script:DnsDefault = $v; Save-Settings }
                else { Write-WarningMsg (t 'Некорректный DNS' 'Invalid DNS') }
            }
            '4' {
                $script:UseColor = -not $script:UseColor
                Save-Settings
            }
            '5' {
                Write-Host '  DEBUG | INFO | WARN | ERROR'
                $v = Read-Value (t 'Уровень' 'Level') $script:LogLevel
                if ($v -in @('DEBUG', 'INFO', 'WARN', 'ERROR')) { $script:LogLevel = $v; Save-Settings }
                else { Write-WarningMsg (t 'Неизвестный уровень' 'Unknown level') }
            }
            '6' {
                $v = Read-Value (t 'Язык (ru/en)' 'Language (ru/en)') $script:LangUi
                if ($v -in @('ru', 'en')) { $script:LangUi = $v; Save-Settings }
                else { Write-WarningMsg (t 'Поддерживаются ru и en' 'Only ru and en supported') }
            }
            '7' { break }
        }
    }
}

# ==================== УДАЛЕНИЕ ====================

function Uninstall-Wg {
    Show-Section (t 'Удаление WireGuard' 'Uninstall WireGuard')
    Write-Host "  1) $(t 'Остановить и удалить туннель-сервис' 'Stop and remove tunnel service')"
    Write-Host "  2) $(t 'Удалить конфиги и ключи' 'Remove configs and keys')"
    Write-Host "  3) $(t 'Удалить NAT и правила Firewall' 'Remove NAT and Firewall rules')"
    Write-Host "  4) $(t 'Удалить приложение WireGuard (деинсталлятор)' 'Uninstall WireGuard app')"
    Write-Host "  5) $(t 'Полное удаление' 'Full uninstall')"
    Write-Host "  6) $(t 'Назад' 'Back')"
    $ch = Read-Value (t 'Выбор' 'Choice') ''
    if ($ch -in @('1', '5')) {
        Stop-Tunnel
        if ($ch -eq '1') { return }
    }
    if ($ch -in @('2', '5')) {
        Write-WarningMsg (t "Будет удалён $($script:WgDir)" "$($script:WgDir) will be deleted")
        if (Confirm-Action (t 'Удалить конфиги и ключи? (y/N): ' 'Delete configs and keys? (y/N): ')) {
            Remove-Item $script:WgDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Info (t 'Конфиги удалены' 'Configs removed')
        }
        if ($ch -eq '2') { return }
    }
    if ($ch -in @('3', '5')) {
        Get-NetNat -Name 'WG-Nat' -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetFirewallRule -DisplayName 'wg-admin*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName 'wg-admin-expire-check' -Confirm:$false -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName 'wg-admin-backup' -Confirm:$false -ErrorAction SilentlyContinue
        Write-Info (t 'NAT и Firewall очищены' 'NAT and Firewall cleaned')
        if ($ch -eq '3') { return }
    }
    if ($ch -in @('4', '5')) {
        Write-WarningMsg (t 'Будет запущен деинсталлятор WireGuard' 'WireGuard uninstaller will be launched')
        if (Confirm-Action (t 'Продолжить? (y/N): ' 'Continue? (y/N): ')) {
            $uninst = 'C:\Program Files\WireGuard\uninstall.exe'
            if (Test-Path $uninst) {
                Start-Process $uninst -ArgumentList '/quiet' -Wait
                Write-Info (t 'WireGuard удалён' 'WireGuard uninstalled')
            } else {
                Write-WarningMsg (t 'Деинсталлятор не найден' 'Uninstaller not found')
            }
        }
    }
}

# ==================== О СКРИПТЕ ====================

function Show-AboutMenu {
    while ($true) {
        Show-Section (t 'О скрипте' 'About')
        Write-Host "  1) $(t 'Версия' 'Version')"
        Write-Host "  2) $(t 'Автор / репозиторий' 'Author / repository')"
        Write-Host "  3) $(t 'Лицензия' 'License')"
        Write-Host "  4) $(t 'Проверить обновления скрипта' 'Check for script updates')"
        Write-Host "  5) $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1' { Write-Host "  wg-admin.ps1 v$($script:AppVersion)" }
            '2' {
                Write-Host '  wg-admin.ps1 — WireGuard admin (Hub-and-Spoke) for Windows'
                Write-Host '  https://github.com/StarLeG/wg-admin-bash'
                Write-Host '  Author: ИП Старинский Олег Григорьевич'
                Write-Host '  UNP: 391567102'
                Write-Host '  Site: https://electroman.by/'
                Write-Host '  Telegram: https://t.me/electroman_industry'
                Write-Host '  E-mail: info@electroman.by'
                Write-Host '  Phone: +375 (29) 714-28-82'
            }
            '3' { Write-Host '  MIT License' }
            '4' {
                try {
                    $raw = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/StarLeG/wg-admin-bash/main/wg-admin.ps1' `
                        -UseBasicParsing -TimeoutSec 8).Content
                    $m = [regex]::Match($raw, "script:AppVersion\s*=\s*'([^']+)'")
                    if (-not $m.Success) {
                        Write-WarningMsg (t 'Не удалось получить версию с GitHub' 'Cannot fetch version from GitHub')
                    } elseif ($m.Groups[1].Value -eq $script:AppVersion) {
                        Write-Info (t "Актуальная версия: $($script:AppVersion)" "Up to date: $($script:AppVersion)")
                    } else {
                        Write-Info (t "Доступна версия: $($m.Groups[1].Value) (локальная: $($script:AppVersion))" "Available: $($m.Groups[1].Value) (local: $($script:AppVersion))")
                    }
                } catch {
                    Write-WarningMsg (t 'Не удалось проверить обновления' 'Update check failed')
                }
            }
            '5' { break }
        }
    }
}

# ==================== МЕНЮ ====================

function Show-ClientsMenu {
    while ($true) {
        Show-Section (t 'Управление клиентами' 'Client management')
        Write-Host "  3.1 $(t 'Добавить клиента' 'Add client')"
        Write-Host "  3.2 $(t 'Список клиентов' 'List clients')"
        Write-Host "  3.3 $(t 'Редактировать клиента' 'Edit client')"
        Write-Host "  3.4 $(t 'Удалить клиента' 'Remove client')"
        Write-Host "  3.5 $(t 'Отключить / включить клиента' 'Disable / enable client')"
        Write-Host "  3.6 $(t 'Управление сроком действия' 'Expiry management')"
        Write-Host "  3.7 $(t 'Показать конфиг клиента' 'Show client config')"
        Write-Host "  3.8 $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1'   { Add-Client }
            '3.1' { Add-Client }
            '2'   { Get-ClientList }
            '3.2' { Get-ClientList }
            '3'   { Edit-Client }
            '3.3' { Edit-Client }
            '4'   { Remove-Client }
            '3.4' { Remove-Client }
            '5'   { Toggle-Client }
            '3.5' { Toggle-Client }
            '6' {
                Show-Section (t 'Срок действия' 'Expiry')
                Write-Host "  1) $(t 'Установить срок' 'Set expiry')"
                Write-Host "  2) $(t 'Продлить срок' 'Extend expiry')"
                Write-Host "  3) $(t 'Сбросить срок (бессрочно)' 'Reset expiry (never)')"
                Write-Host "  4) $(t 'Показать истекающие / истёкшие' 'Show expiring / expired')"
                Write-Host "  5) $(t 'Автопроверка (Планировщик задач)' 'Auto-check (Task Scheduler)')"
                $ech = Read-Value (t 'Выбор' 'Choice') ''
                switch ($ech) {
                    '1' { Set-ClientExpiry }
                    '2' { Extend-ClientExpiry }
                    '3' { Reset-ClientExpiry }
                    '4' { Show-Expiring }
                    '5' { Install-ExpiryCheck }
                }
            }
            '3.6' {
                Show-Section (t 'Срок действия' 'Expiry')
                Write-Host "  1) $(t 'Установить срок' 'Set expiry')"
                Write-Host "  2) $(t 'Продлить срок' 'Extend expiry')"
                Write-Host "  3) $(t 'Сбросить срок (бессрочно)' 'Reset expiry (never)')"
                Write-Host "  4) $(t 'Показать истекающие / истёкшие' 'Show expiring / expired')"
                Write-Host "  5) $(t 'Автопроверка (Планировщик задач)' 'Auto-check (Task Scheduler)')"
                $ech = Read-Value (t 'Выбор' 'Choice') ''
                switch ($ech) {
                    '1' { Set-ClientExpiry }
                    '2' { Extend-ClientExpiry }
                    '3' { Reset-ClientExpiry }
                    '4' { Show-Expiring }
                    '5' { Install-ExpiryCheck }
                }
            }
            '7'   { Show-ClientConfig }
            '3.7' { Show-ClientConfig }
            { $_ -in @('8', '3.8') } { return }
        }
        if ($ch -in @('8', '3.8')) { return }
        Pause-Menu
    }
}

function Show-MonitorMenu {
    while ($true) {
        Show-Section (t 'Мониторинг и статистика' 'Monitoring and statistics')
        Write-Host "  4.1 $(t 'wg show (активные / молчащие / потерянные)' 'wg show (active / silent / lost)')"
        Write-Host "  4.2 $(t 'Трафик по клиентам' 'Traffic per client')"
        Write-Host "  4.3 $(t 'Состояние сервиса' 'Service status')"
        Write-Host "  4.4 $(t 'Ping всех пиров' 'Ping all peers')"
        Write-Host "  4.5 $(t 'Публичный ключ сервера' 'Server public key')"
        Write-Host "  4.6 $(t 'Внешний IP сервера' 'Server external IP')"
        Write-Host "  4.7 $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1'   { Show-WgStatus }
            '4.1' { Show-WgStatus }
            '2'   { Show-Traffic }
            '4.2' { Show-Traffic }
            '3'   { Show-ServiceStatus }
            '4.3' { Show-ServiceStatus }
            '4'   { Test-PeerPing }
            '4.4' { Test-PeerPing }
            '5'   { Get-ServerPublicKey }
            '4.5' { Get-ServerPublicKey }
            '6'   { Get-ServerExternalIp }
            '4.6' { Get-ServerExternalIp }
        }
        if ($ch -in @('7', '4.7')) { return }
        Pause-Menu
    }
}

function Show-ServiceMenu {
    while ($true) {
        Show-Section (t 'Управление сервисом' 'Service management')
        Write-Host "  5.1 $(t 'Запустить туннель' 'Start tunnel')"
        Write-Host "  5.2 $(t 'Остановить туннель' 'Stop tunnel')"
        Write-Host "  5.3 $(t 'Перезапустить туннель' 'Restart tunnel')"
        Write-Host "  5.4 $(t 'Включить автозапуск' 'Enable autostart')"
        Write-Host "  5.5 $(t 'Отключить автозапуск' 'Disable autostart')"
        Write-Host "  5.6 $(t 'Перезагрузить конфиг без разрыва' 'Reload config without downtime')"
        Write-Host "  5.7 $(t 'Показать журнал' 'Show log')"
        Write-Host "  5.8 $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1'   { Start-Tunnel }
            '5.1' { Start-Tunnel }
            '2'   { Stop-Tunnel }
            '5.2' { Stop-Tunnel }
            '3'   { Restart-Tunnel }
            '5.3' { Restart-Tunnel }
            '4'   { Set-TunnelAutostart -Enable $true }
            '5.4' { Set-TunnelAutostart -Enable $true }
            '5'   { Set-TunnelAutostart -Enable $false }
            '5.5' { Set-TunnelAutostart -Enable $false }
            '6'   { Update-TunnelConfig }
            '5.6' { Update-TunnelConfig }
            '7'   { Show-TunnelLog }
            '5.7' { Show-TunnelLog }
        }
        if ($ch -in @('8', '5.8')) { return }
        Pause-Menu
    }
}

function Show-ConfigMenu {
    while ($true) {
        Show-Section (t 'Редактирование конфигурации' 'Configuration')
        Write-Host "  6.1 $(t 'Открыть server.conf в блокноте' 'Open server.conf in notepad')"
        Write-Host "  6.2 $(t 'Проверить синтаксис' 'Check syntax')"
        Write-Host "  6.3 $(t 'Изменить внешний интерфейс' 'Change external interface')"
        Write-Host "  6.4 $(t 'Изменить порт' 'Change port')"
        Write-Host "  6.5 $(t 'Изменить VPN-подсеть' 'Change VPN subnet')"
        Write-Host "  6.6 $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1'   { Edit-ServerConfig }
            '6.1' { Edit-ServerConfig }
            '2'   { Test-ConfigSyntax }
            '6.2' { Test-ConfigSyntax }
            '3'   { Set-ExternalInterface }
            '6.3' { Set-ExternalInterface }
            '4'   { Set-ListenPort }
            '6.4' { Set-ListenPort }
            '5'   { Set-VpnSubnet }
            '6.5' { Set-VpnSubnet }
        }
        if ($ch -in @('6', '6.6')) { return }
        Pause-Menu
    }
}

function Show-RoutingMenu {
    while ($true) {
        Show-Section (t 'Маршрутизация' 'Routing')
        Write-Host "  7.1 $(t 'Доступ клиентов к LAN сервера' 'Client access to server LAN')"
        Write-Host "  7.2 $(t 'Доступ к LAN за клиентом' 'Access to LAN behind client')"
        Write-Host "  7.3 $(t 'Site-to-Site' 'Site-to-Site')"
        Write-Host "  7.4 $(t 'DNS' 'DNS')"
        Write-Host "  7.5 $(t 'Ограничение скорости (QoS)' 'Rate limiting (QoS)')"
        Write-Host "  7.6 $(t 'Split-tunnel' 'Split-tunnel')"
        Write-Host "  7.7 $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1'   { Set-LanAccess }
            '7.1' { Set-LanAccess }
            '2'   { Set-ClientLanAccess }
            '7.2' { Set-ClientLanAccess }
            '3'   { Set-SiteToSite }
            '7.3' { Set-SiteToSite }
            '4'   { Set-Dns }
            '7.4' { Set-Dns }
            '5'   { Set-RateLimit }
            '7.5' { Set-RateLimit }
            '6'   { Set-SplitTunnel }
            '7.6' { Set-SplitTunnel }
        }
        if ($ch -in @('7', '7.7')) { return }
        Pause-Menu
    }
}

function Show-SecurityMenu {
    while ($true) {
        Show-Section (t 'Безопасность' 'Security')
        Write-Host "  8.1 $(t 'Firewall (Windows Firewall)' 'Firewall (Windows Firewall)')"
        Write-Host "  8.2 $(t 'Ограничение по IP' 'IP restriction')"
        Write-Host "  8.3 $(t 'Аудит подключений' 'Connection audit')"
        Write-Host "  8.4 $(t 'Ротация ключей сервера' 'Rotate server keys')"
        Write-Host "  8.5 $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1'   { Set-Firewall }
            '8.1' { Set-Firewall }
            '2'   { Set-IpRestriction }
            '8.2' { Set-IpRestriction }
            '3'   { Show-ConnectionAudit }
            '8.3' { Show-ConnectionAudit }
            '4'   { Rotate-ServerKeys }
            '8.4' { Rotate-ServerKeys }
        }
        if ($ch -in @('5', '8.5')) { return }
        Pause-Menu
    }
}

function Show-BackupMenu {
    while ($true) {
        Show-Section (t 'Бэкап / Восстановление' 'Backup / Restore')
        Write-Host "  9.1 $(t 'Создать бэкап' 'Create backup')"
        Write-Host "  9.2 $(t 'Восстановить из бэкапа' 'Restore from backup')"
        Write-Host "  9.3 $(t 'Автобэкап по расписанию' 'Scheduled backup')"
        Write-Host "  9.4 $(t 'Список бэкапов' 'Backup list')"
        Write-Host "  9.5 $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1'   { New-WgBackup }
            '9.1' { New-WgBackup }
            '2'   { Restore-WgBackup }
            '9.2' { Restore-WgBackup }
            '3'   { Set-BackupSchedule }
            '9.3' { Set-BackupSchedule }
            '4'   { Get-WgBackupList }
            '9.4' { Get-WgBackupList }
        }
        if ($ch -in @('5', '9.5')) { return }
        Pause-Menu
    }
}

function Show-MaintenanceMenu {
    while ($true) {
        Show-Section (t 'Обслуживание' 'Maintenance')
        Write-Host "  10.1 $(t 'Очистить неактивных клиентов' 'Clean inactive clients')"
        Write-Host "  10.2 $(t 'Удалить истёкших' 'Remove expired')"
        Write-Host "  10.3 $(t 'Сбросить счётчики трафика' 'Reset traffic counters')"
        Write-Host "  10.4 $(t 'Перезагрузка компьютера' 'Reboot computer')"
        Write-Host "  10.5 $(t 'Диагностика проблем' 'Problem diagnostics')"
        Write-Host "  10.6 $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1'    { Remove-InactiveClients }
            '10.1' { Remove-InactiveClients }
            '2'    { Remove-ExpiredClients }
            '10.2' { Remove-ExpiredClients }
            '3'    { Reset-TrafficCounters }
            '10.3' { Reset-TrafficCounters }
            '4' {
                Write-WarningMsg (t 'Компьютер будет перезагружен' 'Computer will reboot')
                if (Confirm-Action (t 'Перезагрузить? (y/N): ' 'Reboot? (y/N): ')) {
                    Write-Log -Message 'Maintenance: reboot requested'
                    Restart-Computer -Force
                }
            }
            '10.4' {
                Write-WarningMsg (t 'Компьютер будет перезагружен' 'Computer will reboot')
                if (Confirm-Action (t 'Перезагрузить? (y/N): ' 'Reboot? (y/N): ')) {
                    Write-Log -Message 'Maintenance: reboot requested'
                    Restart-Computer -Force
                }
            }
            '5'    { Show-DiagnosticsMenu }
            '10.5' { Show-DiagnosticsMenu }
        }
        if ($ch -in @('6', '10.6')) { return }
        Pause-Menu
    }
}

function Show-DiagnosticsMenu {
    while ($true) {
        Show-Section (t 'Диагностика' 'Diagnostics')
        Write-Host "  11.1 $(t 'Проверить IP-форвардинг' 'Check IP forwarding')"
        Write-Host "  11.2 $(t 'Проверить NAT' 'Check NAT')"
        Write-Host "  11.3 $(t 'Проверить порт извне' 'Check external port')"
        Write-Host "  11.4 $(t 'Ping всех пиров' 'Ping all peers')"
        Write-Host "  11.5 $(t 'Проверка DNS' 'DNS check')"
        Write-Host "  11.6 $(t 'Собрать отчёт для поддержки' 'Collect support report')"
        Write-Host "  11.7 $(t 'Назад' 'Back')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1'    { Test-IpForwarding }
            '11.1' { Test-IpForwarding }
            '2'    { Test-Nat }
            '11.2' { Test-Nat }
            '3'    { Test-ExternalPort }
            '11.3' { Test-ExternalPort }
            '4'    { Test-PeerPing }
            '11.4' { Test-PeerPing }
            '5'    { Test-DnsThroughTunnel }
            '11.5' { Test-DnsThroughTunnel }
            '6'    { New-SupportReport }
            '11.6' { New-SupportReport }
        }
        if ($ch -in @('7', '11.7')) { return }
        Pause-Menu
    }
}

function Show-MainMenu {
    while ($true) {
        Write-Host ''
        if ($script:UseColor) {
            Write-Host ('=' * 50) -ForegroundColor Cyan
            Write-Host ("  wg-admin.ps1 v{0}" -f $script:AppVersion) -ForegroundColor Cyan
            Write-Host ("  {0}" -f (t 'WireGuard Hub-and-Spoke администратор (Windows)' 'WireGuard Hub-and-Spoke admin (Windows)')) -ForegroundColor Cyan
            Write-Host ('=' * 50) -ForegroundColor Cyan
        } else {
            Write-Host ('=' * 50)
            Write-Host ("  wg-admin.ps1 v{0}" -f $script:AppVersion)
            Write-Host ("  {0}" -f (t 'WireGuard Hub-and-Spoke администратор (Windows)' 'WireGuard Hub-and-Spoke admin (Windows)'))
            Write-Host ('=' * 50)
        }
        Write-Host "  1)  $(t 'Установка WireGuard' 'Install WireGuard')"
        Write-Host "  2)  $(t 'Инициализация сервера' 'Server initialization')"
        Write-Host "  3)  $(t 'Управление клиентами' 'Client management')"
        Write-Host "  4)  $(t 'Мониторинг и статистика' 'Monitoring and statistics')"
        Write-Host "  5)  $(t 'Управление сервисом' 'Service management')"
        Write-Host "  6)  $(t 'Редактирование конфигурации' 'Edit configuration')"
        Write-Host "  7)  $(t 'Маршрутизация' 'Routing')"
        Write-Host "  8)  $(t 'Безопасность' 'Security')"
        Write-Host "  9)  $(t 'Бэкап / Восстановление' 'Backup / Restore')"
        Write-Host "  10) $(t 'Обслуживание' 'Maintenance')"
        Write-Host "  11) $(t 'Диагностика' 'Diagnostics')"
        Write-Host "  12) $(t 'Настройки скрипта' 'Script settings')"
        Write-Host "  13) $(t 'Удаление WireGuard' 'Uninstall WireGuard')"
        Write-Host "  14) $(t 'О скрипте' 'About')"
        Write-Host "  0)  $(t 'Выход' 'Exit')"
        $ch = Read-Value (t 'Выбор' 'Choice') ''
        switch ($ch) {
            '1' {
                Show-Section (t 'Установка' 'Install')
                Write-Host "  1) $(t 'Установить компоненты' 'Install components')"
                Write-Host "  2) $(t 'Проверить установленные компоненты' 'Check installed components')"
                Write-Host "  3) $(t 'Обновить WireGuard' 'Update WireGuard')"
                Write-Host "  4) $(t 'Назад' 'Back')"
                $ich = Read-Value (t 'Выбор' 'Choice') ''
                switch ($ich) {
                    '1' { Install-WireGuard }
                    '2' { Test-WireGuardInstalled }
                    '3' { Update-WireGuard }
                }
            }
            '2'  { Initialize-Server }
            '3'  { Show-ClientsMenu }
            '4'  { Show-MonitorMenu }
            '5'  { Show-ServiceMenu }
            '6'  { Show-ConfigMenu }
            '7'  { Show-RoutingMenu }
            '8'  { Show-SecurityMenu }
            '9'  { Show-BackupMenu }
            '10' { Show-MaintenanceMenu }
            '11' { Show-DiagnosticsMenu }
            '12' { Show-SettingsMenu }
            '13' {
                Uninstall-Wg
                Pause-Menu
            }
            '14' { Show-AboutMenu }
            '0'  {
                Write-Info (t 'Выход' 'Exit')
                Write-Log -Message 'exit'
                exit 0
            }
            default {
                Write-WarningMsg (t "Неизвестный пункт: $ch" "Unknown choice: $ch")
            }
        }
        if ($ch -ne '13') { Pause-Menu }
    }
}

# ==================== ТОЧКА ВХОДА ====================

if ($Help) {
    Write-Host "wg-admin.ps1 v$($script:AppVersion) — $(t 'управление WireGuard (Hub-and-Spoke) для Windows' 'WireGuard admin (Hub-and-Spoke) for Windows')"
    Write-Host (t 'Запуск: powershell -ExecutionPolicy Bypass -File wg-admin.ps1' 'Run: powershell -ExecutionPolicy Bypass -File wg-admin.ps1')
    Write-Host (t 'ОС: Windows 10/11, Server 2016+. Требуются права Администратора.' 'OS: Windows 10/11, Server 2016+. Administrator rights required.')
    exit 0
}
if ($Version) {
    Write-Host $script:AppVersion
    exit 0
}

# Запуск только при прямом вызове (не при dot-source — для тестов)
if ($MyInvocation.InvocationName -ne '.') {
if (-not (Test-IsAdministrator)) {
    Exit-WithError (t 'Скрипт должен запускаться от имени Администратора' 'Script must be run as Administrator')
}

Load-Settings
# включить цвета только в консоли
if (-not [Console]::IsOutputRedirected) {
    # оставить как есть
} else {
    $script:UseColor = $false
}

if (-not (Test-Path $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
}
Write-Log -Message "Script started v$($script:AppVersion)"
Show-MainMenu
}

# ==================== ИСПОЛЬЗОВАНИЕ ====================
#
# Установка и первый запуск:
#   1. Установите WireGuard для Windows (пункт меню 1 или вручную с wireguard.com)
#   2. powershell -ExecutionPolicy Bypass -File wg-admin.ps1  (от Администратора)
#   3. → [2] Инициализация сервера (подсеть, порт, ключи, NAT, Firewall)
#   4. → [3] Управление клиентами → Добавить клиента
#
# Конфиги: C:\ProgramData\wg-admin\server.conf, clients\*.conf
# Лог:     C:\ProgramData\wg-admin\logs\wg-admin.log
# Проверка синтаксиса: powershell -NoProfile -Command "Get-Command -Syntax .\wg-admin.ps1"
#
# Поддерживаемые ОС: Windows 10/11, Server 2016+ (x64/arm64)
# Требования: PowerShell 5.1+, WireGuard для Windows, права Администратора.
# Лицензия: MIT.




