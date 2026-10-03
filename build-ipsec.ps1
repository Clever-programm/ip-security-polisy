<#
.SYNOPSIS
    Собирает политику IPsec "блокировка сайтов" из текстового списка доменов
    и экспортирует её в файл .ipsec (тот же формат, что "Экспорт политик" в secpol.msc).

.DESCRIPTION
    Формат входного файла: по одной записи на строку.
      example.com              - домен (резолвится в IP в момент запуска)
      https://site.ru/page     - URL: схема, путь и порт отбрасываются
      мойгород.рус             - кириллические домены переводятся в punycode
      185.62.202.2             - одиночный IP
      10.20.0.0/16             - подсеть
      # комментарий            - всё после # игнорируется
    Всё после первого пробела в строке игнорируется ("aliexpress.ru NS1" -> aliexpress.ru).

    Запуск (от администратора):
      powershell -ExecutionPolicy Bypass -File .\build-ipsec.ps1 -InputFile .\domains.txt

    По умолчанию после экспорта политика удаляется из локального хранилища,
    чтобы скрипт не оставлял следов на машине. -KeepInStore оставляет её (не назначенной).
#>
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [string]$OutputFile       = ".\blok-ip-new.ipsec",
    [string]$PolicyName       = "Блокировка сайтов",
    [string]$Description      = "Блокирует указанные сайты по IP или адресам подсетей",
    [string]$FilterListName   = "Нежелательные сайты",
    [string]$FilterActionName = "Блокировка сайта",
    [string]$RuleName         = "Блокировка нежелательных сайтов",
    [switch]$KeepInStore
)

$ErrorActionPreference = 'Stop'

# --- Проверка прав администратора -----------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Нужно запустить от имени администратора." -ForegroundColor Red
    exit 1
}

function Invoke-Netsh {
    param([string[]]$NetshArgs)
    $out = & netsh.exe @NetshArgs 2>&1 | Out-String
    [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Output = $out.Trim() }
}

# --- Разбор входного файла -------------------------------------------------
$inPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputFile)
if (-not (Test-Path -LiteralPath $inPath)) {
    Write-Host "Файл не найден: $inPath" -ForegroundColor Red
    exit 1
}

$idn        = New-Object System.Globalization.IdnMapping
$reIp       = '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
$reCidr     = '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$'
$reDomain   = '^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$'

$entries = New-Object System.Collections.Generic.List[object]
$seen    = @{}
$invalid = New-Object System.Collections.Generic.List[string]

foreach ($raw in Get-Content -LiteralPath $inPath -Encoding UTF8) {
    $line = ($raw -replace '#.*$', '').Trim()
    if (-not $line) { continue }
    $line = ($line -split '\s+')[0]
    $line = $line -replace '^[a-zA-Z][a-zA-Z0-9+.-]*://', ''

    $addr = $null; $mask = $null

    if ($line -match $reCidr) {
        $addr = $Matches[1]; $mask = [int]$Matches[2]
        if ($mask -lt 1 -or $mask -gt 32) { $invalid.Add($raw); continue }
    }
    else {
        $line = $line -replace '[/?].*$', '' -replace ':\d+$', ''
        $line = $line.TrimEnd('.').ToLowerInvariant()
        if ($line -match $reIp) {
            if (($Matches[1..4] | Where-Object { [int]$_ -gt 255 })) { $invalid.Add($raw); continue }
            $addr = $line
        }
        else {
            try { $line = $idn.GetAscii($line) } catch { $invalid.Add($raw); continue }
            if ($line -notmatch $reDomain) { $invalid.Add($raw); continue }
            $addr = $line
        }
    }

    $key = "$addr/$mask"
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $entries.Add([pscustomobject]@{ Addr = $addr; Mask = $mask; Source = $raw.Trim() })
}

if ($entries.Count -eq 0) {
    Write-Host "В файле нет ни одной корректной записи." -ForegroundColor Red
    exit 1
}
Write-Host "Записей к добавлению: $($entries.Count) (некорректных строк: $($invalid.Count))"

# --- Удаляем старую версию политики с теми же именами (если есть) ----------
function Remove-OurPolicy {
    Invoke-Netsh @('ipsec','static','delete','policy',"name=$PolicyName") | Out-Null
    Invoke-Netsh @('ipsec','static','delete','filterlist',"name=$FilterListName") | Out-Null
    Invoke-Netsh @('ipsec','static','delete','filteraction',"name=$FilterActionName") | Out-Null
}
Remove-OurPolicy

# --- Создаём политику, список фильтров и действие --------------------------
$steps = @(
    @('ipsec','static','add','policy',"name=$PolicyName","description=$Description",'assign=no'),
    @('ipsec','static','add','filterlist',"name=$FilterListName"),
    @('ipsec','static','add','filteraction',"name=$FilterActionName",'action=block')
)
foreach ($s in $steps) {
    $r = Invoke-Netsh $s
    if (-not $r.Ok) {
        Write-Host "Ошибка: netsh $($s -join ' ')`n$($r.Output)" -ForegroundColor Red
        Remove-OurPolicy
        exit 1
    }
}

# --- Фильтры ---------------------------------------------------------------
$failed = New-Object System.Collections.Generic.List[string]
$i = 0
foreach ($e in $entries) {
    $i++
    Write-Progress -Activity "Добавление фильтров" -Status "$i / $($entries.Count): $($e.Addr)" `
                   -PercentComplete ([int](100 * $i / $entries.Count))

    $a = @('ipsec','static','add','filter',"filterlist=$FilterListName",
           'srcaddr=me',"dstaddr=$($e.Addr)",'protocol=any','mirrored=yes',
           "description=$($e.Source)")
    if ($null -ne $e.Mask) { $a += "dstmask=$($e.Mask)" }

    $r = Invoke-Netsh $a
    if (-not $r.Ok) { $failed.Add("$($e.Source)  ->  $($r.Output -replace '\s+', ' ')") }
}
Write-Progress -Activity "Добавление фильтров" -Completed

$added = $entries.Count - $failed.Count
if ($added -eq 0) {
    Write-Host "Ни один фильтр не добавлен (нет сети / DNS?)." -ForegroundColor Red
    Remove-OurPolicy
    exit 1
}

# --- Правило, связывающее список фильтров и действие ------------------------
$r = Invoke-Netsh @('ipsec','static','add','rule',"name=$RuleName","policy=$PolicyName",
                    "filterlist=$FilterListName","filteraction=$FilterActionName")
if (-not $r.Ok) {
    Write-Host "Ошибка при создании правила:`n$($r.Output)" -ForegroundColor Red
    Remove-OurPolicy
    exit 1
}

# --- Экспорт в .ipsec ------------------------------------------------------
$outFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
if ($outFull -notlike '*.ipsec') { $outFull += '.ipsec' }
$outDir = Split-Path -Parent $outFull
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
if (Test-Path -LiteralPath $outFull) { Remove-Item -LiteralPath $outFull -Force }

$base = $outFull.Substring(0, $outFull.Length - '.ipsec'.Length)   # netsh сам добавляет .ipsec
$r = Invoke-Netsh @('ipsec','static','exportpolicy',"file=$base")

if (-not $KeepInStore) { Remove-OurPolicy }

if (-not $r.Ok -or -not (Test-Path -LiteralPath $outFull)) {
    Write-Host "Экспорт не удался:`n$($r.Output)" -ForegroundColor Red
    exit 1
}

# --- Итог ------------------------------------------------------------------
Write-Host ""
Write-Host "Готово: $outFull" -ForegroundColor Green
Write-Host "Добавлено фильтров: $added из $($entries.Count)"
if ($invalid.Count) {
    Write-Host "`nПропущены некорректные строки:" -ForegroundColor Yellow
    $invalid | ForEach-Object { Write-Host "  $_" }
}
if ($failed.Count) {
    Write-Host "`nНе удалось добавить (обычно домен не резолвится):" -ForegroundColor Yellow
    $failed | ForEach-Object { Write-Host "  $_" }
}
