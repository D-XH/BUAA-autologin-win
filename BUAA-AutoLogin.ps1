#requires -Version 5.1
<#
.SYNOPSIS
  北航校园网（srun3000，gw.buaa.edu.cn，ac_id=78）自动登录脚本。
.DESCRIPTION
  开机登录或网络连接时由计划任务调用：
  1. 等待网关可达（不在校园网时安静退出）；
  2. 检测是否已在线，已在线则退出；
  3. 通过 get_challenge 获取 token，按 srun3000 协议加密后发起登录；
  4. 登录后验证互联网连通性，全部过程写入 login.log。
  凭据来自同目录 config.json（用户名）与 password.sec（DPAPI 加密的密码），
  由 Install-BUAA-AutoLogin.ps1 生成。
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$PasswordFile,
    [int]$WaitSeconds  = 180,
    [int]$MaxAttempts  = 5,
    [switch]$SelfTest,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# 注意：param() 默认值里不能用 $PSScriptRoot（经 powershell.exe -File 冷启动时为空），
# 改为在脚本体内通过 $MyInvocation.MyCommand.Path 获取脚本目录。
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
if (-not $ConfigPath)   { $ConfigPath   = Join-Path $scriptDir 'config.json' }
if (-not $PasswordFile) { $PasswordFile = Join-Path $scriptDir 'password.sec' }

$script:LogFile = Join-Path $scriptDir 'login.log'

# ---------------- 日志 ----------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch {}
}

# ---------------- srun3000 加密原语 ----------------
function ConvertTo-U32 {
    param([int64]$x)
    return [uint32]($x -band 4294967295)
}

function ConvertFrom-UShr {
    param([uint32]$x, [int]$n)
    return [uint32][math]::Floor($x / [math]::Pow(2, $n))
}

function ConvertTo-UInt32Array {
    param([string]$Str, [bool]$AppendLength)
    $len   = $Str.Length
    $count = [int][math]::Ceiling($len / 4)
    if ($count -lt 1) { $count = 1 }
    $v = New-Object 'uint32[]' $count
    for ($i = 0; $i -lt $count; $i++) {
        $b0 = 0; $b1 = 0; $b2 = 0; $b3 = 0
        if (($i * 4)     -lt $len) { $b0 = [int][char]$Str[$i * 4] }
        if (($i * 4 + 1) -lt $len) { $b1 = [int][char]$Str[$i * 4 + 1] }
        if (($i * 4 + 2) -lt $len) { $b2 = [int][char]$Str[$i * 4 + 2] }
        if (($i * 4 + 3) -lt $len) { $b3 = [int][char]$Str[$i * 4 + 3] }
        $v[$i] = ConvertTo-U32 (($b3 -shl 24) -bor ($b2 -shl 16) -bor ($b1 -shl 8) -bor $b0)
    }
    if ($AppendLength) {
        $v2 = New-Object 'uint32[]' ($v.Length + 1)
        [Array]::Copy($v, $v2, $v.Length)
        $v2[$v.Length] = [uint32]$len
        return ,$v2
    }
    return ,$v
}

function Invoke-XEncode {
    # srun3000 的 xencode（XXTEA 变体），输入字符串，输出字节数组
    param([string]$Msg, [string]$Key)
    if ([string]::IsNullOrEmpty($Msg)) { return ,([byte[]]@()) }
    [uint32[]]$v = ConvertTo-UInt32Array -Str $Msg -AppendLength $true
    [uint32[]]$k = ConvertTo-UInt32Array -Str $Key -AppendLength $false
    if ($k.Length -lt 4) {
        $k2 = New-Object 'uint32[]' 4
        [Array]::Copy($k, $k2, $k.Length)
        $k = $k2
    }
    $n = $v.Length - 1
    [uint32]$z = $v[$n]
    [uint32]$y = 0
    [uint32]$c = ConvertTo-U32 0x9E3779B9   # 0x86014019 -bor 0x183639A0
    $q = [int][math]::Floor(6 + 52 / ($n + 1))
    [uint32]$d = 0
    while ($q -gt 0) {
        $q--
        $d = ConvertTo-U32 ([int64]$d + $c)
        $e = [int](($d -shr 2) -band 3)
        $p = 0
        while ($p -lt $n) {
            $y = $v[$p + 1]
            [uint64]$m = (ConvertFrom-UShr $z 5) -bxor (ConvertTo-U32 ([uint64]$y -shl 2))
            $m = ($m + (((ConvertFrom-UShr $y 3) -bxor (ConvertTo-U32 ([uint64]$z -shl 4))) -bxor ($d -bxor $y))) -band 4294967295
            $m = ($m + ($k[($p -band 3) -bxor $e] -bxor $z)) -band 4294967295
            $v[$p] = [uint32](($v[$p] + $m) -band 4294967295)
            $z = $v[$p]
            $p++
        }
        $y = $v[0]
        [uint64]$m = (ConvertFrom-UShr $z 5) -bxor (ConvertTo-U32 ([uint64]$y -shl 2))
        $m = ($m + (((ConvertFrom-UShr $y 3) -bxor (ConvertTo-U32 ([uint64]$z -shl 4))) -bxor ($d -bxor $y))) -band 4294967295
        $m = ($m + ($k[($p -band 3) -bxor $e] -bxor $z)) -band 4294967295
        $v[$n] = [uint32](($v[$n] + $m) -band 4294967295)
        $z = $v[$n]
    }
    $bytes = New-Object 'byte[]' ($v.Length * 4)
    for ($i = 0; $i -lt $v.Length; $i++) {
        $bytes[$i * 4]     = [byte]($v[$i] -band 0xFF)
        $bytes[$i * 4 + 1] = [byte](($v[$i] -shr 8)  -band 0xFF)
        $bytes[$i * 4 + 2] = [byte](($v[$i] -shr 16) -band 0xFF)
        $bytes[$i * 4 + 3] = [byte](($v[$i] -shr 24) -band 0xFF)
    }
    return ,$bytes
}

function ConvertTo-SrunBase64 {
    # 标准 base64 后按 srun 自定义字母表替换字符
    param([byte[]]$Bytes)
    $std = [Convert]::ToBase64String($Bytes)
    $alphaStd  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    $alphaSrun = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $std.ToCharArray()) {
        $idx = $alphaStd.IndexOf($ch)
        if ($idx -ge 0) { [void]$sb.Append($alphaSrun[$idx]) } else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

function Get-HmacMd5Hex {
    param([string]$Key, [string]$Data)
    $h = New-Object System.Security.Cryptography.HMACMD5
    $h.Key = [Text.Encoding]::ASCII.GetBytes($Key)
    $hash = $h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))
    return ([BitConverter]::ToString($hash) -replace '-', '').ToLower()
}

function Get-Sha1Hex {
    param([string]$Data)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))
    return ([BitConverter]::ToString($hash) -replace '-', '').ToLower()
}

function ConvertTo-JsonEscaped {
    param([string]$s)
    $s = $s -replace '\\', '\\'
    $s = $s -replace '"', '\"'
    $s = $s -replace "`r", '\r' -replace "`n", '\n' -replace "`t", '\t'
    return $s
}

# ---------------- 网络检测 ----------------
function Test-GatewayReachable {
    param([string]$Gw)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($Gw, 443, $null, $null)
        $ok  = $iar.AsyncWaitHandle.WaitOne(3000)
        if ($ok -and $tcp.Connected) { $tcp.Close(); return $true }
        $tcp.Close()
    } catch {}
    return $false
}

function Test-InternetOnline {
    try {
        $r = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 8
        return ($r.Content.Trim() -eq 'Microsoft Connect Test')
    } catch { return $false }
}

function Test-PortalAuthenticated {
    param([string]$Gw)
    try {
        $url = "https://$Gw/cgi-bin/rad_user_info?callback=cb&_=$((Get-Date).Ticks)"
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 8
        if (($r.Content -match '"user_name"\s*:\s*"([^"]+)"') -and ($Matches[1].Length -gt 0)) { return $true }
    } catch {}
    return $false
}

function Get-LocalIPv4 {
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                 Sort-Object -Property RouteMetric, InterfaceMetric | Select-Object -First 1
        if ($route) {
            $addr = Get-NetIPAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv4 -ErrorAction Stop |
                    Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
            if ($addr) { return $addr.IPAddress }
        }
    } catch {}
    return ''
}

# ---------------- srun3000 登录 ----------------
function Get-InfoJson {
    param([string]$Username, [string]$Password, [string]$IP, [string]$AcId)
    return '{{"username":"{0}","password":"{1}","ip":"{2}","acid":"{3}","enc_ver":"srun_bx1"}}' -f `
        (ConvertTo-JsonEscaped $Username), (ConvertTo-JsonEscaped $Password), (ConvertTo-JsonEscaped $IP), (ConvertTo-JsonEscaped $AcId)
}

function Get-SrunChallenge {
    param([string]$Gw, [string]$Username, [string]$IP)
    $url = "https://$Gw/cgi-bin/get_challenge?callback=jQuery&username=$([uri]::EscapeDataString($Username))&ip=$([uri]::EscapeDataString($IP))&_=$((Get-Date).Ticks)"
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
    $token = ''; $clientIp = ''
    if ($r.Content -match '"challenge"\s*:\s*"([0-9a-fA-F]+)"') { $token = $Matches[1] }
    if ($r.Content -match '"client_ip"\s*:\s*"([0-9.]+)"')     { $clientIp = $Matches[1] }
    if (-not $token) { throw "未能获取 challenge，网关返回：$($r.Content)" }
    return @{ Token = $token; ClientIP = $clientIp }
}

function Invoke-SrunLogin {
    param([string]$Gw, [string]$Username, [string]$Password, [string]$IP, [string]$Token, [string]$AcId)
    $infoJson  = Get-InfoJson -Username $Username -Password $Password -IP $IP -AcId $AcId
    $xBytes    = Invoke-XEncode -Msg $infoJson -Key $Token
    $hmac      = Get-HmacMd5Hex -Key $Token -Data $Password
    $pwdParam  = '{MD5}' + $hmac
    # 官方 Portal.js：chksum 中的 i 是 '{SRBX1}'+base64(xencode(...)) 完整字符串（见 _encodeUserInfo），
    # 不是 xencode 原始字节；同时官方请求还带 nas_ip（直连时为空）。
    $infoParam = '{SRBX1}' + (ConvertTo-SrunBase64 -Bytes $xBytes)
    $chkstr    = $Token + $Username + $Token + $hmac + $Token + $AcId + $Token + $IP + `
                 $Token + '200' + $Token + '1' + $Token + $infoParam
    $chksum    = Get-Sha1Hex -Data $chkstr
    # 注意：不要在 @(...) 数组字面量里写 'a=' + $x 再 -join，
    # 逗号与方法调用/`+` 的优先级会把参数名和值拆成独立元素，改用逐行追加。
    $qs  = 'callback=jQuery'
    $qs += '&action=login'
    $qs += '&username='     + [uri]::EscapeDataString($Username)
    $qs += '&password='     + [uri]::EscapeDataString($pwdParam)
    $qs += '&os='           + [uri]::EscapeDataString('Windows 10')
    $qs += '&name=Windows'
    $qs += '&nas_ip='
    $qs += '&double_stack=0'
    $qs += '&chksum='       + $chksum
    $qs += '&info='         + [uri]::EscapeDataString($infoParam)
    $qs += '&ac_id='        + [uri]::EscapeDataString($AcId)
    $qs += '&ip='           + [uri]::EscapeDataString($IP)
    $qs += '&n=200'
    $qs += '&type=1'
    $qs += '&_='            + [string](Get-Date).Ticks
    $url = "https://$Gw/cgi-bin/srun_portal?$qs"
    Write-Log "请求URL: $url"
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
    return $r.Content
}

# ---------------- 自检（与 tests/srun_ref.py 输出对比） ----------------
function Invoke-SelfTest {
    $u = 'test_user'; $p = 'P@ss w0rd!'; $ipT = '10.20.30.40'; $ac = '78'
    $tk = '0123456789abcdef0123456789abcdef'
    $infoJson = Get-InfoJson -Username $u -Password $p -IP $ipT -AcId $ac
    $xb  = Invoke-XEncode -Msg $infoJson -Key $tk
    $ip2 = '{SRBX1}' + (ConvertTo-SrunBase64 -Bytes $xb)
    $hm  = Get-HmacMd5Hex -Key $tk -Data $p
    $ck  = $tk + $u + $tk + $hm + $tk + $ac + $tk + $ipT + $tk + '200' + $tk + '1' + $tk + $ip2
    Write-Output "hmac=$hm"
    Write-Output "chksum=$(Get-Sha1Hex -Data $ck)"
    Write-Output "info_b64=$(ConvertTo-SrunBase64 -Bytes $xb)"
    Write-Output "info_json=$infoJson"
}

# ---------------- 主流程 ----------------
function Invoke-Main {
    try {
        if ((Test-Path $script:LogFile) -and ((Get-Item $script:LogFile).Length -gt 512KB)) {
            Move-Item $script:LogFile ($script:LogFile -replace '\.log$', '.old.log') -Force
        }
    } catch {}
    Write-Log '===== 启动自动登录 ====='

    if (-not (Test-Path $ConfigPath))   { Write-Log "缺少配置文件 $ConfigPath，请先运行 Install-BUAA-AutoLogin.ps1" 'ERROR'; exit 2 }
    if (-not (Test-Path $PasswordFile)) { Write-Log "缺少密码文件 $PasswordFile，请先运行 Install-BUAA-AutoLogin.ps1" 'ERROR'; exit 2 }

    $cfg      = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $gw       = if ($cfg.gw)   { [string]$cfg.gw }   else { 'gw.buaa.edu.cn' }
    $acid     = if ($cfg.acid) { [string]$cfg.acid } else { '78' }
    $username = [string]$cfg.username
    if (-not $username) { Write-Log 'config.json 中 username 为空' 'ERROR'; exit 2 }

    $sec   = (Get-Content $PasswordFile -Raw).Trim() | ConvertTo-SecureString
    $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

    # 1. 等待网关可达（最多 WaitSeconds 秒；不在校园网则安静退出）
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $reachable = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-GatewayReachable $gw) { $reachable = $true; break }
        Start-Sleep -Seconds 5
    }
    if (-not $reachable) { Write-Log "等待 $WaitSeconds 秒后仍无法连接 $gw（可能不在校园网），退出"; exit 0 }
    Write-Log "网关 $gw 可达"

    # 2. 已在线则直接退出（-Force 时跳过检测，强制执行完整认证流程，用于测试）
    if (-not $Force) {
        if (Test-PortalAuthenticated $gw) { Write-Log '检测到已在线，无需登录'; exit 0 }
        if (Test-InternetOnline)          { Write-Log '互联网连接正常，无需登录'; exit 0 }
    }

    # 3. 登录（带重试）
    $ip = Get-LocalIPv4
    Write-Log "本机 IPv4=$ip，开始登录（账号 $username）"
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $ch    = Get-SrunChallenge -Gw $gw -Username $username -IP $ip
            $token = $ch.Token
            $ipUse = if ($ch.ClientIP) { $ch.ClientIP } else { $ip }
            Write-Log "第 $attempt 次尝试：challenge 获取成功，客户端 IP=$ipUse"
            $resp = Invoke-SrunLogin -Gw $gw -Username $username -Password $password -IP $ipUse -Token $token -AcId $acid
            if (($resp -match '"error"\s*:\s*"ok"') -or ($resp -match 'IP has been online')) {
                Write-Log "网关返回登录成功"
                Start-Sleep -Seconds 3
                if (Test-InternetOnline) { Write-Log '联网验证通过，完成'; exit 0 }
                Write-Log '网关返回成功，但联网验证未通过' 'WARN'
                exit 0
            }
            Write-Log "登录失败，网关返回：$resp" 'WARN'
        } catch {
            Write-Log "第 $attempt 次尝试异常：$($_.Exception.Message)" 'WARN'
        }
        Start-Sleep -Seconds 10
    }
    Write-Log "重试 $MaxAttempts 次后仍未登录成功，请查看上方错误信息" 'ERROR'
    exit 1
}

if ($SelfTest) { Invoke-SelfTest; exit 0 }
Invoke-Main
