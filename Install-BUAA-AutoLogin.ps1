#requires -Version 5.1
<#
.SYNOPSIS
  安装北航校园网自动登录：
  1. 把 BUAA-AutoLogin.ps1 复制到 %USERPROFILE%\BUAA-AutoLogin；
  2. 提示输入一次校园网账号密码，密码用 Windows DPAPI 加密保存（仅本机本用户可解密）；
  3. 注册计划任务：开机登录时、网络连接成功时各触发一次。
  使用方法：在 PowerShell 中执行
      powershell -ExecutionPolicy Bypass -File .\Install-BUAA-AutoLogin.ps1
  卸载：先运行  Unregister-ScheduledTask -TaskName 'BUAA-AutoLogin' -Confirm:$false
        再删除  %USERPROFILE%\BUAA-AutoLogin  文件夹。
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$taskName = 'BUAA-AutoLogin'
$dest = Join-Path $env:USERPROFILE 'BUAA-AutoLogin'

Write-Host '=== 北航校园网自动登录 安装 ===' -ForegroundColor Cyan
Write-Host ''

# 1. 复制主脚本
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot 'BUAA-AutoLogin.ps1') -Destination $dest -Force
Write-Host "[1/4] 脚本已安装到 $dest" -ForegroundColor Green

# 2. 录入凭据（用户名即学号/工号；密码用 DPAPI 加密后落盘）
Write-Host ''
Write-Host '请输入校园网账号和密码（用户名填学号/工号，密码即登录 gw.buaa.edu.cn 所用密码）：' -ForegroundColor Cyan
$cred = Get-Credential -Message '校园网账号'
$u = $cred.UserName
if ($u -match '\\') { $u = ($u -split '\\')[-1] }
$u = $u.Trim()
if (-not $u) { Write-Host '用户名不能为空，安装中止。' -ForegroundColor Red; exit 1 }
@{ username = $u; gw = 'gw.buaa.edu.cn'; acid = '78' } |
    ConvertTo-Json | Set-Content -Path (Join-Path $dest 'config.json') -Encoding UTF8
$cred.Password | ConvertFrom-SecureString |
    Set-Content -Path (Join-Path $dest 'password.sec') -Encoding ascii
Write-Host '[2/4] 凭据已加密保存（password.sec 只有本机当前用户能解密）' -ForegroundColor Green

# 3. 注册计划任务：登录时 + 网络连上时触发
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f (Join-Path $dest 'BUAA-AutoLogin.ps1')) `
    -WorkingDirectory $dest

$tLogon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$tLogon.Delay = 'PT15S'   # 登录后等 15 秒，给 Wi-Fi 自动连接留时间

$cls = Get-CimClass -ClassName 'MSFT_TaskEventTrigger' -Namespace 'Root/Microsoft/Windows/TaskScheduler'
$tNet = New-CimInstance -CimClass $cls -ClientOnly
$tNet.Enabled = $true
$tNet.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and (EventID=10000)]]</Select></Query></QueryList>"
$tNet.Delay = 'PT10S'     # 网络连接事件后等 10 秒

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($tLogon, $tNet) `
    -Settings $settings -Description '北航校园网 gw.buaa.edu.cn 自动登录（开机/连网时触发）' | Out-Null
Write-Host '[3/4] 计划任务已注册：开机登录后、每次连上网络时自动执行' -ForegroundColor Green

# 4. 可选：立即试运行
Write-Host ''
$run = Read-Host '[4/4] 是否现在试运行一次？（若已联网会提示无需登录）(y/N)'
if ($run -match '^[yY]') {
    Write-Host '正在试运行...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dest 'BUAA-AutoLogin.ps1')
    Write-Host "试运行结束，日志如下：" -ForegroundColor Cyan
    Get-Content (Join-Path $dest 'login.log') -Tail 12
}

Write-Host ''
Write-Host "安装完成。以后开机/连网时会自动登录校园网，日志在 $dest\login.log" -ForegroundColor Green
