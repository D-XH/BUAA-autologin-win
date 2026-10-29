#requires -Version 5.1
# 抓取北航网关登录页与其 JS，核对 srun3000 算法参数（需连接校园网时运行）
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
$ErrorActionPreference = 'Continue'

function Fetch([string]$u) {
    try { return (Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 12).Content }
    catch { return "ERR: $($_.Exception.Message)" }
}

$page = Fetch 'https://gw.buaa.edu.cn/srun_portal_pc?ac_id=78&theme=buaa'
"=== PAGE length=$($page.Length) ==="

$jsUrls = [regex]::Matches($page, 'src="([^"]+\.js[^"]*)"') |
          ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
"=== JS URLS ==="
$jsUrls

foreach ($j in $jsUrls) {
    if ($j -match 'jquery|bootstrap|vue|react|layer|swiper|echarts') { continue }
    $u = if ($j -match '^https?://') { $j }
         elseif ($j.StartsWith('/')) { "https://gw.buaa.edu.cn$j" }
         else { "https://gw.buaa.edu.cn/$j" }
    $c = Fetch $u
    "=== JS $u length=$($c.Length) ==="
    foreach ($pat in 'srun_bx1', 'LVoJPiCN2R8G90yg', 'get_challenge', '"?200"?', 'enc_ver', 'double_stack', 'SRBX1') {
        $mm = [regex]::Matches($c, ".{0,50}$pat.{0,70}") | Select-Object -First 2
        foreach ($x in $mm) { "  [$pat] $($x.Value -replace "`r?`n", ' ')" }
    }
}

$ch = Fetch 'https://gw.buaa.edu.cn/cgi-bin/get_challenge?callback=cb&username=test&ip='
"=== get_challenge sample ==="
$ch.Substring(0, [Math]::Min(400, $ch.Length))

$ri = Fetch 'https://gw.buaa.edu.cn/cgi-bin/rad_user_info?callback=cb&_=1'
"=== rad_user_info sample ==="
$ri.Substring(0, [Math]::Min(400, $ri.Length))
