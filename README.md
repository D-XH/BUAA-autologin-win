# 北航校园网自动登录（BUAA-AutoLogin）

> 仅供学习交流，请遵守学校网络管理规定，勿用于他人账号。凭据仅存于本机（DPAPI 加密），

解决：每次开机 Wi-Fi（BUAA-WiFi）已自动连接，但还要手动打开浏览器登录
`https://gw.buaa.edu.cn`（srun3000 网关，ac_id=78）的问题。

安装后，Windows 计划任务会在 **每次开机登录后** 和 **每次网络连接成功时**
自动运行登录脚本，无需再打开浏览器。不在校园网时脚本会自动安静退出。

## 文件

| 文件 | 说明 |
|---|---|
| `BUAA-AutoLogin.ps1` | 主脚本：检测在线状态 → 获取 challenge → 加密 → 登录 → 验证联网 |
| `Install-BUAA-AutoLogin.ps1` | 安装脚本：复制主脚本、录入凭据、注册计划任务 |
| `tests/srun_ref.py` | srun3000 加密算法 Python 参考实现 |
| `tests/probe-portal.ps1` | 抓取网关登录页 JS 核对算法参数（校园网内运行） |

## 安装（一次性，约 1 分钟）

1. 用资源管理器打开本文件夹；
2. 在空白处按住 `Shift` + 右键 → 「在此处打开 PowerShell 窗口」；
3. 执行：

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Install-BUAA-AutoLogin.ps1
   ```

4. 按提示输入一次校园网 **学号/工号** 和 **密码**（即登录 gw.buaa.edu.cn 用的密码）。

完成。之后每次开机、每次连上 Wi-Fi 都会自动登录。

## 安全性

- 密码经 **Windows DPAPI** 加密后保存在 `%USERPROFILE%\BUAA-AutoLogin\password.sec`，
  只有你这台电脑上的你这个账户能解密，换机器/换账户无法使用，脚本本身不含明文密码；
- 账号明文保存在同目录 `config.json`；
- 登录全程只与 `gw.buaa.edu.cn`（HTTPS）通信，脚本不开源外发任何数据，可放心审查。

## 验证 / 测试

- 安装时最后一步可直接试运行；
- 任何时候手动测试（比如在已连接 Wi-Fi 但未登录时）：

  ```powershell
  powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\BUAA-AutoLogin\BUAA-AutoLogin.ps1"
  ```

- 已在线也想验证完整认证流程（强制走一遍 challenge→加密→登录）：

  ```powershell
  powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\BUAA-AutoLogin\BUAA-AutoLogin.ps1" -Force
  ```

- 验证计划任务链路本身（模拟开机触发）：

  ```powershell
  Start-ScheduledTask -TaskName 'BUAA-AutoLogin'
  ```

- 运行日志：`%USERPROFILE%\BUAA-AutoLogin\login.log`（超过 512KB 自动滚动为 login.old.log）。

## 常见问题

- **改密码了怎么办**：重新运行一次安装脚本即可（会重新录入凭据）。
- **日志里出现 `E2532` / 账号或密码错误**：重新运行安装脚本录入正确密码。
- **日志里出现 `challenge_expire_error`**：偶发的 challenge 过期，脚本会自动重试，一般不用管。
- **在家里/其他网络下**：脚本检测不到 `gw.buaa.edu.cn` 会直接退出，不影响正常使用。
- **想临时停用**：`Disable-ScheduledTask -TaskName 'BUAA-AutoLogin'`；恢复用 `Enable-ScheduledTask`。

## 卸载

```powershell
Unregister-ScheduledTask -TaskName 'BUAA-AutoLogin' -Confirm:$false
Remove-Item -Recurse -Force "$env:USERPROFILE\BUAA-AutoLogin"
```

## 原理（简要）

北航网关是深澜 srun3000。登录流程：`GET /cgi-bin/get_challenge` 获取 token →
本地把 `{"username",...,"enc_ver":"srun_bx1"}` 用 xencode（XXTEA 变体，密钥为 token）加密，
密码用 HMAC-MD5（密钥为 token）计算，再拼固定串做 SHA-1 校验和，
最后 `GET /cgi-bin/srun_portal?action=login&...&info={SRBX1}<自定义base64>&chksum=<sha1>` 完成认证。
