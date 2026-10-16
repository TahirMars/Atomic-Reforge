# manual_download.md — ExternalPayloads 补齐说明

> 状态（2026-10）：对本仓库当前 Windows + powershell/command_prompt 范围内的
> Atomic Tests 做 payload 发现扫描时，**本地缺失引用为 0**（`bin/` 与
> `ExternalPayloads/` 已齐）。本文件保留为历史补齐清单与再次核对时的参考。

若重新同步上游 atomics 后出现缺失，可：

1. 将文件放到 `ref/atomic-red-team-master/atomics/` 下对应相对路径（或
   `ExternalPayloads/`）。
2. 再跑 release：`atomic-reforge release ... --bundle outputs/release`，确认
   `manifest.json` 中相关条目为 `bundled` 而非 `remote_required`。

## 历史清单（曾缺失、现多已就位）

根目录：`F:\AI\Atomic-Reforge`  
`AT` = `ref\atomic-red-team-master\atomics`  
`EP` = `ref\atomic-red-team-master\ExternalPayloads`（亦可能位于 `AT\ExternalPayloads`）

| 技术 | 文件名 | 落盘路径 | 下载源 / 说明 |
|---|---|---|---|
| T1555.003 | ChromeStandaloneSetup64.msi | `EP\ChromeStandaloneSetup64.msi` | https://dl.google.com/chrome/install/ChromeStandaloneSetup64.msi |
| T1555.003 | VS_BuildTools.exe | `EP\VS_BuildTools.exe` | https://aka.ms/vs/17/release/vs_BuildTools.exe |
| T1555.003 | FirefoxStubInstaller.exe | `EP\FirefoxStubInstaller.exe` | https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US |
| T1048 | dnsexfil.ps1 | `EP\dnsexfil.ps1` | https://www.darkoperator.com/scripts/DNSExfil.ps1 |
| T1110.002 | hashcat.exe | `EP\hashcat6\hashcat-6.1.1\hashcat.exe` | https://hashcat.net/files/hashcat-6.1.1.7z |
| T1550.003 | rubeus.exe | `EP\rubeus.exe` | https://github.com/GhostPack/Rubeus/releases |
| T1219 | GoToAssist.exe 等 | `EP\...` | 各远程协助客户端官网 |
| T1046 | rustscan.exe | `EP\rustscan.exe` | RustScan releases |
| T1040 | npcap_installer.exe | `EP\npcap_installer.exe` | https://npcap.com/dist/ |
| T1218 | svchost.exe | `EP\svchost.exe` | 自 `C:\Windows\System32\svchost.exe` 复制 |
| T1095 | ncat.exe | `EP\T1095\nmap-7.80\ncat.exe` | nmap win32 zip |
| T1539 | sqlite3.exe | `EP\sqlite-tools-...\sqlite3.exe` | sqlite.org |
| T1018 | netscan.zip | `EP\netscan.zip` | SoftPerfect |
| T1620 | Invoke-ReflectivePEInjection.ps1 | `EP\Powersploit\...` | PowerSploit |
| T1560.001 | winzip.exe | `EP\winzip.exe` | WinZip |
| T1482 | TruffleSnout.exe | `EP\TruffleSnout.exe` | GitHub releases |
| T1134.001 | NSudoLG.exe | `AT\T1134.001\bin\NSudoLG.exe` | NSudo releases |
| T1048.002 / T1105 | curl 多版本 | `EP\curl\...` | curl.se Windows builds |
| T1055.011 | payload.exe | `AT\T1055.011\bin\payload.exe` | 含 `#{arch}` 时按 x64 放置 |

## Release 离线约定

- 本地已有的二进制会镜像到 `release/atomics/`（保留相对路径）。
- `binary/rename` 产物在 `release/atomics/payloads/<TID>/`。
- 断网机执行时 CLI 会自动把 `path_to_atomics` 指到包内 `atomics/`。
- `remote_required` 条目仍需联网或手工补齐后才能实跑对应测试。
