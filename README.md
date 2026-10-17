# atomic-reforge（原子重铸）

`atomic-reforge` 是一个独立的第三方工具，读取 MITRE **atomic-red-team** 的原子测试（Atomic Tests），并在**不改变其 TTP 分类与攻击意图**的前提下，对每个 Atomic Test 的**实现方式与执行过程**做适度变形，生成一批"形态不同、本质相同"的变体。

这些变体用于更真实、更全面地测评 EDR/检测规则的覆盖能力——验证检测规则能否覆盖同一技战术（Technique/Tactic）的多种落地形态，而不仅是原始 atomic-red-team 那一种固定、可预测的载荷形态。

> **用途边界**：本项目仅用于**授权范围内的攻防演练、EDR 能力评估、检测规则验证等防御性/合规性场景**。请勿将本工具产出的变体用于未授权环境的真实攻击。

本仓库两块能力：

1. **atomic-reforge**：读取 Atomic Red Team，在 TTP 与攻击意图不变的前提下变形、离线打包、实机执行。
2. **eval**（仅本地，不进 Git）：对照执行日志与 EDR 遥测/告警，出「可见 / 检出 / 告警」测评报告。本机有 `eval/` 时可看 [`eval/README.md`](eval/README.md)。

## 仓库结构（提交范围）

| 路径 | 提交？ | 说明 |
| --- | --- | --- |
| `src/atomic_reforge/` | 是 | 变形、release、run |
| `tests/` | 是 | pytest（不含本地 `test_eval.py`） |
| `scripts/` | 是 | 远程 payload 预取 |
| `pyproject.toml` / `uv.lock` / `LICENSE` | 是 | 工程元数据 |
| `eval/` | **否** | EDR 对照测评代码、夹具、日志，仅本机保留 |
| `tests/test_eval.py` | **否** | eval 单测，跟 `eval/` 一起留在本机 |
| `ref/` | **否** | 上游 ART、embed Python、原始 EDR 日志，见 [`ref/README.md`](ref/README.md) |
| `outputs/` | **否** | release 包、测评 HTML/JSON（可达 GB） |

根目录已有 `.gitignore`。克隆后需自行放入 `ref/atomic-red-team-master/`，测评时用 `--telemetry` 指向本机 EDR 日志即可。

## 核心约束

1. **TTP 分类与攻击意图不变**：变体必须始终对应原 Atomic Test 所属的 ATT&CK 战术(Tactic)、技术(Technique, 含子技术)，以及原测试想要模拟的恶意行为意图。任何变形都不得改变"这段载荷到底在做什么攻击行为"。
2. **仅变形实现与执行过程**：允许在 payload 的载体、编码、包装、混淆、执行上下文、参数化方式、进程载体（如由 powershell.exe 换为其他宿主）、载荷落地形态等"如何执行"层面做变形；**不得**修改核心攻击逻辑、不得引入原测试之外的攻击意图。
3. **保持可实机运行、可复现**：每个变体必须能独立运行，产生与原技术一致的可观测行为（命令执行、凭据采集、持久化写入等），且行为可被检测规则观测。
4. **可追溯性**：每个变体可回溯到来源 Atomic Test（description 中记录 Source GUID + 变形策略标签；`name` 追加 `- reforge/<tag>`）。
5. **合法合规边界**：如上用途边界。本 README 声明本项目与 MITRE 及 atomic-red-team 为**独立的第三方关系**。

## 当前范围（首批流水线）

- **平台**：Windows
- **执行器（executor）**：`powershell` 与 `command_prompt`
- 后续可扩展到 Linux/macOS 及 `sh` / `bash` / `manual` 执行器。

## 变形策略

| 家族 family | 策略 tag | 说明 |
| --- | --- | --- |
| `identity` | `original` | 不变形：保留上游 Windows 测试原文。前置步骤里的工具 / 原子红队仓库下载改为 `PathToAtomicsFolder` 本地载荷；C2、外泄、工具传入等**攻击本身就是外联**的命令 URL 仍保留下载 |
| `obfuscation` | `char_concat` | 字符串拆分为单字符后拼接/连接，扰动静态字符串特征 |
| `obfuscation` | `string_reverse` | 字符串反转 + 运行时反转回来 |
| `encoding` | `base64` | Base64 编码 + 内联解码执行 |
| `encoding` | `hex` | Hex 编码 + 内联解码执行 |
| `host_swap` | `powershell_alt` / `cmd_alt` | 更换宿主进程/调用方式（`powershell → pwsh`、`command_prompt → powershell` 内嵌 `cmd.exe /c`） |
| `wrapper` | `noop` | 用无害操作包裹核心载荷，干扰静态特征匹配 |
| `parameterize` | `constant` | 把模板中的常量参数化为新的 `#{arg}` |
| `binary` | `rename` | 把本地二进制**改名**为随机文件名（保留扩展名）；默认指向 `PathToAtomicsFolder\payloads\<TID>\...` |
| `binary` | `package_extract` | 把本地二进制 **base64 嵌入** YAML，运行时解压到 `%TEMP%` 再执行（体积膨胀大，精简发布建议排除） |

## 安装

```bash
# 推荐：uv
uv sync
# 或
pip install -e .
pip install -e ".[dev]"
```

## CLI 命令

当前入口：`atomic-reforge` / `python -m atomic_reforge.cli`

| 命令 | 作用 |
| --- | --- |
| `list` | 按 platform / executor 列出范围内技术与原子测试 |
| `generate` | 生成变体 YAML + 解析后的脚本 |
| `report` | 生成《变体-检测对照表》（md/csv） |
| `release` | 构建离线包（内部重新生成变体，写入 bundle） |
| `run` | 调度执行变体（默认 dry-run；加 `--execute` 才实跑） |

> Schema / `#{arg}` 平衡在加载与生成时由上游 Pydantic 模型校验，**无独立的 `parse` / `validate` 子命令**。

## 快速开始

```bash
# 列出 windows + powershell 范围内的技术/原子测试
atomic-reforge list --platform windows --executor powershell

# 为单个技术生成变体（默认全策略）
atomic-reforge generate T1059.001 --out outputs/variants --scripts outputs/scripts

# 排除体积膨胀的 package_extract
atomic-reforge generate T1059.001 --strategies identity/original,obfuscation/char_concat,obfuscation/string_reverse,encoding/base64,encoding/hex,host_swap/powershell_alt,host_swap/cmd_alt,wrapper/noop,parameterize/constant,binary/rename --out outputs/variants

# 生成《变体-检测对照表》
atomic-reforge report --path outputs/variants --format md --output outputs/report.md
```

`generate` 写入 `outputs/variants/`；`release` **不会读取**该目录，而是按所选 TID **重新变形**并直接写入 bundle 内的 `variants/`。

## 测评（eval）

实机 `run --execute` 之后，用执行 JSONL 对照 EDR 的 `*_telemetry.log` / `*_alert.log`：

```text
python -m eval --atomic-logs C:\ProgramData\atomic_reforge_logs ^
               --telemetry <EDR日志目录> ^
               --out outputs\eval
```

三层不要混：`「可见」`（命令对上了）≠ 检出（Technique 对齐）≠ 告警（alert.log 工单）。夹具自测：

```text
python -m pytest tests/test_runtime.py tests/test_runner.py -q
# 本机有 eval/ 时：python -m pytest tests/test_eval.py -q
# python -m eval --atomic-logs eval/testdata/run-fixture.json --telemetry eval/testdata/telemetry.ndjson --out outputs/eval
```

完整口径、父技术开关、从 JSON 重渲 HTML：本机有 `eval/` 时见 [`eval/README.md`](eval/README.md)。

### 远程脚本本地化（全量默认开启）

生成变体前会扫描命令 / 参数默认值 / 依赖命令中的 `http(s)://` URL，在构建机下载到：

`atomics/ExternalPayloads/reforge_remote/<hash>/<filename>`

并把 `DownloadString('https://...')` 等改写为读取 `PathToAtomicsFolder\ExternalPayloads\reforge_remote\...`。  
若 URL 对应本地 ART 树或 `../ExternalPayloads` 里已有同内容文件，则**复用/硬链进该缓存**（同名同内容只保留一份）而不再联网。命令里的 `PathToAtomicsFolder\..\ExternalPayloads\...` 也会改写到同一缓存路径。  
**攻击意图不变**（仍加载并执行同一份脚本），仅把传输从远程改为本地，以便断网测评。下载失败则保留原 URL（该条仍需联网）。

构建机访问 GitHub 困难时，本地化下载会自动尝试中转/镜像（`ghproxy` / `gitmirror` / `jsDelivr` 等）。也可自定义：

```bash
# 逗号分隔的代理前缀，会拼在原始 https URL 前面
set ATOMIC_REFORGE_GITHUB_MIRROR=https://ghproxy.net/,https://mirror.ghproxy.com/
```

**推荐：提前下到 ref，发布时只复制**

```bash
# 生成清单 + 手动下载脚本（默认写到 ref/remote_prefetch/）
uv run python scripts/prefetch_remote_payloads.py --list

# 或按 TID 过滤后生成，再执行 download_manual.ps1 / .bat
uv run python scripts/prefetch_remote_payloads.py --list --tid T1059.001 --tid T1082

# 也可自动拉（走镜像）
uv run python scripts/prefetch_remote_payloads.py --download
```

文件统一落到 `atomics/ExternalPayloads/reforge_remote/<sha12>/`。清单里 `COPY_ART` 可本地复制、`MISSING` 需手下或 `--download`；缓存已有则 `generate`/`release` 不再联网。

## 离线发布（release）与断网测评

测评环境多数为**断网**，且测评机往往**没有预装 Python**。`release` 把选定技术的变体 + 本地二进制（镜像到 `atomics/`，含 `reforge_remote` 缓存）+ SHA256 清单打成自包含目录；加 `--bundle-runtime` 后还可带便携 Python 与 `run_offline.bat`。

### 一、联网机：构建 release 包

TID 按 **YAML 文件名精确匹配**（写 `T1055` 不会误带上 `T1055.002`；需要子技术请显式列出）。

```bash
# 指定若干技术 + 排除 package_extract + 便携运行时 + zip
atomic-reforge release T1059.001 T1055 T1047 \
  --strategies identity/original,obfuscation/char_concat,obfuscation/string_reverse,encoding/base64,encoding/hex,host_swap/powershell_alt,host_swap/cmd_alt,wrapper/noop,parameterize/constant,binary/rename \
  --bundle outputs/release_lite \
  --bundle-runtime \
  --archive zip
```

`--bundle-runtime` 优先使用仓库内预置的 embed 包（若存在）：

- `ref/python-<当前解释器版本>-embed-amd64.zip`
- 或 `ref/python-3.13.3-embed-amd64.zip`

找不到时再尝试从 python.org 下载。也可用 `--runtime-dir <已解压的 embed 根目录>` 复用。

产出目录结构：

```
release_lite/   # 或 outputs/release/
├── manifest.json              # SHA256 + size + 溯源 + status
├── run_offline.bat            # --bundle-runtime 时生成
├── runtime/                   # 便携 embeddable Python
├── atomics/                   # 镜像的本地 payload（含 payloads/<TID>/ 改名文件）
├── variants/<TID>/<变体>.yaml # 正式执行输入（run 读这个）
└── scripts/<TID>/*.{ps1,bat}  # 展开 #{arg} 后的预览脚本（非 run 必需）
```

`manifest.json` 条目 `status`：

- `generated` — 变体 YAML / 脚本
- `bundled` — 已随包携带的本地二进制
- `embedded` — base64 嵌在变体内（仅 `package_extract`）
- `remote_required` — 仍缺本地文件、需联网或手工补齐
- `runtime` — 便携运行时文件

### 二、离线机：用 run_offline.bat（推荐）

先进入**解压后的包根目录**（与 `run_offline.bat`、`variants`、`manifest.json` 同级），再执行。`--path` 指向包内的 `variants`：

```bat
:: 假设已 cd 到 release_lite 包根
run_offline.bat run T1059.001 --path variants --get-prereqs --check-integrity

:: 一次跑 variants 下全部技术（省略 TID 或写 all）
run_offline.bat run all --path variants --get-prereqs --check-integrity

:: 授权靶机上真实执行
run_offline.bat run all --path variants --execute --get-prereqs --check-integrity
```

若当前目录是仓库根或其它位置，应写绝对/相对完整路径，例如：

```bat
run_offline.bat run T1059.001 --path F:\path\to\release_lite\variants --get-prereqs --check-integrity
```

> **注意**：已在包根目录时不要写 `--path release_lite\variants`（会变成找不到的嵌套路径）。

`run` 发现 `--path` 为 `...\variants` 时，会自动把 `path_to_atomics` 设为同级的 `atomics\`，从而解析 `PathToAtomicsFolder\...`。

默认 dry-run；只有加 `--execute` 才会真正拉起进程。`--check-integrity` 用父目录的 `manifest.json` 校验哈希（失败 exit 2）。

### 三、离线机：未带 runtime 时

需本机已装 Python 与本项目：

```bash
atomic-reforge run T1059.001 --path /path/to/release_lite/variants --get-prereqs --check-integrity
atomic-reforge run T1059.001 --path /path/to/release_lite/variants --execute --get-prereqs --check-integrity
```

**本地优先**：不加 `--allow-download` 时不联网；`bundled`/`embedded` 载荷本地存在则直接跑。

### 四、允许联网补齐 remote_required

```bash
atomic-reforge run T1055 --path /path/to/release_lite/variants --get-prereqs --allow-download
```

### 五、测评日志

写到 `C:\ProgramData\atomic_reforge_logs\`（无权限时回退到用户目录下的 `.atomic_reforge_logs`）：

- `run-<时间戳>.log` — 人类可读
- `run-<时间戳>.json` — 按行 JSON（机器可解析）

## 输出（generate）

- `outputs/variants/<TID>/`：变体 YAML（新 GUID、`reforge/<tag>` 后缀、description 含 Source GUID）
- `outputs/scripts/<TID>/`：解析后的 `.ps1` / `.bat` 预览
- `outputs/report.md`（或 `.csv`）：《变体-检测对照表》

## 架构

```
src/atomic_reforge/
├── cli.py          # Typer CLI
├── source.py       # 从 ref/ 导入上游 atomic_red_team 模型，发现 atomics
├── transform.py    # 变换引擎：策略、变体、#{arg} 平衡
├── resolve.py      # #{arg} / PathToAtomicsFolder -> 脚本预览
├── serializer.py   # 输出变体 YAML（literal 块，避免路径被折行破坏）+ 脚本
├── report.py       # 对照表 (md/csv)
├── payloads.py     # 二进制发现/拷贝/SHA256
├── runner.py       # 调度执行（本地优先 + 日志）
├── result_log.py   # .log + JSON Lines
├── release.py      # 离线包 + manifest
├── runtime.py      # embeddable Python 组装（优先 ref/ 本地 zip）
└── strategies/     # 可插拔变形策略
```

上游 `atomic_red_team` 通过 `sys.path` 从 `ref/atomic-red-team-master/` 导入，保持 schema 单一来源。

## 与 MITRE / atomic-red-team 的关系及许可

本项目为**独立的第三方工具**，与 MITRE Corporation 及 [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) 无隶属或背书关系。

- `atomic-red-team` 遵循其自身许可（`ref/atomic-red-team-master/LICENSE.txt`）。本项目解析并变形其测试数据，使用时须遵守其署名要求。
- 本项目的原创代码采用 **MIT License**（见根目录 `LICENSE`）。
- ATT&CK® 与 Atomic Red Team™ 相关标识均为其各自所有者的商标/财产。

## 建议提交到 Git 的命令

确认没有把 `ref/`、`outputs/`、`eval/` 加进去之后：

```text
git add .gitignore README.md LICENSE pyproject.toml uv.lock manual_download.md
git add src/atomic_reforge tests scripts
git status   # 不应出现 outputs/、ref/atomic-red-team、eval/、*.log
```

`prompt.txt` 是内部需求草稿，一般不必提交。

## 免责声明

本工具产出的变形变体与检测工具（EDR/杀软）对抗的相关内容，仅限授权场景下的防御性评估使用。使用者须自行确保其所有操作均在合法授权范围内。作者与 MITRE / atomic-red-team 对任何不当使用概不负责。
