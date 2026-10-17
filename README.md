# Atomic Reforge

### 形态不同、本质相同的 Atomic Red Team 变体，用于授权范围内的 EDR 覆盖测评。

`atomic-reforge` 读取 MITRE [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) 的原子测试，在**不改变 TTP 分类与攻击意图**的前提下，对实现方式与执行过程做适度变形，生成一批可实机运行的变体。用这些变体检查检测规则能否覆盖同一 Technique 的多种落地形态，而不仅是上游那一种固定写法。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

> [!IMPORTANT]
> 仅用于授权范围内的攻防演练、EDR 能力评估与检测规则验证。请勿将产出的变体用于未授权环境。本项目与 MITRE / Atomic Red Team 无隶属或背书关系。

---

## Why Atomic Reforge?

- **意图不变。** 变体始终对应原测试的 Tactic / Technique（含子技术）以及要模拟的恶意行为。变形只发生在「怎么执行」，不改「在做什么」。
- **覆盖形态，而不只是原文。** 编码、混淆、宿主进程、包装、参数化、二进制改名等策略扰动静态特征，用来压测规则是否过拟合某一种写法。
- **可追溯。** 每个变体带新的 GUID，`name` 追加 `- reforge/<tag>`，description 记录 Source GUID 与策略标签。
- **面向断网测评。** `release` 打出自包含离线包（可选便携 Python 与 `run_offline.bat`）。远程脚本默认预取到本地缓存，再改写成读 `PathToAtomicsFolder`。
- **可实机复现。** 每个变体可独立运行，产生与原技术一致的可观测行为，便于对照遥测与告警。

---

## Scope

当前流水线面向：

| | |
| --- | --- |
| 平台 | Windows |
| 执行器 | `powershell`、`command_prompt` |

后续可扩展到 Linux / macOS 以及 `sh` / `bash` / `manual`。

变形允许改动的范围：载体、编码、包装、混淆、执行上下文、参数化、进程宿主、载荷落地形态。不允许改核心攻击逻辑，也不允许引入原测试之外的攻击意图。

---

## Quick start

### 1. Install

需要 **Python 3.9+**。推荐 [uv](https://docs.astral.sh/uv/)：

```bash
uv sync
```

或：

```bash
pip install -e .
pip install -e ".[dev]"
```

入口：`atomic-reforge` / `python -m atomic_reforge.cli`。

### 2. 准备上游 Atomic Red Team

变形依赖本地 ART 树（schema 单一来源，不进 Git）：

```text
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git ref/atomic-red-team-master
```

说明见 [`ref/README.md`](ref/README.md)。

### 3. 列出范围并生成变体

```bash
atomic-reforge list --platform windows --executor powershell

atomic-reforge generate T1059.001 --out outputs/variants --scripts outputs/scripts

atomic-reforge generate T1059.001 \
  --strategies identity/original,obfuscation/char_concat,obfuscation/string_reverse,encoding/base64,encoding/hex,host_swap/powershell_alt,host_swap/cmd_alt,wrapper/noop,parameterize/constant,binary/rename \
  --out outputs/variants

atomic-reforge report --path outputs/variants --format md --output outputs/report.md
```

> [!NOTE]
> `generate` 写入 `outputs/variants/`。`release` **不会读取**该目录，而是按所选 Technique ID 重新变形并写入离线包内的 `variants/`。

Schema 与 `#{arg}` 平衡在加载和生成时由上游 Pydantic 模型校验，没有独立的 `parse` / `validate` 子命令。

---

## CLI

| 命令 | 作用 |
| --- | --- |
| `list` | 按 platform / executor 列出范围内的技术与原子测试 |
| `generate` | 生成变体 YAML 与解析后的脚本 |
| `report` | 生成《变体-检测对照表》（md / csv） |
| `release` | 构建离线包（内部重新生成变体） |
| `run` | 调度执行（默认 dry-run；加 `--execute` 才实跑） |

```bash
python -m pytest tests/test_runtime.py tests/test_runner.py -q
```

---

## Strategies

| 家族 | 策略 | 说明 |
| --- | --- | --- |
| `identity` | `original` | 不变形：保留上游 Windows 测试原文。前置步骤里的工具 / ART 仓库下载改为 `PathToAtomicsFolder` 本地载荷；攻击本身就是外联的 URL 仍保留下载 |
| `obfuscation` | `char_concat` | 字符串拆成单字符后拼接 |
| `obfuscation` | `string_reverse` | 字符串反转，运行时再反转回来 |
| `encoding` | `base64` | Base64 编码 + 内联解码执行 |
| `encoding` | `hex` | Hex 编码 + 内联解码执行 |
| `host_swap` | `powershell_alt` / `cmd_alt` | 更换宿主（`powershell → pwsh`、`command_prompt → powershell` 内嵌 `cmd.exe /c`） |
| `wrapper` | `noop` | 用无害操作包裹核心载荷 |
| `parameterize` | `constant` | 把模板中的常量参数化为新的 `#{arg}` |
| `binary` | `rename` | 本地二进制改名（保留扩展名），默认指向 `PathToAtomicsFolder\payloads\<TID>\...` |
| `binary` | `package_extract` | 把二进制 base64 嵌入 YAML，运行时解压到 `%TEMP%`（体积大，精简发布建议排除） |

---

## Offline release

测评环境多数断网，且测评机往往没有预装 Python。`release` 把选定技术的变体、本地二进制（镜像到 `atomics/`，含 `reforge_remote` 缓存）和 SHA256 清单打成自包含目录；`--bundle-runtime` 还可带便携 Python 与 `run_offline.bat`。

Technique ID 按 **YAML 文件名精确匹配**（写 `T1055` 不会带上 `T1055.002`）。

### 联网机构建

```bash
atomic-reforge release T1059.001 T1055 T1047 \
  --strategies identity/original,obfuscation/char_concat,obfuscation/string_reverse,encoding/base64,encoding/hex,host_swap/powershell_alt,host_swap/cmd_alt,wrapper/noop,parameterize/constant,binary/rename \
  --bundle outputs/release_lite \
  --bundle-runtime \
  --archive zip
```

`--bundle-runtime` 优先使用：

- `ref/python-<当前解释器版本>-embed-amd64.zip`
- 或 `ref/python-3.13.3-embed-amd64.zip`

找不到时再尝试从 python.org 下载。也可用 `--runtime-dir` 指向已解压的 embed 根目录。

```
release_lite/
├── manifest.json
├── run_offline.bat            # --bundle-runtime 时生成
├── runtime/                   # 便携 Python
├── atomics/                   # 本地 payload
├── variants/<TID>/<变体>.yaml
└── scripts/<TID>/*.{ps1,bat}  # 展开 #{arg} 后的预览（非 run 必需）
```

`manifest.json` 的 `status`：`generated`、`bundled`、`embedded`、`remote_required`、`runtime`。

### 离线机执行

进入解压后的包根目录（与 `run_offline.bat`、`variants`、`manifest.json` 同级）：

```bat
run_offline.bat run T1059.001 --path variants --get-prereqs --check-integrity
run_offline.bat run all --path variants --get-prereqs --check-integrity
run_offline.bat run all --path variants --execute --get-prereqs --check-integrity
```

> [!WARNING]
> 已在包根时不要写 `--path release_lite\variants`（会变成找不到的嵌套路径）。`run` 发现 `--path` 为 `...\variants` 时，会把 `path_to_atomics` 设为同级 `atomics\`。

默认 dry-run；只有 `--execute` 才会真正拉起进程。`--check-integrity` 用父目录 `manifest.json` 校验哈希（失败 exit 2）。

未带 runtime 时，需本机已装 Python 与本项目：

```bash
atomic-reforge run T1059.001 --path /path/to/release_lite/variants --get-prereqs --check-integrity
atomic-reforge run T1059.001 --path /path/to/release_lite/variants --execute --get-prereqs --check-integrity
```

不加 `--allow-download` 时不联网；`bundled` / `embedded` 载荷本地存在则直接跑。需要补齐 `remote_required` 时再加 `--allow-download`。

执行日志写到 `C:\ProgramData\atomic_reforge_logs\`（无权限时回退到 `~/.atomic_reforge_logs`）：

- `run-<时间戳>.log` — 人类可读
- `run-<时间戳>.json` — JSON Lines

### 远程脚本本地化

生成变体前会扫描命令 / 参数默认值 / 依赖命令中的 `http(s)://` URL，下载到：

`atomics/ExternalPayloads/reforge_remote/<hash>/<filename>`

并把 `DownloadString('https://...')` 等改写为读取本地缓存。攻击意图不变，只把传输从远程改为本地。下载失败则保留原 URL。

构建机访问 GitHub 困难时，会尝试 `ghproxy` / `gitmirror` / `jsDelivr` 等镜像，也可自定义：

```bash
set ATOMIC_REFORGE_GITHUB_MIRROR=https://ghproxy.net/,https://mirror.ghproxy.com/
```

推荐先预取再发布：

```bash
uv run python scripts/prefetch_remote_payloads.py --list
uv run python scripts/prefetch_remote_payloads.py --list --tid T1059.001 --tid T1082
uv run python scripts/prefetch_remote_payloads.py --download
```

---

## Outputs

`generate` 默认产出：

- `outputs/variants/<TID>/` — 变体 YAML（新 GUID、`reforge/<tag>` 后缀、Source GUID）
- `outputs/scripts/<TID>/` — 解析后的 `.ps1` / `.bat` 预览
- `outputs/report.md`（或 `.csv`）— 《变体-检测对照表》

---

## Architecture

```
src/atomic_reforge/
├── cli.py          # Typer CLI
├── source.py       # 从 ref/ 导入上游 atomic_red_team 模型
├── transform.py    # 变换引擎：策略、变体、#{arg} 平衡
├── resolve.py      # #{arg} / PathToAtomicsFolder → 脚本预览
├── serializer.py   # 变体 YAML（literal 块）与脚本
├── report.py       # 对照表
├── payloads.py     # 二进制发现 / 拷贝 / SHA256
├── localize.py     # 远程 URL 预取与改写
├── runner.py       # 调度执行
├── result_log.py   # .log + JSON Lines
├── release.py      # 离线包 + manifest
├── runtime.py      # embeddable Python
└── strategies/     # 可插拔变形策略
```

上游 `atomic_red_team` 通过 `sys.path` 从 `ref/atomic-red-team-master/` 导入。

本机另有一套对照执行日志与 EDR 遥测/告警的 `eval/` 流水线，**不随本仓库发布**。若本机有该目录，说明见 [`eval/README.md`](eval/README.md)。

---

## Repository layout

| 路径 | 发布 | 说明 |
| --- | --- | --- |
| `src/atomic_reforge/` | 是 | 变形、release、run |
| `tests/` | 是 | pytest（不含本地 `test_eval.py`） |
| `scripts/` | 是 | 远程 payload 预取 |
| `pyproject.toml` / `LICENSE` | 是 | 工程元数据 |
| `eval/` | 否 | 本机 EDR 对照测评 |
| `ref/` | 否 | 上游 ART、embed Python、原始 EDR 日志 |
| `outputs/` | 否 | 生成物与离线包 |

---

## Attribution

本项目是独立的第三方工具，与 MITRE Corporation 及 [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) 无隶属或背书关系。

- Atomic Red Team 遵循其自身许可。解析并变形其测试数据时须遵守其署名要求。
- 本项目原创代码采用 [MIT License](LICENSE)。
- ATT&CK® 与 Atomic Red Team™ 相关标识均为其各自所有者的商标或财产。

## Disclaimer

产出的变体仅限授权场景下的防御性评估。使用者须自行确保操作均在合法授权范围内。作者与 MITRE / Atomic Red Team 对任何不当使用概不负责。
