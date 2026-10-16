# NGES 遥测测评架构

本文档是 `eval/` 的实现规格。实现以代码为准；本文说明口径与目录约定。

测评对象是 EDR 产品 **NGES**。金标准来自 `atomic-reforge` 实机执行日志，对照物是 NGES 主机遥测 NDJSON。目标是判断每条 Atomic 是否真正跑起来，以及 NGES 是否**看见**行为、是否**标到对应 ATT&CK TTP**、是否出告警。

## 1. 原则

**检出 ≠ 有遥测。** NGES 示例日志（`ref/nges/*.log`）是遥测级事件流，不是告警工单。大量记录是 `explorer` 的 `ThreadCreate` / `FileOpen`，几乎全程都有遥测。若把「时间窗内出现任意事件」当成检出，召回率会虚高，正确率无意义。

因此对照分三层，报告里必须分开写，不得混成一个布尔值：

| 层 | 名称 | 含义 | 是否算「检出 TTP」 |
| --- | --- | --- | --- |
| A | 可见 observed | 时间窗内，命令行/映像/目标路径能对上本次 Atomic | 否（仅遥测覆盖） |
| B | TTP 检出 detected | 层 A 成立，且事件带有与本次 `technique_id` 对齐的 Technique 标注 | **是（主结论）** |
| C | 告警 alerted | 层 A 成立，且来自 `*_alert.log` 工单（`edgesInfo[].Event`） | 否（工单层，单独统计告警率） |

## 2. 目录约定

```
eval/
  docs/
    architecture.md          # 本文
  nges/                      # NGES 适配；换别的 EDR 再加同级目录
    schema.py
    parse.py
  atomic_logs.py             # 读 run-*.json，聚合成执行回合
  match.py                   # 时间窗 + 命令行 + TTP 对齐
  metrics.py                 # 指标
  report.py                  # HTML / JSON / CSV
  cli.py                     # python -m eval
  testdata/                  # 小样例，禁止拷入 83MB 原日志
  attck_enterprise.json      # MITRE Enterprise 矩阵（战术/名称）
```

报告里的战术来自 Enterprise ATT&CK（`ref/atomic-red-team-master/atomic_red_team/enterprise-attack.json` 抽出），不是只含 Windows Atomic 索引。可用 `python -m eval.build_attck_index` 重建。

83 MB 示例遥测留在 `ref/nges/`，测评时用参数指向，不复制进 `eval/`。

实现阶段默认输出目录：`outputs/eval/`。

## 3. 数据契约

### 3.1 atomic-reforge 执行日志

路径：`C:\ProgramData\atomic_reforge_logs\run-*.json`（失败时回退 `~/.atomic_reforge_logs`）。

格式：JSON Lines。每条记录至少使用：

| 字段 | 用途 |
| --- | --- |
| `timestamp` | 回合起始时间，**UTC** |
| `technique_id` | ATT&CK 技术 ID（含子技术） |
| `variant_guid` | 变体 GUID |
| `variant_name` | 展示名 |
| `branch` | `prereq` / `main` / `cleanup` |
| `simulated` | dry-run 为 true |
| `command` / `argv` | 实际下发的命令 |
| `exit_code` | 进程退出码 |
| `timed_out` | 是否超时 |
| `had_error` | 调度层错误 |
| `duration_s` | 执行时长，用于估结束时刻 |

**测评单元**：一次 `branch=main` 且 `simulated=false` 的变体执行，键为 `(technique_id, variant_guid, timestamp)`。同一变体多次实跑视为多个回合。

前置（`prereq`）与清理（`cleanup`）单独列表，**不进入检出召回的分母**。后续若要评「依赖下载是否被看见」，再加可选开关，默认关闭。

**执行成功**：`exit_code == 0` 且 `timed_out` 为假且 `had_error` 为假。执行失败的条目标「未成功执行」，**不进入层 B 召回分母**（避免把「没跑起来」算成「EDR 漏报」）。

当前执行日志**没有子进程 PID**。对齐只能靠时间窗 + 命令行，不能按 PID 绑进程。若日后 `run` 补记 PID，匹配器应优先用 PID。

### 3.2 NGES 遥测

路径示例：`ref/nges/87bc957b4715c19c66dd541638914612_telemetry.log`。同一主机可能切成多段，文件名带序号，遥测和告警各自一份：

```text
87bc957b4715c19c66dd541638914612_telemetry.log
87bc957b4715c19c66dd541638914612_2_telemetry.log
87bc957b4715c19c66dd541638914612_alert.log
87bc957b4715c19c66dd541638914612_2_alert.log
```

`--telemetry` 指向目录、glob，或其中任意一个文件时，都会把同一主机的分段遥测/告警一并读入。

格式：NDJSON，单文件可达数十 MB，解析必须流式，禁止一次性 `json.loads` 全文件。

顶层键：`Event`、`SourceProcess`、可选 `TargetProcess` / `TargetFile` / `TargetNetworkTraffic` / `TargetDns` / `TargetRegistry` / `TargetNamedPipe` / `TargetScheduledJob` / `TargetService` / `TargetWMI`、`tags`。

对照优先字段：

| 字段 | 用途 |
| --- | --- |
| `Event.agentDisplayTime` | 对齐时间。示例形态：`2026-10-08 10:40:41.824 (UTC+8)` |
| `Event.telemetrySubType` | 行为类型 |
| `Event.basicTtp` | JSON 字符串，含 `BasicTtp[].Technique`、`ScoreTtp[]` |
| `Event.builtinTtpTechnique` / `builtinTtpRuleName` | 内置规则 TTP 与规则名 |
| `Event.customTtpTechnique` | 自定义规则 TTP |
| `SourceProcess.commandLine` / `normalCommandLine` / `pid` / `fileName` / `filePath` | 与 Atomic 命令对齐 |
| 各 `Target*` | 文件、网络、注册表等旁证 |

示例切片（约 2.1 万条）观察：

- 带 Technique 标注的是少数；多数事件只有 `telemetrySubType`。
- `basicTtp` 常见形态：`{"BasicTtp":[{"Tactic":"TA0005","Technique":"T1055"}],"ScoreTtp":[]}`。
- `builtinTtpTechnique` 与 `basicTtp.Technique` 可能一个空、一个有值，抽取时**并集**。

**带 TTP 标注**的定义（层 B 的候选正例）：下列任一非空即可：

1. `builtinTtpTechnique`
2. `customTtpTechnique`
3. `basicTtp` 解析后 `BasicTtp[].Technique` 或 `ScoreTtp` 非空

其余事件最多参与层 A（可见），不得单独当作「检出」。

### 3.3 NGES 告警

路径示例：`eval/logs/<date>/nges_report/*_alert.log`（含 `*_2_alert.log` 分段）。

格式同样是 NDJSON，但顶层是告警工单，不是遥测事件。常见字段：`alertId`、`ruleName`、`ruleId`、`techniques`、`firstDetectTime` / `agentDisplayTime`、`edgesInfo[]`。

每条 `edgesInfo[]` 内含与遥测相同的 `Event` + `SourceProcess`（+ 可选 `TargetProcess`）。解析时把 `edgesInfo` 展开成与遥测同构的记录，并标记 `kind=alert`。若没有 `edgesInfo`，用信封上的 `techniques` / `ruleName` / `entryProcess` 合成一条事件。

层 C 只统计 `kind=alert` 且层 A 通过的回合。告警上的 Technique 仍走层 B 对齐；告警但 Technique 对不上标 `alerted_wrong_ttp`。

## 4. 流水线

```
run-*.json ──► 执行回合（按变体、仅 main）
                    │
                    ▼
              时间窗 [t0 − Δ, t1 + Δ]
                    │
*_telemetry.log ──► 候选事件 ──► 层 A / B / C
*_alert.log     ──┘
                                    │
                                    ▼
                              指标 + HTML / JSON / CSV
```

- \(t_0\)：回合 `timestamp`（转 UTC）。
- \(t_1\)：\(t_0 + duration\_s\)；若缺时长则 \(t_1 = t_0\)。
- \(\Delta\) 默认 60 秒，CLI 可配。
- Atomic 日志是 UTC，NGES 示例是 UTC+8，解析后**全部转 UTC** 再比。

同一场连续 `run all` 时相邻回合窗口会重叠。匹配必须做**一对一归属**：每个执行回合只绑定得分最高的一簇事件；带 TTP 标注的事件簇不得重复分给两条 Atomic。

## 5. 匹配算法

对每个执行成功的回合：

1. 收集时间窗内全部遥测。
2. 用命令行/映像/路径打层 A 分。
3. 在层 A 通过的事件上抽 Technique，打层 B。
4. 看是否来自 `alert.log`，打层 C。
5. 与其它回合做贪心去重。

### 5.1 层 A：可见

窗内至少一条事件满足命令行重叠。建议分数由下列信号加权（实现时可调，但要在报告「方法与口径」里写出阈值）：

- Atomic `argv` / `command` 中的独特路径片段（`atomics\Txxxx`、`ExternalPayloads\reforge_remote\`、payload 文件名）出现在 `commandLine` 或 `TargetFile.path`。
- 执行器映像：`powershell.exe`、`pwsh.exe`、`cmd.exe` 与本次 executor 一致。
- 技术相关二进制名（从 `argv` 抽出的 `.exe` / `.dll` / `.ps1`）出现在 `SourceProcess.fileName` 或目标路径。
- 子串过短（如单独的 `powershell`）不得单独判可见，避免把系统噪声算进来。
- `python.exe -m atomic_reforge.cli run Txxxx` 是测评调度器，不是 Atomic payload。技术 ID 只出现在这条 runner 命令上时，不得据此判「可见」；示例 commandLine 应取 `TargetProcess.commandLine` 或 Atomic 下发命令，不要展示 runner。

进程树可能断（`parentProcessNodeId` 为 0），**不要依赖父子 PID 作为硬条件**。

### 5.2 层 B：TTP 对齐

仅在层 A 通过的事件上比较 Technique。对齐规则：

| 关系 | 例子 | 判定 |
| --- | --- | --- |
| 精确 | Atomic `T1055.004`，EDR `T1055.004` | 检出 |
| 父级放宽 | Atomic `T1055.004`，EDR `T1055` | 「父技术命中」：默认算检出，报告单独一列；可用开关关掉 |
| 子级更细 | Atomic `T1055`，EDR `T1055.011` | 检出，标「粒度更细」 |
| 无关 | Atomic `T1059.001`，EDR `T1574.001` | 不算本条检出；该事件可进入误报候选；回合明细用红色列出这些 Technique，便于排查标错 |

比较前把 ID 正规化为大写、去掉空白。父 ID 取第一个点之前的部分（`T1055.004` → `T1055`）。

一条 Atomic 的最终状态（互斥，取最强）：

```
未执行成功
  → 执行成功但不可见
    → 可见未标 TTP
      → TTP 检出（含父技术 / 更细粒度，报告里再拆）
        → 告警（工单层，单独统计）
```

告警仍可同时是 TTP 检出；告警但 Technique 对不上标 `alerted_wrong_ttp`。

### 5.3 归属与去重

每个带 TTP 标注且层 A 通过的事件簇，按匹配分排序，分给尚未占用的最高分回合。分数建议：精确 Technique > 父子关系 > 仅命令行可见。同分时取时间更近者。

未分出去的带标注事件计入 **FP 候选**（见第 6 节）。

## 6. 指标

只对**执行成功**的回合算检出类指标。

符号：

- \(N\)：执行成功的 Atomic 回合数
- \(TP\)：其中层 B 为真的数量（默认含父技术命中）
- \(FN = N - TP\)
- \(FP\)：整场测评中，带 TTP 标注、且未能归属到任何成功 Atomic 的**检测簇**（按规则 ID + 短时间窗聚类，避免把同一注入的多条 `ProcessInject` 算成多个 FP）

| 指标 | 公式 | 含义 |
| --- | --- | --- |
| 召回率 Recall | \(TP / N\) | 跑成功的 TTP 里，EDR 标对了多少 |
| 漏报率 Miss | \(FN / N = 1 - Recall\) | 跑成功但没标对 |
| 精确率 Precision | \(TP / (TP + FP)\) | 打出去的 TTP 标签有多少能对上本次测试。低精确率 / 多 FP 簇说明标签偏吵（过宽规则、系统进程或调度器被标成攻击），不是遥测盲区；也不是生产误报率，不能代替告警率。FP 簇 ≠ 回合状态「标成别的 TTP」 |
| 正确率 Accuracy | \((TP + TN) / (TP+TN+FP+FN)\) | 见下 |

**Accuracy 的 \(TN\)**：取「无 Atomic 的安静时段里也没有 TTP 标注」。若输入日志几乎全是测评窗口、没有负样本时段，报告必须写 **Accuracy 不适用**，不得用 \( (TP+TN)/(全部事件) \) 这种把海量 `FileOpen` 当负例的算法。

精确率的正例集合是「带 TTP 标注的事件/簇」，**不是**全部遥测。

此外必须输出：

- **执行成功率**：执行成功 / 执行用例总数（`main` 成功数 / `main` 总数，排除 `simulated=true`）。摘要卡片的小字统一写成「分子名 数字 / 分母名 数字」
- **可见率**：执行成功且层 A 为真的比例
- **告警率**：执行成功且层 C 为真
- **精确命中召回**：\((exact + child) / N\)。精确 = 同一 Technique ID；child = EDR 标得更细。父技术命中（Atomic 子技术、EDR 只标父 ID）计入主召回，不进本列。主召回高而本列低，说明许多检出靠父技术放宽
- 按 `technique_id` / Tactic / 变体策略（`identity/original` 等）分组的召回
- **检出时延**：Atomic `timestamp` 到第一条层 B 命中事件的秒数（中位数 + 分位）
- 失败原因分布：非 0 退出、超时、缺 payload；HTML 另附启发式「推测」说明（域/ESXi/注册表/横向等），不是调度器错误码

分母为 0 时该指标输出 `null`，HTML 显示「—」，不要写成 0% 或 100%。

## 7. 报告

每次测评写三份同名不同后缀的文件到 `--out`：

- `report-<时间>.html`：给人看
- `report-<时间>.json`：给脚本
- `report-<时间>.csv`：每回合一行

HTML 至少包含：

1. 先 Batch Summary（测试用例数 / TTP 数；指标卡片下用本场数字串成中文测评结论；按最新 ATT&amp;CK 战术阶段出条形图；同一 TTP 可落入多个阶段；v19 原 Defense Evasion 已拆成 Stealth 与 Defense Impairment；召回过低的 TTP 同样按阶段拆分），再「方法与口径」
2. 按战术汇总（按单个阶段拆开；多归属 TTP 的回合会重复出现在多行）；块内「状态说明」解释回合状态芯片（互斥，取最强）
3. 可筛选/排序的 TTP 主表（「可见」 / 检出 / 告警 / 召回），展开回合明细
4. FP 候选预览：有 Technique 标注但对不上本次 Atomic
5. 未执行成功：原因分布与推测汇总常显，明细表默认折叠可展开（明确不计入漏报；全量在 JSON/CSV）
6. 解析警告

JSON 顶层建议：`meta`、`summary`、`by_technique`、`episodes`、`false_positives`。字段名用英文，与代码一致；HTML 用中文标题。

## 8. CLI

离线对照，不在 `run` 过程中实时打分。

```text
python -m eval --atomic-logs C:\ProgramData\atomic_reforge_logs
               --telemetry F:\AI\Atomic-Reforge\ref\nges\*.log
               --out outputs/eval
               --window-sec 60
               [--parent-match / --no-parent-match]
```

`--telemetry` 支持文件、目录或 glob。目录收集 `*_telemetry.log` / `*_alert.log`（含 `_N_` 分段）；给单个 NGES 日志会展开同主机其余分段。`--atomic-logs` 支持目录（读取全部 `run-*.json`）或单个文件。

日后可挂到主 CLI：`atomic-reforge eval ...`。第一期不必改 `src/atomic_reforge/cli.py`，`eval` 作为仓库子包独立运行即可。

## 9. 实现顺序

1. NGES 流式解析 + Atomic JSONL 聚合成回合（含时区归一）
2. 时间窗 + 命令行重叠 + TTP 字段对齐与去重归属
3. 指标与 HTML / JSON / CSV
4. `eval/testdata/`：从 `ref/nges` 抽几行真实事件 + 构造对应的假 Atomic 日志，覆盖精确命中、父技术、无关 TTP、执行失败不计入漏报、Accuracy 不适用
5. 再接到真实 `run-*.json`

## 10. 已知限制

- 示例遥测没有告警工单，检出完全依赖 `basicTtp` / `builtinTtp*` / `customTtp*`。规则没打 Technique 的行为只能进「可见」。
- 进程树可能不完整，命令行模糊匹配是主手段。
- 无 PID 时相邻 TTP 窗口重叠会造成抢命中，必须做一簇一事归属。
- 示例切片中 `isBlocked` 可能长期为 0；测评不再把拦截当作指标。

## 11. 范围外（第一期不做）

- 把 NGES 以外的 EDR 适配写进同一匹配器（只留目录扩展点）
- 在 `run` 时实时对照遥测
- 修改 `atomic-reforge` 执行日志 schema（PID 等增强另开任务）
- 将 83 MB 原日志纳入 git 或测试夹具
- 把前置/清理步骤计入检出召回
