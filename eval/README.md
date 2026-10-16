# EDR 遥测测评（NGES）

对照 `atomic-reforge` 执行日志与 NGES NDJSON，判断每条 Atomic **是否跑成功**，以及 EDR 是否 **「可见」** 这次命令、是否 **标到对应 ATT&CK TTP**、是否 **出告警**。

**「可见」≠ 检出 ≠ 告警。** 规格见 [`docs/architecture.md`](docs/architecture.md)。

## 三层

| 层 | 名称 | 含义 | 算检出？ |
| --- | --- | --- | --- |
| A | 「可见」 observed | 时间窗内命令行/路径对上这次测试 | 否（只说明遥测覆盖） |
| B | 检出 detected | 「可见」且 Technique 与本次 `technique_id` 对齐 | **是（主结论）** |
| C | 告警 alerted | 「可见」且来自 `*_alert.log` 工单 | 否（单独统计告警率） |

告警不要求 TTP 标对：工单层衡量「有没有喊人」，检出衡量「认没认准」。

## 运行

在仓库根目录（需能 `import eval`，`pyproject.toml` 已把 `.` 加入 pytest/`pythonpath`）：

```text
python -m eval --atomic-logs C:\ProgramData\atomic_reforge_logs ^
               --telemetry F:\path\to\nges_logs ^
               --out outputs\eval ^
               --window-sec 60
```

- `--atomic-logs`：目录（读全部 `run-*.json`）或单个 JSONL。
- `--telemetry`：文件、目录或 glob，可重复。目录收集 `*_telemetry.log` / `*_alert.log`（含 `_2_` 分段）；给其中一个文件会带上同主机其余分段。
- `--parent-match` / `--no-parent-match`：Atomic `T1055.004`、EDR 只标 `T1055` 时是否算检出，默认算。

产出 `outputs/eval/report-<时间>.html|json|csv`。HTML 可从已有 JSON 重渲，不必重跑 GB 级日志。

夹具（仓库内小样例，不含真实遥测）：

```text
python -m eval --atomic-logs eval/testdata/run-fixture.json --telemetry eval/testdata/telemetry.ndjson --out outputs/eval
python -m pytest tests/test_eval.py -q
```

重建 ATT&CK 战术索引（依赖 `ref/atomic-red-team-master/.../enterprise-attack.json`）：

```text
python -m eval.build_attck_index
```

## 口径要点

- 分母 *N* = **执行成功的测试命令**（不含前置、清理；非 0 退出/超时/缺文件不进召回）。
- 召回 = 检出 / *N*；漏报 = 未检出 / *N*（含未「可见」、未标、标成别的 TTP、告警但 TTP 不对齐）。
- 精确率 = 检出 / (检出 + FP 簇)。FP 簇是带 Technique、却没挂上任何成功测试的检测簇，**不是**回合状态「标成别的 TTP」。
- 战术名按 ATT&CK v19：原 Defense Evasion 拆成 Stealth 与 Defense Impairment。

不要把 `eval/logs/` 或 `outputs/eval/` 提交进 Git（体积大，且可能含客户环境命令行）。
