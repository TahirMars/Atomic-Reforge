# ref/ — 本地依赖（默认不进 Git）

把体积大、不属于本仓库原创的材料放这里，克隆后按需自行准备：

| 路径 | 用途 |
| --- | --- |
| `atomic-red-team-master/` | 上游 Atomic Red Team（含 `atomics/` 与 `enterprise-attack.json`） |
| `python-*-embed-amd64.zip` | 可选：便携 Python，供 `atomic-reforge release --bundle-runtime` |
| `edr/` 或测评机拷回的 `*_telemetry.log` / `*_alert.log` | EDR 原始日志，用 `--telemetry` 指向即可 |

`generate` / `release` 通过 `sys.path` 从 `atomic-red-team-master/` 导入上游 schema。没有这份树时，变形与离线打包无法运行。

获取 ART 示例：

```text
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git ref/atomic-red-team-master
```

远程 payload 预取见仓库根 README「远程脚本本地化」与 `scripts/prefetch_remote_payloads.py`。
