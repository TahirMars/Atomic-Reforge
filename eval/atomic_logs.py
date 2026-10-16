"""Load atomic-reforge JSONL run logs into evaluation episodes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

PAYLOAD_HINTS = (
    "cannot find",
    "not found",
    "找不到",
    "no such file",
    "externalpayloads",
    "pathtoatomicsfolder",
    "the system cannot find",
)

_STRATEGY_RE = re.compile(r"reforge/([A-Za-z0-9_./-]+)", re.I)


def parse_iso_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def strategy_from_name(variant_name: str) -> str:
    match = _STRATEGY_RE.search(variant_name or "")
    if not match:
        return ""
    tag = match.group(1).strip()
    if "/" not in tag and "_" in tag:
        family, _, rest = tag.partition("_")
        if family and rest:
            return f"{family}/{rest}"
    return tag


FAILURE_LABELS = {
    "timeout": "超时",
    "nonzero_exit": "非 0 退出",
    "scheduler_error": "非 0 退出",
    "missing_payload": "缺 payload",
    "simulated": "模拟未执行",
}


def failure_reason(record: dict[str, Any]) -> str:
    if record.get("simulated"):
        return "simulated"
    if record.get("timed_out"):
        return "timeout"
    stderr = str(record.get("stderr") or "").lower()
    if any(h in stderr for h in PAYLOAD_HINTS):
        return "missing_payload"
    exit_code = record.get("exit_code")
    if exit_code not in (0, None):
        return "nonzero_exit"
    if record.get("had_error"):
        return "scheduler_error"
    return ""


def display_failure_reason(reason: str | None) -> str:
    if not reason:
        return "—"
    if reason.startswith("exit_"):
        return f"非 0 退出（{reason.split('_', 1)[1]}）"
    return FAILURE_LABELS.get(reason, reason)


def normalize_failure_reason(reason: str | None) -> str:
    if reason == "scheduler_error":
        return "nonzero_exit"
    if reason and reason.startswith("exit_"):
        return "nonzero_exit"
    return reason or ""


def _failure_haystack(row: dict[str, Any]) -> str:
    return "\n".join(
        str(row.get(k) or "")
        for k in ("command", "argv", "variant_name", "stderr", "technique_id")
    ).lower()


def _has(hay: str, *needles: str) -> bool:
    return any(n.lower() in hay for n in needles)


def guess_failure(row: dict[str, Any]) -> str:
    """Heuristic note from command/name/technique. Not a scheduler error code."""
    reason = normalize_failure_reason(str(row.get("failure_reason") or ""))
    timed_out = bool(row.get("timed_out")) or reason == "timeout"
    hay = _failure_haystack(row)
    stderr = str(row.get("stderr") or "").lower()
    tid = str(row.get("technique_id") or "").upper()

    if timed_out:
        if _has(hay, "winpwn", "s3cur3th1ssh1t"):
            return "超时：WinPwn/在线侦察套件，默认时限不够"
        if _has(hay, "for /l", "1..254", "1..255") or (
            _has(hay, "ping -n") and _has(hay, "for ")
        ) or (_has(hay, "resolve-dnsname") and _has(hay, "for($", " -le ")):
            return "超时：内网扫描或大批量 DNS/HTTP 查询"
        if _has(
            hay,
            "github.com",
            "githubusercontent",
            "invoke-webrequest",
            "bitsadmin",
            "test-netconnection",
            "www.google.com",
        ):
            return "超时：外连下载或探测公网"
        if _has(hay, "cipher.exe", " cipher "):
            return "超时：磁盘擦除/覆盖很慢"
        if hay.rstrip().endswith(" time") or _has(hay, "cmd.exe /c time"):
            return "超时：可能在等交互输入"
        if _has(hay, "psexec", "invoke-command", "enter-pssession", "wmi", "eventfilter"):
            return "超时：远程执行或 WMI 订阅卡住"
        if _has(hay, "reg save", "hklm\\sam", "hklm\\security"):
            return "超时：敏感注册表/SAM 导出卡住"
        return "超时：默认时限内未结束（扫描、外连或卡住）"

    if reason == "missing_payload" or any(h in stderr for h in PAYLOAD_HINTS):
        return "缺文件：payload 或 atomics 路径找不到"

    if (
        _has(
            hay,
            "/domain",
            "domain controller",
            "get-aduser",
            "get-adcomputer",
            "get-addomain",
            "adfind",
            "nltest",
            "dsquery",
            "ldifde",
            "objectcategory",
            "ldap://",
            r"root\directory\ldap",
            "dcpromo",
            "net group /domain",
            "net user /domain",
            "%userdnsdomain%",
            "%logonserver%",
            "sysvol",
            "setspn",
            "password spray",
            "domain users",
        )
        or tid.startswith(("T1482", "T1069.002", "T1087.002", "T1110", "T1558"))
    ):
        return "推测：需要域控/AD，单机实验网没有域"

    if _has(hay, "esxcli", "esxi", "powercli", "get-vmhost", "vsphere") or "vmware" in hay:
        return "推测：需要 ESXi/vSphere 目标，本机没有"

    if (
        tid.startswith("T1003")
        or _has(
            hay,
            "lsass",
            "mimikatz",
            "sekurlsa",
            "procdump",
            "pypykatz",
            "ntdsutil",
            "ntds.dit",
            "comsvcs",
            "secretsdump",
        )
    ):
        return "推测：凭据转储失败（权限、防护或工具未落地）"

    if _has(
        hay,
        "psexec",
        "wmic /node",
        "enter-pssession",
        "new-pssession",
        "admin$",
        "impacket",
        "-computername",
        "\\\\target",
        "\\target\\",
        "crackmapexec",
        "enable-psremoting",
        " /s localhost",
        "\\\\localhost",
    ) or tid.startswith(("T1021", "T1550.002")):
        return "推测：横向移动缺少可达目标（占位主机/凭据）"

    if tid.startswith("T1112") or _has(
        hay, "reg add", "reg.exe add", "reg import", "reg.exe import", "new-itemproperty"
    ):
        return "推测：改系统注册表失败（权限不足或被防护）"

    if tid.startswith(("T1489", "T1490")) or _has(
        hay,
        "vssadmin",
        "wbadmin",
        "delete shadows",
        "diskshadow",
        "wmic shadowcopy",
    ):
        return "推测：卷影复制/备份/停服务失败（权限或目标不存在）"

    if _has(
        hay,
        "radmin",
        "pdq deploy",
        "subinacl",
        "crackmapexec",
        "sysmon -u",
        "is not recognized",
        "不是内部或外部命令",
    ):
        return "推测：依赖工具未安装或不在 PATH"

    if _has(
        hay,
        "net.exe stop",
        "sc.exe config",
        "sc config",
        "sc start",
        "auditpol",
        "wevtutil cl",
        "windefend",
        "/remove /norestart",
    ) or tid.startswith("T1685"):
        return "推测：服务/防护组件不存在或无权更改"

    if _has(
        hay,
        "invoke-webrequest",
        "bitsadmin",
        "certreq.exe -post",
        "downloadfile",
        "curl.exe",
        "https://",
    ) or tid.startswith("T1105"):
        return "推测：外连下载失败（无网、被拦或 URL 无效）"

    if "externalpayloads" in hay:
        return "推测：第三方 payload/exe 未落地或无法运行"

    if tid.startswith("T1218") or _has(
        hay, "rundll32", "regsvr32", "mshta", "odbcconf", "infdefaultinstall", "mavinject"
    ):
        return "推测：系统代理执行失败（DLL/脚本/参数不匹配或被拦）"

    if _has(hay, "appcmd.exe", "inetsrv"):
        return "推测：本机没有 IIS 或无权改模块"

    return "推测：命令非 0 退出（环境、权限或参数，需看 stderr）"


def is_executed_ok(record: dict[str, Any]) -> bool:
    return (
        record.get("exit_code") == 0
        and not record.get("timed_out")
        and not record.get("had_error")
    )


@dataclass
class Episode:
    """One main-branch, non-simulated variant execution."""

    technique_id: str
    variant_guid: str
    variant_name: str
    timestamp: datetime
    duration_s: float
    executor: str
    command: str
    argv: str
    exit_code: int | None
    timed_out: bool
    had_error: bool
    executed_ok: bool
    strategy: str
    stderr: str = ""
    stdout: str = ""
    pid: int | None = None
    source_file: str = ""
    failure: str = ""
    signatures: tuple[str, ...] = field(default_factory=tuple)
    executor_images: tuple[str, ...] = field(default_factory=tuple)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.technique_id, self.variant_guid, self.timestamp.isoformat())

    @property
    def t0(self) -> datetime:
        return self.timestamp

    @property
    def t1(self) -> datetime:
        extra = self.duration_s if self.duration_s and self.duration_s > 0 else 0.0
        from datetime import timedelta

        return self.timestamp + timedelta(seconds=extra)


_GENERIC_TOKENS = {
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "cmd",
    "cmd.exe",
    "conhost.exe",
    "python.exe",
    "python",
    "explorer.exe",
    "-noprofile",
    "-noninteractive",
    "-command",
    "-nop",
    "-ep",
    "bypass",
    "-windowstyle",
    "hidden",
    "-c",
    "/c",
}

_PATH_HINT = re.compile(
    r"(?i)(?:[a-z]:)?(?:\\|/)?[^\s'\"`]{0,240}"
    r"(?:atomics|externalpayloads|reforge_remote)[^\s'\"`]*"
)
_FILE_NAME = re.compile(
    r"(?i)\b[\w.\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|msi|bin|xsl|hta)\b"
)

_EXECUTOR_IMAGES = {
    "powershell": ("powershell.exe", "pwsh.exe"),
    "command_prompt": ("cmd.exe",),
    "cmd": ("cmd.exe",),
    "pwsh": ("pwsh.exe", "powershell.exe"),
}


def extract_signatures(
    command: str,
    argv: str,
    technique_id: str,
) -> tuple[str, ...]:
    text = f"{command or ''}\n{argv or ''}"
    found: list[str] = []
    seen: set[str] = set()

    def add(token: str) -> None:
        tok = token.strip().lower()
        if not tok or tok in seen or tok in _GENERIC_TOKENS:
            return
        seen.add(tok)
        found.append(tok)

    for match in _PATH_HINT.finditer(text):
        add(match.group(0).strip("\\/'"))
    if technique_id:
        add(technique_id)
    for match in _FILE_NAME.finditer(text):
        add(match.group(0))
    for tok in re.findall(r"[^\s'\"`;|&<>]+", text):
        cleaned = tok.strip("\\/'\" ").lower()
        if len(cleaned) >= 12:
            add(cleaned)
    return tuple(found)


def _episode_from_record(record: dict[str, Any], source_file: str) -> Episode | None:
    if (record.get("branch") or "").lower() != "main":
        return None
    if record.get("simulated"):
        return None
    ts = parse_iso_utc(record.get("timestamp"))
    if ts is None:
        return None
    technique_id = str(record.get("technique_id") or "").strip()
    command = str(record.get("command") or "")
    argv = str(record.get("argv") or "")
    executor = str(record.get("executor") or "")
    duration = record.get("duration_s")
    try:
        duration_s = float(duration) if duration is not None else 0.0
    except (TypeError, ValueError):
        duration_s = 0.0
    pid_raw = record.get("pid")
    try:
        pid = int(pid_raw) if pid_raw not in (None, "") else None
    except (TypeError, ValueError):
        pid = None
    name = str(record.get("variant_name") or "")
    return Episode(
        technique_id=technique_id,
        variant_guid=str(record.get("variant_guid") or ""),
        variant_name=name,
        timestamp=ts,
        duration_s=duration_s,
        executor=executor,
        command=command,
        argv=argv,
        exit_code=record.get("exit_code"),
        timed_out=bool(record.get("timed_out")),
        had_error=bool(record.get("had_error")),
        executed_ok=is_executed_ok(record),
        strategy=strategy_from_name(name),
        stderr=str(record.get("stderr") or ""),
        stdout=str(record.get("stdout") or ""),
        pid=pid,
        source_file=source_file,
        failure=failure_reason(record) if not is_executed_ok(record) else "",
        signatures=extract_signatures(command, argv, technique_id),
        executor_images=_EXECUTOR_IMAGES.get(executor.lower(), ()),
    )


def load_jsonl(path: Path) -> tuple[list[Episode], list[dict[str, Any]], list[str]]:
    """Return (main episodes, skipped side records, errors)."""
    episodes: list[Episode] = []
    skipped: list[dict[str, Any]] = []
    errors: list[str] = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                errors.append(f"{path.name}:{line_no}: {exc}")
                continue
            if not isinstance(record, dict):
                continue
            ep = _episode_from_record(record, str(path))
            if ep is None:
                skipped.append(
                    {
                        "technique_id": record.get("technique_id"),
                        "variant_guid": record.get("variant_guid"),
                        "branch": record.get("branch"),
                        "simulated": record.get("simulated"),
                        "timestamp": record.get("timestamp"),
                    }
                )
                continue
            episodes.append(ep)
    return episodes, skipped, errors


def discover_atomic_logs(path: Path) -> list[Path]:
    path = Path(path)
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.glob("run-*.json"))
    return []


def load_from_path(path: Path) -> tuple[list[Episode], list[dict[str, Any]], list[str]]:
    files = discover_atomic_logs(path)
    if not files:
        return [], [], [f"no run-*.json under {path}"]
    episodes: list[Episode] = []
    skipped: list[dict[str, Any]] = []
    errors: list[str] = []
    for file in files:
        eps, skip, err = load_jsonl(file)
        episodes.extend(eps)
        skipped.extend(skip)
        errors.extend(err)
    episodes.sort(key=lambda e: e.timestamp)
    return episodes, skipped, errors


def load_from_paths(paths: Iterable[Path]) -> tuple[list[Episode], list[dict[str, Any]], list[str]]:
    episodes: list[Episode] = []
    skipped: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in paths:
        eps, skip, err = load_from_path(Path(path))
        episodes.extend(eps)
        skipped.extend(skip)
        errors.extend(err)
    episodes.sort(key=lambda e: e.timestamp)
    return episodes, skipped, errors
