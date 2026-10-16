"""Binary payload deformation strategies: rename and package+extract.

These strategies operate at the *template* level (template_based=True) so that
``#{arg}`` placeholders and the payload files themselves are not consumed: the
deformation is expressed as added_args (new defaults pointing at renamed /
embedded-payload paths) plus a payload_ops list that the release/materialization
step realizes (physical file copy+rename, or base64 embed).

* ``binary/rename`` — give each local binary a fresh random filename (new
  on-disk hash/path signature) and rewrite the reference to point at the new
  name under ``PathToAtomicsFolder\\payloads\\<TID>\\``.
* ``binary/package_extract`` — base64-embed each local binary into a new
  ``#{arg}`` and emit a loader command that writes the bytes to a temp file
  then invokes the ORIGINAL payload args/command.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from .base import Strategy, TransformPlan
from ..payloads import ATOMICS_PATH, discover_payloads, local_exists

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic, CommandExecutor


@dataclass
class PayloadOp:
    """A physical payload operation to realize at release/materialization time.

    ``kind`` is ``"copy_rename"`` (copy ``src_path`` to ``dest_rel`` holding its
    original name renamed to ``new_name``) or ``"embed_base64"`` (the strategy
    already embedded bytes via an added arg; nothing to copy).
    """

    kind: str  # "copy_rename" | "embed_base64"
    src_path: Path
    new_name: str
    dest_rel: str  # relative path inside the bundle atomics/ payloads/<TID>/
    arg_key: Optional[str] = None
    token: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "src_path": str(self.src_path),
            "new_name": self.new_name,
            "dest_rel": self.dest_rel,
            "arg_key": self.arg_key,
            "token": self.token,
        }


def _fresh_name(original: Path) -> str:
    """Random new file name preserving the original extension."""
    return f"{uuid.uuid4().hex[:8]}{original.suffix}"


def _renamed_token(technique_id: str, new_name: str) -> str:
    """Default / literal path for a renamed payload inside a release atomics root."""
    return f"PathToAtomicsFolder\\payloads\\{technique_id}\\{new_name}"


class BinaryRenameStrategy(Strategy):
    """Rename each local payload binary to a fresh random name."""

    name = "binary/rename"
    family = "binary"

    def applies(
        self, atomic: "Atomic", executor: "CommandExecutor", path_to_atomics=None
    ) -> bool:
        refs = discover_payloads(atomic, path_to_atomics or ATOMICS_PATH)
        return any(local_exists(r) for r in refs)

    def plan(
        self,
        technique_id: str,
        atomic: "Atomic",
        executor: "CommandExecutor",
        path_to_atomics=None,
    ) -> Optional[TransformPlan]:
        root = path_to_atomics or ATOMICS_PATH
        refs = discover_payloads(atomic, root)
        present = [r for r in refs if local_exists(r)]
        if not present:
            return None

        added_args: dict[str, object] = {}
        ops: list[PayloadOp] = []
        # Map ref identity -> chosen new name (same name for op + command rewrite).
        rename_map: list[tuple[object, str]] = []

        for ref in present:
            new_name = _fresh_name(ref.path)
            dest_rel = f"payloads/{technique_id}/{new_name}"
            rename_map.append((ref, new_name))
            if ref.arg_key:
                added_args[ref.arg_key] = _renamed_token(technique_id, new_name)
                arg_key_out = ref.arg_key
            else:
                arg_key_out = None
            ops.append(
                PayloadOp(
                    kind="copy_rename",
                    src_path=ref.path,
                    new_name=new_name,
                    dest_rel=dest_rel,
                    arg_key=arg_key_out,
                    token=ref.token,
                )
            )

        new_command = executor.command or ""
        for ref, new_name in rename_map:
            if ref.arg_key:
                continue
            if ref.literal:
                new_command = new_command.replace(
                    ref.literal, _renamed_token(technique_id, new_name)
                )

        explanation = (
            "Renames each locally-present payload binary to a fresh random "
            "file name (preserving extension) and rewrites the reference to "
            "point at the renamed file under payloads/<TID>/. This changes the "
            "on-disk file name / hash / path signature while keeping the binary "
            "and its arguments identical."
        )

        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=explanation,
            applied_to="command",
            new_command=new_command,
            added_args=added_args,
            template_based=True,
            payload_ops=ops,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        return command


class BinaryPackageStrategy(Strategy):
    """Package each local payload: base64-embed it and loader-extract at run."""

    name = "binary/package_extract"
    family = "binary"

    def applies(
        self, atomic: "Atomic", executor: "CommandExecutor", path_to_atomics=None
    ) -> bool:
        if executor.name != "powershell":
            return False
        refs = discover_payloads(atomic, path_to_atomics or ATOMICS_PATH)
        return any(local_exists(r) for r in refs)

    def plan(
        self,
        technique_id: str,
        atomic: "Atomic",
        executor: "CommandExecutor",
        path_to_atomics=None,
    ) -> Optional[TransformPlan]:
        root = path_to_atomics or ATOMICS_PATH
        refs = discover_payloads(atomic, root)
        present = [r for r in refs if local_exists(r)]
        if not present:
            return None
        if executor.name != "powershell":
            return None
        if not (executor.command or "").strip():
            return None

        added_args: dict[str, object] = {}
        ops: list[PayloadOp] = []
        loader_parts: list[str] = []

        for idx, ref in enumerate(present):
            data = ref.path.read_bytes()
            b64 = base64.b64encode(data).decode("ascii")
            blob_key = f"reforge_payload_{idx}"
            added_args[blob_key] = b64
            new_name = _fresh_name(ref.path)
            ops.append(
                PayloadOp(
                    kind="embed_base64",
                    src_path=ref.path,
                    new_name=new_name,
                    dest_rel=f"payloads/{technique_id}/{new_name}",
                    arg_key=ref.arg_key,
                    token=ref.token,
                )
            )
            ext = ref.path.suffix or ".bin"
            loader_parts.append(
                (
                    "$reforge_path_{0}=Join-Path $env:TEMP "
                    "('reforge_'+[guid]::NewGuid().ToString('N')+'{2}');"
                    "[IO.File]::WriteAllBytes($reforge_path_{0},"
                    "[Convert]::FromBase64String('#{{{1}}}'));"
                ).format(idx, blob_key, ext.replace("'", "''"))
            )

        original = executor.command or ""
        loader = (
            "# reforge binary/package_extract\n"
            + "\n".join(loader_parts)
            + "\n"
            + _relocate_command(original, present)
        )

        explanation = (
            "Base64-embeds each locally-present payload binary and emits a "
            "PowerShell loader that writes the bytes to a random temp file "
            "(fresh name/hash) and then executes the original command against "
            "it — no payload on disk in the script and a fresh on-disk "
            "signature at run time."
        )
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=explanation,
            applied_to="command",
            new_command=loader,
            template_based=True,
            added_args=added_args,
            payload_ops=ops,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        return command


def _relocate_command(original: str, refs) -> str:
    """Point each payload arg token at its materialized temp file path."""
    out = original
    for idx, ref in enumerate(refs):
        var = f"$reforge_path_{idx}"
        if ref.arg_key and f"#{{{ref.arg_key}}}" in out:
            out = out.replace(f"#{{{ref.arg_key}}}", var)
        elif ref.literal:
            out = out.replace(ref.literal, var)
    return out
