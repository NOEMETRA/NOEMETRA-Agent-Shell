"""Out-of-band OS-native interactive human confirmation for ACK patch approvals."""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Tuple

_WIN_MSGBOX_SCRIPT = (
    "import ctypes, json, sys\n"
    "payload = json.loads(sys.stdin.read())\n"
    "u32 = ctypes.windll.user32\n"
    "u32.MessageBoxW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]\n"
    "u32.MessageBoxW.restype = ctypes.c_int\n"
    "flags = 0x00000004 | 0x00000030 | 0x00000100 | 0x00010000 | 0x00040000\n"
    "rc = u32.MessageBoxW(0, str(payload['message']), str(payload['title']), flags)\n"
    "sys.exit(0 if rc == 6 else 1)\n"
)


def _sanitize_dialog_text(value: Any, max_len: int = 240) -> str:
    """Strip control characters and collapse newlines to prevent OS dialog spoofing."""
    cleaned = "".join(ch if (ch.isprintable() and ch not in "\r\n\t") else " " for ch in str(value or ""))
    collapsed = " ".join(cleaned.split())
    if len(collapsed) > max_len:
        return collapsed[: max_len - 3] + "..."
    return collapsed


def _build_confirmation_prompt(context: Dict[str, Any]) -> Tuple[str, str]:
    """Build deterministic OS confirmation dialog title and body bound to run and hashes."""
    title = "NOEMETRA ACK — Conferma Umana Patch"
    reasons_raw = context.get("manual_review_reasons") or []
    reasons_str = "; ".join(_sanitize_dialog_text(r, 120) for r in reasons_raw[:4]) or "Nessuna segnalazione extra"
    lines: List[str] = [
        "Confermi l'emissione del token monouso per applicare la patch sul file target?",
        "",
        f"Run ID: {_sanitize_dialog_text(context.get('run_id'), 64)}",
        f"Target: {_sanitize_dialog_text(context.get('target_file_path'), 200)}",
        f"Classificazione: {_sanitize_dialog_text(context.get('patch_classification'), 64)}",
        f"Revisione manuale: {'SI' if context.get('manual_review_required') else 'NO'}",
        f"Note revisione: {reasons_str}",
        f"SHA-256 originale: {_sanitize_dialog_text(context.get('original_sha256'), 32)[:16]}",
        f"SHA-256 diff:      {_sanitize_dialog_text(context.get('patch_diff_sha256'), 32)[:16]}",
        f"SHA-256 patched:   {_sanitize_dialog_text(context.get('patched_target_sha256'), 32)[:16]}",
    ]
    return title, "\n".join(lines)


def _windows_has_interactive_desktop() -> bool:
    """Return True only when running inside an interactive visible Windows desktop station."""
    if sys.platform != "win32":
        return False
    try:
        user32 = ctypes.windll.user32
        user32.GetProcessWindowStation.restype = ctypes.c_void_p
        hwinsta = user32.GetProcessWindowStation()
        if not hwinsta:
            return False

        class _UserObjectFlags(ctypes.Structure):
            _fields_ = [
                ("fInherit", ctypes.c_int),
                ("fReserved", ctypes.c_int),
                ("dwFlags", ctypes.c_uint32),
            ]

        flags = _UserObjectFlags()
        needed = ctypes.c_uint32(0)
        user32.GetUserObjectInformationW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        user32.GetUserObjectInformationW.restype = ctypes.c_int
        ok = user32.GetUserObjectInformationW(
            hwinsta,
            1,  # UOI_FLAGS
            ctypes.byref(flags),
            ctypes.sizeof(flags),
            ctypes.byref(needed),
        )
        if not ok:
            return False
        return bool(flags.dwFlags & 0x0001)  # WSF_VISIBLE
    except Exception:
        return False


def prompt_interactive_operator_confirmation(context: Dict[str, Any], *, timeout_seconds: int = 60) -> bool:
    """Fail-closed out-of-band OS modal dialog confirmation unavailable to API/LLM agents."""
    if (
        os.environ.get("PYTEST_CURRENT_TEST")
        or os.environ.get("CI")
        or os.environ.get("NOEMETRA_ACK_HEADLESS") == "1"
        or context.get("remote_client") is True
    ):
        return False

    timeout = max(5, min(300, int(timeout_seconds)))
    title, msg = _build_confirmation_prompt(context)

    try:
        if sys.platform == "win32":
            if not _windows_has_interactive_desktop():
                return False
            proc = subprocess.run(
                [sys.executable, "-c", _WIN_MSGBOX_SCRIPT],
                input=json.dumps({"title": title, "message": msg}),
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return proc.returncode == 0

        if sys.platform == "darwin":
            if not shutil.which("osascript"):
                return False
            script = (
                "on run argv\n"
                "  set t to item 1 of argv\n"
                "  set m to item 2 of argv\n"
                f"  display dialog m with title t buttons {{\"Annulla\", \"Approva Patch\"}} "
                f"default button \"Annulla\" cancel button \"Annulla\" with icon caution giving up after {timeout}\n"
                "end run"
            )
            proc = subprocess.run(
                ["osascript", "-e", script, "--", title, msg],
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False,
            )
            return (
                proc.returncode == 0
                and "button returned:Approva Patch" in (proc.stdout or "")
                and "gave up:true" not in (proc.stdout or "")
            )

        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return False
        if shutil.which("zenity"):
            proc = subprocess.run(
                [
                    "zenity",
                    "--question",
                    "--default-cancel",
                    f"--timeout={timeout}",
                    f"--title={title}",
                    f"--text={msg}",
                ],
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False,
            )
            return proc.returncode == 0
        if shutil.which("kdialog"):
            proc = subprocess.run(
                ["kdialog", "--title", title, "--warningyesno", msg],
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False,
            )
            return proc.returncode == 0
        return False
    except Exception:
        return False
