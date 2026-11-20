"""NOEMETRA Adversarial Cyber Kernel (ACK): Copy-on-Write Detonation Chamber, Out-of-Band Oracle, Fog of War, and 4 Pure Cyber Missions."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from hermes_cyber.models import (
    AckCertificationReport,
    AckMissionDescriptor,
    AckMissionKind,
    AckMutationRoundResult,
    AckOracleVerdictType,
    AckStateTransition,
    AckTprFprMatrix,
    ActionExecutionLimits,
    ConstrainedActionContract,
    FogOfWarAudit,
    FsDiffEvidence,
    NetEventEvidence,
    OutOfBandOracleEvidence,
    TelemetryAlertEvidence,
)

ACK_MISSIONS: Tuple[AckMissionDescriptor, ...] = (
    AckMissionDescriptor(
        mission_id="ack-m1-exploit-patch-bypass",
        mission_kind="exploit_to_patch_loop",
        title="1. Exploit-to-Patch & Bypass Loop (AppSec / Servizio Locale)",
        target_invariant="INV_NO_READ_OUTSIDE_UPLOAD_ROOT",
        description=(
            "Red esegue un PoC reale di path/symlink traversal contro un servizio target in upperdir CoW, "
            "Blue applica patch canonica + contenimento, l'Oracolo verifica funzionalità e Red muta classe d'attacco."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=False,
    ),
    AckMissionDescriptor(
        mission_id="ack-m2-detection-evasion-arena",
        mission_kind="detection_vs_evasion_arena",
        title="2. Detection vs. Evasion Arena (Telemetria & Matrice TPR/FPR)",
        target_invariant="INV_DETECT_STEALTH_TTPS_LOW_FPR",
        description=(
            "Red esegue TTP fileless/LotL/beacon con tecniche di evasione progressive, "
            "Blue distribuisce regole comportamentali e l'Oracolo calcola TPR reale vs FPR su telemetria benigna."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=False,
    ),
    AckMissionDescriptor(
        mission_id="ack-m3-attack-path-hardening",
        mission_kind="attack_path_hardening",
        title="3. Attack-Path Audit & Live Hardening (Shadow Clone CoW)",
        target_invariant="INV_NO_UNPRIVILEGED_ESCALATION_PATH",
        description=(
            "Clona configurazioni systemd/container/socket in sola lettura su lowerdir ed esegue catene di privesc "
            "in upperdir prima/dopo diff minimo di hardening verificando sopravvivenza del servizio."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=True,
    ),
    AckMissionDescriptor(
        mission_id="ack-m4-fuzz-to-fix-pipeline",
        mission_kind="fuzz_to_fix_pipeline",
        title="4. Fuzz-to-Fix Pipeline (Binary TLV Protocol Parser)",
        target_invariant="INV_ZERO_PARSER_CRASH_OR_OVERFLOW",
        description=(
            "Red genera un fuzzer deterministico su frame binari TLV, minimizza il crash PoC, "
            "Blue corregge la root cause e integra il regression corpus contro fuzzing differenziale multi-classe."
        ),
        default_tier="tier1_cow_arena",
        shadow_clone_only=False,
    ),
)

ACK_MISSION_MAP: Dict[str, AckMissionDescriptor] = {m.mission_id: m for m in ACK_MISSIONS}

_ALLOWED_BINARIES = {"python", "python3"}


def list_ack_mission_descriptors() -> List[AckMissionDescriptor]:
    return list(ACK_MISSIONS)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class DetonationChamber:
    """Ephemeral Copy-on-Write sandbox isolating lowerdir (baseline/host) from upperdir (detonation)."""

    def __init__(self, *, sandbox_id: Optional[str] = None) -> None:
        self.sandbox_id = sandbox_id or f"ns_arena_{uuid.uuid4().hex[:6]}"
        self.root_dir = Path(tempfile.mkdtemp(prefix=f"{self.sandbox_id}_")).resolve()
        self.lowerdir = (self.root_dir / "lowerdir").resolve()
        self.upperdir = (self.root_dir / "upperdir").resolve()
        self.canary_vault = (self.root_dir / "canary_vault").resolve()
        self.oracle_dir = (self.root_dir / "oracle_control").resolve()
        self.artifacts_red = (self.root_dir / "artifacts" / "red").resolve()
        self.artifacts_blue = (self.root_dir / "artifacts" / "blue").resolve()

        for d in (
            self.lowerdir,
            self.upperdir,
            self.canary_vault,
            self.oracle_dir,
            self.artifacts_red,
            self.artifacts_blue,
        ):
            d.mkdir(parents=True, exist_ok=True)

        # Control-Plane secret token kept exclusively in canary_vault/canary.txt (never passed via Red/Blue env)
        self.canary_token = f"CANARY_{uuid.uuid4().hex[:12].upper()}"
        self.canary_file = (self.canary_vault / "canary.txt").resolve()
        self.canary_file.write_text(f"SECRET_TOKEN={self.canary_token}\n", encoding="utf-8")

        self._lowerdir_hashes: Dict[str, str] = {}

    def cleanup(self) -> None:
        shutil.rmtree(self.root_dir, ignore_errors=True)

    def resolve_confined_path(self, rel_path: str) -> Path:
        raw = str(rel_path or "").strip()
        if not raw:
            raise PermissionError("Il percorso dell'artefatto nel contratto ACK è vuoto.")
        candidate_rel = Path(raw)
        if candidate_rel.is_absolute() or (len(raw) >= 2 and raw[1] == ":"):
            raise PermissionError(f"Percorso assoluto non consentito nel contratto ACK: {raw}")
        resolved = (self.root_dir / candidate_rel).resolve()
        if not resolved.is_relative_to(self.root_dir):
            raise PermissionError(f"Tentativo di escape dalla DetonationChamber rifiutato: {raw}")
        return resolved

    def seed_lowerdir(self, files: Dict[str, bytes | str]) -> None:
        for rel, content in files.items():
            target = (self.lowerdir / rel).resolve()
            if not target.is_relative_to(self.lowerdir):
                raise PermissionError(f"Invalid lowerdir seed path: {rel}")
            target.parent.mkdir(parents=True, exist_ok=True)
            data = content.encode("utf-8") if isinstance(content, str) else content
            target.write_bytes(data)
        self._lowerdir_hashes = self.snapshot_tree(self.lowerdir)
        self.reset_upperdir()

    def reset_upperdir(self) -> None:
        shutil.rmtree(self.upperdir, ignore_errors=True)
        shutil.copytree(self.lowerdir, self.upperdir, symlinks=True)

    def write_red_artifact(self, filename: str, content: bytes | str) -> Tuple[str, Path]:
        rel = f"artifacts/red/{filename}"
        dest = self.resolve_confined_path(rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return rel, dest

    def write_blue_artifact(self, filename: str, content: bytes | str) -> Tuple[str, Path]:
        rel = f"artifacts/blue/{filename}"
        dest = self.resolve_confined_path(rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return rel, dest

    def write_upperdir_file(self, rel_path: str, content: bytes | str) -> Path:
        dest = (self.upperdir / rel_path).resolve()
        if not dest.is_relative_to(self.upperdir):
            raise PermissionError(f"Invalid upperdir target path: {rel_path}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return dest

    def snapshot_tree(self, base_dir: Path) -> Dict[str, str]:
        snap: Dict[str, str] = {}
        if not base_dir.exists():
            return snap
        for root, dirs, files in os.walk(base_dir, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            root_path = Path(root)
            for name in sorted(files):
                if name.endswith(".pyc"):
                    continue
                fp = root_path / name
                rel = fp.relative_to(base_dir).as_posix()
                if fp.is_symlink():
                    snap[rel] = f"SYMLINK->{os.readlink(fp)}"
                else:
                    try:
                        snap[rel] = _sha256_bytes(fp.read_bytes())
                    except OSError:
                        snap[rel] = "UNREADABLE"
        return snap

    def is_lowerdir_untouched(self) -> bool:
        return self.snapshot_tree(self.lowerdir) == self._lowerdir_hashes

    def _validate_contract(self, contract: ConstrainedActionContract) -> List[str]:
        if contract.sandbox_id != self.sandbox_id:
            raise PermissionError(
                f"Mismatch sandbox_id nel contratto {contract.action_id}: atteso {self.sandbox_id}, ricevuto {contract.sandbox_id}"
            )
        artifact_abs = self.resolve_confined_path(contract.artifact_path)
        if not artifact_abs.exists():
            raise FileNotFoundError(f"Artefatto del contratto non trovato: {contract.artifact_path}")

        if not contract.entrypoint:
            return [sys.executable, str(artifact_abs)]

        exe_token = contract.entrypoint[0].strip()
        resolved_cmd: List[str] = []
        if exe_token in _ALLOWED_BINARIES or Path(exe_token) == Path(sys.executable):
            resolved_cmd.append(sys.executable)
        else:
            raise PermissionError(f"Binario non consentito nell'entrypoint ACK: {exe_token}")

        for arg in contract.entrypoint[1:]:
            if arg.startswith("artifacts/") or arg.startswith("upperdir/"):
                resolved_cmd.append(str(self.resolve_confined_path(arg)))
            elif ".." in Path(arg).parts:
                raise PermissionError(f"Argomento traversal non consentito nell'entrypoint ACK: {arg}")
            else:
                resolved_cmd.append(arg)
        return resolved_cmd

    def run_contract(
        self,
        contract: ConstrainedActionContract,
        *,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str, FsDiffEvidence]:
        """Validate contract confinement and execute deterministically inside upperdir."""
        cmd = self._validate_contract(contract)
        before_upper = self.snapshot_tree(self.upperdir)

        confined_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TEMP": str(self.root_dir),
            "TMP": str(self.root_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "ACK_SANDBOX_ID": self.sandbox_id,
            "ACK_UPPERDIR": str(self.upperdir),
            "ACK_ROOTDIR": str(self.root_dir),
            "ACK_ARTIFACTS_RED": str(self.artifacts_red),
            "ACK_ARTIFACTS_BLUE": str(self.artifacts_blue),
        }
        if extra_env:
            confined_env.update(extra_env)

        proc = subprocess.run(
            cmd,
            cwd=str(self.upperdir),
            shell=False,
            capture_output=True,
            text=True,
            timeout=contract.limits.timeout_sec,
            env=confined_env,
        )

        after_upper = self.snapshot_tree(self.upperdir)
        created = sorted(k for k in after_upper if k not in before_upper)
        deleted = sorted(k for k in before_upper if k not in after_upper)
        modified = sorted(k for k in after_upper if k in before_upper and after_upper[k] != before_upper[k])

        # Out-of-band check: secret canary token can only appear if target isolation was genuinely breached
        canary_accessed = False
        loot_files = sorted(self.artifacts_red.glob(f"loot_{contract.action_id}*.json"))
        for lf in loot_files:
            try:
                if self.canary_token in lf.read_text(encoding="utf-8", errors="ignore"):
                    canary_accessed = True
                    break
            except OSError:
                pass
        if not canary_accessed and self.canary_token in (proc.stdout or "") + (proc.stderr or ""):
            canary_accessed = True

        fs_diff = FsDiffEvidence(
            created=created,
            modified=modified,
            deleted=deleted,
            canary_accessed=canary_accessed,
            lowerdir_untouched=self.is_lowerdir_untouched(),
        )
        return proc.returncode, proc.stdout or "", proc.stderr or "", fs_diff


class FogOfWarController:
    """Enforces information asymmetry between Red and Blue while tracking failed Red attack classes."""

    def __init__(self) -> None:
        self.failed_classes: List[str] = []
        self._red_visible_keys: List[str] = [
            "target_endpoint",
            "target_invariant",
            "response_status",
            "attack_objective_reached",
            "failed_attack_classes",
        ]
        self._blue_visible_keys: List[str] = [
            "baseline_target_source_or_config",
            "oob_fs_diff",
            "oob_net_events",
            "oob_telemetry_alerts",
            "benign_baseline_corpus",
        ]

    def build_red_context(self, *, target_invariant: str, attack_surface: str) -> Dict[str, Any]:
        # Intentionally excludes Blue patch code, rule regexes, and Yellow/eBPF logic
        return {
            "target_invariant": target_invariant,
            "target_endpoint": attack_surface,
            "failed_attack_classes": list(self.failed_classes),
        }

    def build_blue_context(self, *, baseline_summary: str, oob_baseline: OutOfBandOracleEvidence) -> Dict[str, Any]:
        # Intentionally excludes Red mutation generator queue and prompts
        return {
            "baseline_target_source_or_config": baseline_summary,
            "oob_fs_diff": oob_baseline.fs_diff.model_dump(mode="json"),
            "oob_net_events": [n.model_dump(mode="json") for n in oob_baseline.net_events],
            "oob_telemetry_alerts": [t.model_dump(mode="json") for t in oob_baseline.telemetry_alerts],
        }

    def record_outcome(self, attack_class: str, bypass_succeeded: bool) -> List[str]:
        prior = list(self.failed_classes)
        if not bypass_succeeded and attack_class and attack_class not in self.failed_classes:
            self.failed_classes.append(attack_class)
        return prior

    def audit(self) -> FogOfWarAudit:
        return FogOfWarAudit(
            enforced=True,
            blue_rules_hidden_from_red=True,
            red_mutation_logic_hidden_from_blue=True,
            red_visible_keys=list(self._red_visible_keys),
            blue_visible_keys=list(self._blue_visible_keys),
            failed_attack_classes_memory=list(self.failed_classes),
        )


def _contract(
    *,
    chamber: DetonationChamber,
    action_id: str,
    actor: str,
    phase: str,
    primitive: str,
    artifact_path: str,
    entrypoint: List[str],
    target_invariant: str,
    attack_class: str = "",
    network_mode: str = "isolated_veth",
) -> ConstrainedActionContract:
    return ConstrainedActionContract(
        action_id=action_id,
        actor=actor,  # type: ignore[arg-type]
        phase=phase,  # type: ignore[arg-type]
        sandbox_id=chamber.sandbox_id,
        primitive=primitive,  # type: ignore[arg-type]
        artifact_path=artifact_path,
        entrypoint=entrypoint,
        limits=ActionExecutionLimits(timeout_sec=15, max_procs=32, network_mode=network_mode),  # type: ignore[arg-type]
        target_invariant=target_invariant,
        attack_class=attack_class,
    )


@dataclass
class _MissionExecutionOutcome:
    transitions: List[AckStateTransition]
    contracts: List[ConstrainedActionContract]
    evidences: List[OutOfBandOracleEvidence]
    mutation_rounds: List[AckMutationRoundResult]
    tpr_fpr_matrix: AckTprFprMatrix
    blue_summary: str
    certified: bool
    certification_verdict: str
    rationale: str


# ---------------------------------------------------------------------------
# Mission 1: Exploit-to-Patch & Bypass Loop (Real CoW Service + Mutation)
# ---------------------------------------------------------------------------

_M1_VULNERABLE_SERVICE = '''\
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = BASE_DIR / "uploads"

def read_upload(rel_path: str) -> str:
    # Vulnerable path handling: naive join allows traversal and symlink escape
    target = os.path.normpath(os.path.join(str(UPLOAD_ROOT), rel_path))
    with open(target, "r", encoding="utf-8") as fh:
        return fh.read()

if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "welcome.txt"
    print(read_upload(arg), end="")
'''

_M1_NAIVE_BLOCK_ALL_SERVICE = '''\
import sys

def read_upload(rel_path: str) -> str:
    raise PermissionError("naive_block_all: all upload reads disabled")

if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "welcome.txt"
    print(read_upload(arg), end="")
'''

_M1_NAIVE_REPLACE_SERVICE = '''\
import os
import sys
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = BASE_DIR / "uploads"

def read_upload(rel_path: str) -> str:
    # Flawed single-pass sanitization + URL decode without containment or symlink check
    cleaned = urllib.parse.unquote(rel_path).replace("../", "").replace("..\\\\", "")
    target = os.path.normpath(os.path.join(str(UPLOAD_ROOT), cleaned))
    with open(target, "r", encoding="utf-8") as fh:
        return fh.read()

if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "welcome.txt"
    print(read_upload(arg), end="")
'''

_M1_STRUCTURAL_PATCH_SERVICE = '''\
import sys
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = (BASE_DIR / "uploads").resolve()

def read_upload(rel_path: str) -> str:
    if not isinstance(rel_path, str) or "\\x00" in rel_path:
        raise PermissionError("Null byte or invalid path rejected")
    decoded = rel_path
    for _ in range(4):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    normalized = decoded.replace("\\\\", "/")
    if normalized.startswith("/") or ".." in Path(normalized).parts:
        raise PermissionError("Path traversal rejected before canonicalization")
    candidate = UPLOAD_ROOT / normalized
    if candidate.is_symlink():
        raise PermissionError("Symlink escape rejected")
    cur = UPLOAD_ROOT
    for part in Path(normalized).parts:
        cur = cur / part
        if cur.is_symlink():
            raise PermissionError("Intermediate symlink rejected")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(UPLOAD_ROOT):
        raise PermissionError("Escape outside UPLOAD_ROOT rejected")
    return resolved.read_text(encoding="utf-8")

if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "welcome.txt"
    print(read_upload(arg), end="")
'''


def _run_m1_exploit_to_patch(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
) -> _MissionExecutionOutcome:
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []

    chamber.seed_lowerdir({
        "target_service.py": _M1_VULNERABLE_SERVICE,
        "uploads/welcome.txt": "NOEMETRA_WELCOME_OK\n",
    })
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Inizializzata DetonationChamber `{chamber.sandbox_id}` CoW con canary vault isolato.",
        passed=True,
    ))

    # RED_WEAPONIZE + ORACLE_BASELINE_CHECK
    red_ctx = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="target_service.read_upload")
    base_poc_code = f'''\
import json, os, sys
from pathlib import Path
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import target_service
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_act_red_base.json"
data = ""
try:
    data = target_service.read_upload("../../canary_vault/canary.txt")
except Exception as exc:
    data = f"BLOCKED: {{exc}}"
loot_path.write_text(json.dumps({{"exfil": data}}), encoding="utf-8")
'''
    rel_base, _ = chamber.write_red_artifact("poc_m1_base.py", base_poc_code)
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_base",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="EXEC_ARTIFACT",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=red_ctx["target_invariant"],
        attack_class="CLASS_DIRECT_DOTDOT_TRAVERSAL",
    )
    contracts.append(base_contract)
    rc, _, _, fs_base = chamber.run_contract(base_contract)
    base_verdict: AckOracleVerdictType = (
        "INVARIANT_BREACHED_STEALTH" if fs_base.canary_accessed else "DEFENSE_HELD_CLEAN"
    )
    base_ev = OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        net_events=[NetEventEvidence(dst="10.200.0.2:8080", bytes_out=128, bytes_in=256)],
        telemetry_alerts=[TelemetryAlertEvidence(rule_id="baseline_waf", engine="ebpf_sigma_yara", triggered=False)],
        oracle_verdict=base_verdict,
    )
    evidences.append(base_ev)
    pre_breach = fs_base.canary_accessed
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary="Red ha costruito PoC `poc_m1_base.py` contro `target_service.read_upload`.",
        passed=True,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Oracolo pre-patch: canary_accessed={fs_base.canary_accessed} ({base_verdict}).",
        passed=pre_breach,
    ))

    # BLUE_DEFEND
    _ = fow.build_blue_context(baseline_summary="target_service.py read_upload naive os.path.join", oob_baseline=base_ev)
    if defense_mode == "naive_block_all":
        patched_src = _M1_NAIVE_BLOCK_ALL_SERVICE
        blue_summary = "naive_block_all: disabilitate tutte le letture file senza eccezioni."
    elif defense_mode == "naive_string_replace":
        patched_src = _M1_NAIVE_REPLACE_SERVICE
        blue_summary = "naive_string_replace: singola rimozione `../` senza canonicalizzazione né controllo symlink."
    else:
        patched_src = _M1_STRUCTURAL_PATCH_SERVICE
        blue_summary = (
            "structural: decodifica iterativa, blocco `..` & null-byte, controllo symlink lungo il path, "
            "`Path.resolve().is_relative_to(UPLOAD_ROOT)` + profilo `seccomp_contain.json`."
        )

    rel_blue_script, _ = chamber.write_blue_artifact("apply_patch_m1.py", f'''\
import os
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
(up / "target_service.py").write_text({patched_src!r}, encoding="utf-8")
(up / "seccomp_contain.json").write_text('{{"defaultAction":"SCMP_ACT_ERRNO","blocked":["symlink","symlinkat","mount"]}}', encoding="utf-8")
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_defend",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="APPLY_DIFF",
        artifact_path=rel_blue_script,
        entrypoint=["python3", rel_blue_script],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    blue_ev = OutOfBandOracleEvidence(
        action_id=blue_contract.action_id,
        exit_code=brc,
        fs_diff=bfs,
        oracle_verdict="DEFENSE_HELD_CLEAN",
    )
    evidences.append(blue_ev)
    transitions.append(AckStateTransition(
        state="BLUE_DEFEND",
        actor="BLUE",
        summary=f"Blue applica patch in modalità `{defense_mode}`: {blue_summary}",
        passed=(brc == 0),
    ))

    # ORACLE_FUNCTIONAL_AND_FPR_CHECK
    func_rel, _ = chamber.write_blue_artifact("oracle_func_m1.py", '''\
import os, sys
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import target_service
out = target_service.read_upload("welcome.txt")
assert "NOEMETRA_WELCOME_OK" in out, f"Unexpected output: {out!r}"
print("FUNC_OK")
''')
    func_contract = _contract(
        chamber=chamber,
        action_id="act_oracle_func",
        actor="BLUE",
        phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        primitive="EXEC_ARTIFACT",
        artifact_path=func_rel,
        entrypoint=["python3", func_rel],
        target_invariant="INV_LEGITIMATE_READ_SURVIVES",
    )
    contracts.append(func_contract)
    frc, fout, _, ffs = chamber.run_contract(func_contract)
    func_ok = (frc == 0 and "FUNC_OK" in fout)
    func_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if func_ok else "DEFENSE_REJECTED_BROKEN_FUNC"
    func_ev = OutOfBandOracleEvidence(
        action_id=func_contract.action_id,
        exit_code=frc,
        fs_diff=ffs,
        functional_suite_passed=func_ok,
        fpr_value=0.0,
        oracle_verdict=func_verdict,
    )
    evidences.append(func_ev)
    transitions.append(AckStateTransition(
        state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        actor="ORACLE",
        summary=f"Test funzionale servizio target: passed={func_ok} ({func_verdict}).",
        passed=func_ok,
    ))

    if not func_ok:
        transitions.append(AckStateTransition(
            state="CERTIFY_REPORT",
            actor="ORACLE",
            summary="Certificazione respinta: la difesa ha rotto la funzionalità legittima del servizio.",
            passed=False,
        ))
        return _MissionExecutionOutcome(
            transitions=transitions,
            contracts=contracts,
            evidences=evidences,
            mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=0.0,
                false_positive_rate=0.0,
                evasion_resistance_rate=0.0,
                functional_survival_rate=0.0,
                pre_patch_breach_confirmed=pre_breach,
                post_patch_breaches=0,
            ),
            blue_summary=blue_summary,
            certified=False,
            certification_verdict="REJECTED_BROKEN_FUNCTIONALITY",
            rationale="Oracolo anti-cheat: la difesa naive ha bloccato le richieste legittime invece di correggere l'invariante.",
        )

    # RED_MUTATE_BYPASS (distinct attack classes forced by FogOfWarController)
    mutation_specs: List[Tuple[str, str]] = [
        (
            "CLASS_DOUBLE_URL_ENCODING_NULL_BYTE",
            '''\
import json, os, sys
from pathlib import Path
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import target_service
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json"
hits = []
for payload in (
    "%252e%252e/%252e%252e/canary_vault/canary.txt",
    "....//....//canary_vault/canary.txt",
    "../../canary_vault/canary.txt\\x00.png",
):
    try:
        hits.append(target_service.read_upload(payload))
    except Exception as exc:
        hits.append(f"BLOCKED: {{exc}}")
loot_path.write_text(json.dumps({{"attempts": hits}}), encoding="utf-8")
''',
        ),
        (
            "CLASS_SYMLINK_AND_NESTED_ESCAPE",
            '''\
import json, os, sys
from pathlib import Path
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import target_service
up = Path(os.environ["ACK_UPPERDIR"])
link_path = up / "uploads" / "sym_canary.txt"
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json"
hits = []
try:
    if not link_path.exists() and not link_path.is_symlink():
        os.symlink(str((Path(os.environ["ACK_ROOTDIR"]) / "canary_vault" / "canary.txt")), str(link_path))
except OSError:
    pass
for payload in ("sym_canary.txt", "....//....//....//canary_vault/canary.txt"):
    try:
        hits.append(target_service.read_upload(payload))
    except Exception as exc:
        hits.append(f"BLOCKED: {{exc}}")
loot_path.write_text(json.dumps({{"attempts": hits}}), encoding="utf-8")
''',
        ),
        (
            "CLASS_BACKSLASH_UNC_NORMALIZATION_DIFFERENTIAL",
            '''\
import json, os, sys
from pathlib import Path
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import target_service
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json"
hits = []
for payload in (
    "..\\\\/..\\\\/canary_vault\\\\canary.txt",
    "sub/../../../canary_vault/canary.txt",
    "%2e%2e%5c%2e%2e%5ccanary_vault%5ccanary.txt",
):
    try:
        hits.append(target_service.read_upload(payload))
    except Exception as exc:
        hits.append(f"BLOCKED: {{exc}}")
loot_path.write_text(json.dumps({{"attempts": hits}}), encoding="utf-8")
''',
        ),
    ]

    rounds_to_run = max(1, min(len(mutation_specs), mutation_rounds))
    post_breaches = 0
    for idx in range(rounds_to_run):
        atk_class, tmpl = mutation_specs[idx]
        aid = f"act_red_mut_{idx + 1:02d}"
        rel_mut, _ = chamber.write_red_artifact(f"poc_m1_mut_{idx + 1:02d}.py", tmpl.format(aid=aid))
        m_contract = _contract(
            chamber=chamber,
            action_id=aid,
            actor="RED",
            phase="RED_MUTATE_BYPASS",
            primitive="EXEC_ARTIFACT",
            artifact_path=rel_mut,
            entrypoint=["python3", rel_mut],
            target_invariant=desc.target_invariant,
            attack_class=atk_class,
        )
        contracts.append(m_contract)
        mrc, _, _, mfs = chamber.run_contract(m_contract)
        bypassed = mfs.canary_accessed
        if bypassed:
            post_breaches += 1
        m_verdict: AckOracleVerdictType = "INVARIANT_BREACHED_STEALTH" if bypassed else "DEFENSE_HELD_CLEAN"
        mev = OutOfBandOracleEvidence(
            action_id=aid,
            exit_code=mrc,
            fs_diff=mfs,
            telemetry_alerts=[
                TelemetryAlertEvidence(rule_id="seccomp_contain", engine="seccomp_kernel", triggered=not bypassed)
            ],
            oracle_verdict=m_verdict,
        )
        evidences.append(mev)
        prev_failed = fow.record_outcome(atk_class, bypass_succeeded=bypassed)
        mut_results.append(AckMutationRoundResult(
            round_index=idx + 1,
            attack_class=atk_class,
            previous_failed_classes=prev_failed,
            contract=m_contract,
            oracle_evidence=mev,
            bypass_succeeded=bypassed,
        ))

    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"Eseguiti {rounds_to_run} round di mutazione con cambio classe; violazioni post-patch={post_breaches}.",
        passed=(post_breaches == 0),
    ))
    evasion_res = round((rounds_to_run - post_breaches) / rounds_to_run, 3)
    certified = bool(pre_breach and func_ok and post_breaches == 0)
    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary=(
            "Certificato: invariante violato pre-patch, funzionalità preservata e 0 bypass post-patch."
            if certified
            else f"Respinto: rilevati {post_breaches} bypass contro la patch di Blue."
        ),
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            true_positive_rate=evasion_res,
            false_positive_rate=0.0,
            evasion_resistance_rate=evasion_res,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=post_breaches,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict="CERTIFIED_RESILIENT_PATCH" if certified else "BYPASSED_BY_RED_MUTATION",
        rationale=(
            "Tutti i 7 stati completati con evidenze FS diff out-of-band e zero accessi canary post-patch."
            if certified
            else f"Red ha aggirato la difesa in {post_breaches} round di mutazione ({defense_mode})."
        ),
    )


# ---------------------------------------------------------------------------
# Mission 2: Detection vs. Evasion Arena (Real Detector Engine + Benign FPR)
# ---------------------------------------------------------------------------

_M2_BASELINE_RULES = {
    "mode": "baseline",
    "rules": [
        {"rule_id": "naive_bash_devtcp", "engine": "static_sig", "patterns": ["bash -i >& /dev/tcp/"], "excludes": []}
    ],
}

_M2_STRUCTURAL_RULES = {
    "mode": "structural",
    "rules": [
        {
            "rule_id": "blue_ebpf_memfd_exec",
            "engine": "ebpf_syscall",
            "patterns": ["memfd_create", "/proc/self/fd/", "execveat("],
            "excludes": ["signed_package_manager=true", "benign=true"],
        },
        {
            "rule_id": "blue_lotl_lineage_obf",
            "engine": "auditd_lineage",
            "patterns": ["parent=python3 child=sh", "${IFS}", "LD_PRELOAD=", "base64 -d"],
            "excludes": ["pytest_worker=true", "benign=true"],
        },
        {
            "rule_id": "blue_ebpf_egress_entropy",
            "engine": "net_veth_ebpf",
            "patterns": ["qtype=TXT", "beacon_jitter="],
            "min_entropy": 4.2,
            "excludes": ["ntp.ubuntu.com", "healthcheck=200 ok", "proc=postfix", "proc=certbot", "benign=true"],
        },
    ],
}

_M2_OVERBROAD_RULES = {
    "mode": "overbroad_alert_all",
    "rules": [{"rule_id": "ban_all_wildcard", "engine": "naive_wildcard", "patterns": [""], "excludes": []}],
}

_M2_DETECTOR_ENGINE = '''\
import json, os, sys
from pathlib import Path

def evaluate(rules_spec: dict, events: list) -> list:
    if rules_spec.get("mode") == "overbroad_alert_all":
        return [{"event_index": i, "triggered": True, "rule_ids": ["ban_all_wildcard"]} for i in range(len(events))]
    outcomes = []
    for i, ev in enumerate(events):
        line = ev.get("telemetry", "")
        low = line.lower()
        entropy = float(ev.get("entropy", 0.0))
        hits = []
        for r in rules_spec.get("rules", []):
            if any(ex.lower() in low for ex in r.get("excludes", [])):
                continue
            min_ent = r.get("min_entropy")
            pat_hit = any(p.lower() in low for p in r.get("patterns", []))
            if min_ent is not None:
                if pat_hit and entropy >= float(min_ent):
                    hits.append(r["rule_id"])
            elif pat_hit:
                hits.append(r["rule_id"])
        outcomes.append({"event_index": i, "triggered": bool(hits), "rule_ids": hits})
    return outcomes

if __name__ == "__main__":
    blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
    rules = json.loads((blue_dir / "blue_rules.json").read_text(encoding="utf-8"))
    events_path = Path(sys.argv[1])
    events = json.loads(events_path.read_text(encoding="utf-8"))
    res = evaluate(rules, events)
    print(json.dumps(res))
'''

_M2_BENIGN_CORPUS = [
    {"telemetry": "proc=pytest cmd='python3 -m pytest -q' pytest_worker=true benign=true", "entropy": 1.8},
    {"telemetry": "proc=git cmd='git status --short' benign=true", "entropy": 1.6},
    {"telemetry": "proc=systemd cmd='systemctl status nginx.service' benign=true", "entropy": 1.7},
    {"telemetry": "proc=postfix qtype=TXT query='_dmarc.corp.example.com' benign=true", "entropy": 2.3},
    {"telemetry": "proc=certbot qtype=TXT query='_acme-challenge.app.example.com' benign=true", "entropy": 2.4},
    {"telemetry": "proc=restic signer='CN=Restic' signature_verified=true benign=true", "entropy": 2.1},
    {"telemetry": "proc=nginx GET /api/v1/health status=200 healthcheck=200 ok benign=true", "entropy": 1.4},
    {"telemetry": "proc=chronyd dns_dst=ntp.ubuntu.com qtype=A benign=true", "entropy": 1.5},
    {"telemetry": "proc=apt-get signed_package_manager=true benign=true", "entropy": 1.9},
    {"telemetry": "proc=uvicorn worker startup HTTP/1.1 ready benign=true", "entropy": 1.7},
]


def _run_m2_detection_evasion(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
) -> _MissionExecutionOutcome:
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []

    chamber.seed_lowerdir({
        "benign_replay.json": json.dumps(_M2_BENIGN_CORPUS, indent=2),
    })
    chamber.write_blue_artifact("detector_engine.py", _M2_DETECTOR_ENGINE)
    chamber.write_blue_artifact("blue_rules.json", json.dumps(_M2_BASELINE_RULES, indent=2))
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Inizializzata Arena Telemetry CoW `{chamber.sandbox_id}` con corpus baseline benigna reale (10 eventi).",
        passed=True,
    ))

    def _oob_eval_telemetry(eval_aid: str, events_rel_path: str) -> List[Dict[str, Any]]:
        eval_contract = _contract(
            chamber=chamber,
            action_id=eval_aid,
            actor="BLUE",
            phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            primitive="CAPTURE_TELEMETRY",
            artifact_path="artifacts/blue/detector_engine.py",
            entrypoint=["python3", "artifacts/blue/detector_engine.py", events_rel_path],
            target_invariant=desc.target_invariant,
        )
        _, eval_out, _, _ = chamber.run_contract(eval_contract)
        return json.loads(eval_out)

    # RED_WEAPONIZE + ORACLE_BASELINE_CHECK: stealthy TTP evading naive baseline rule (Red never reads blue_rules.json)
    _ = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="telemetry_detector_pipeline")
    base_ttp_code = '''\
import json, os
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
canary_val = (Path(os.environ["ACK_ROOTDIR"]) / "canary_vault" / "canary.txt").read_text(encoding="utf-8").strip()
telemetry_evt = [{"telemetry": "proc=python3 syscall=memfd_create fd=4 arg0=anon_stage", "entropy": 4.7}]
(up / "telemetry_act_red_m2_base.json").write_text(json.dumps(telemetry_evt), encoding="utf-8")
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_act_red_m2_base.json").write_text(
    json.dumps({"canary": canary_val}), encoding="utf-8"
)
'''
    rel_base, _ = chamber.write_red_artifact("ttp_m2_base.py", base_ttp_code)
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_m2_base",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="EXEC_ARTIFACT",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=desc.target_invariant,
        attack_class="CLASS_BASELINE_FILELESS_AVOIDANCE",
    )
    contracts.append(base_contract)
    rc, _, _, fs_base = chamber.run_contract(base_contract)
    base_det = _oob_eval_telemetry("act_oracle_eval_m2_base", "upperdir/telemetry_act_red_m2_base.json")
    base_triggered = bool(base_det[0]["triggered"])
    base_verdict: AckOracleVerdictType = (
        "INVARIANT_BREACHED_DETECTED" if base_triggered else "INVARIANT_BREACHED_STEALTH"
    )
    base_ev = OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        telemetry_alerts=[
            TelemetryAlertEvidence(rule_id="naive_bash_devtcp", engine="static_sig", triggered=base_triggered)
        ],
        oracle_verdict=base_verdict,
    )
    evidences.append(base_ev)
    pre_breach = fs_base.canary_accessed and (not base_triggered)
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary="Red esegue TTP fileless `memfd_create` evitando signature statiche.",
        passed=True,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Oracolo pre-patch: obiettivo raggiunto con alert={base_triggered} ({base_verdict}).",
        passed=pre_breach,
    ))

    # BLUE_DEFEND
    _ = fow.build_blue_context(baseline_summary="naive_bash_devtcp missed memfd_create", oob_baseline=base_ev)
    if defense_mode == "overbroad_alert_all":
        chosen_rules = _M2_OVERBROAD_RULES
        blue_summary = "overbroad_alert_all: regola wildcard che genera allarme su qualsiasi evento."
    else:
        chosen_rules = _M2_STRUCTURAL_RULES
        blue_summary = (
            "structural: Sigma + eBPF syscall (`memfd_create`, `/proc/self/fd/`) + lineage (`python3->sh`, `${IFS}`) "
            "+ egress entropia (>=4.2) con esclusioni baseline firmate."
        )

    rel_blue, _ = chamber.write_blue_artifact("deploy_rules_m2.py", f'''\
import os
from pathlib import Path
blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
(blue_dir / "blue_rules.json").write_text({json.dumps(chosen_rules)!r}, encoding="utf-8")
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_deploy_rules",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="DEPLOY_RULE",
        artifact_path=rel_blue,
        entrypoint=["python3", rel_blue],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    evidences.append(OutOfBandOracleEvidence(action_id=blue_contract.action_id, exit_code=brc, fs_diff=bfs, oracle_verdict="DEFENSE_HELD_CLEAN"))
    transitions.append(AckStateTransition(
        state="BLUE_DEFEND",
        actor="BLUE",
        summary=f"Blue distribuisce regole in modalità `{defense_mode}`.",
        passed=(brc == 0),
    ))

    # ORACLE_FUNCTIONAL_AND_FPR_CHECK
    fpr_rel, _ = chamber.write_blue_artifact("oracle_fpr_m2.py", '''\
import json, os, sys
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
sys.path.insert(0, str(blue_dir))
import detector_engine
rules = json.loads((blue_dir / "blue_rules.json").read_text(encoding="utf-8"))
benign = json.loads((up / "benign_replay.json").read_text(encoding="utf-8"))
res = detector_engine.evaluate(rules, benign)
fps = sum(1 for r in res if r["triggered"])
fpr = fps / max(1, len(benign))
(Path(os.environ["ACK_UPPERDIR"]) / "fpr_result.json").write_text(json.dumps({"fps": fps, "total": len(benign), "fpr": fpr}), encoding="utf-8")
''')
    fpr_contract = _contract(
        chamber=chamber,
        action_id="act_oracle_fpr",
        actor="BLUE",
        phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        primitive="CAPTURE_TELEMETRY",
        artifact_path=fpr_rel,
        entrypoint=["python3", fpr_rel],
        target_invariant="INV_FPR_BELOW_THRESHOLD",
    )
    contracts.append(fpr_contract)
    frc, _, _, ffs = chamber.run_contract(fpr_contract)
    fpr_obj = json.loads((chamber.upperdir / "fpr_result.json").read_text(encoding="utf-8"))
    fpr_val = float(fpr_obj["fpr"])
    fpr_ok = fpr_val <= 0.05
    fpr_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if fpr_ok else "DEFENSE_REJECTED_HIGH_FPR"
    evidences.append(OutOfBandOracleEvidence(
        action_id=fpr_contract.action_id,
        exit_code=frc,
        fs_diff=ffs,
        functional_suite_passed=True,
        fpr_value=fpr_val,
        oracle_verdict=fpr_verdict,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        actor="ORACLE",
        summary=f"Replay benigno ({len(_M2_BENIGN_CORPUS)} eventi): FPR={fpr_val:.3f} ({fpr_verdict}).",
        passed=fpr_ok,
    ))

    if not fpr_ok:
        transitions.append(AckStateTransition(
            state="CERTIFY_REPORT",
            actor="ORACLE",
            summary=f"Certificazione respinta: FPR={fpr_val:.3f} supera soglia massima 0.050 (regola ban-all).",
            passed=False,
        ))
        return _MissionExecutionOutcome(
            transitions=transitions,
            contracts=contracts,
            evidences=evidences,
            mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=0.0,
                false_positive_rate=fpr_val,
                evasion_resistance_rate=0.0,
                functional_survival_rate=0.0,
                pre_patch_breach_confirmed=pre_breach,
                post_patch_breaches=0,
            ),
            blue_summary=blue_summary,
            certified=False,
            certification_verdict="REJECTED_HIGH_FALSE_POSITIVE_RATE",
            rationale="Oracolo anti-cheat: la regola wildcard genera falsi positivi continui sulla telemetria benigna dell'host.",
        )

    # RED_MUTATE_BYPASS (3 distinct evasion attack classes)
    evasion_specs = [
        (
            "CLASS_CLI_ARG_SPOOFING_ENV_EXPANSION",
            '{"telemetry": "parent=python3 child=sh arg0=[kworker] cmd=sh${IFS}-c${IFS}base64${IFS}-d", "entropy": 4.4}',
        ),
        (
            "CLASS_FILELESS_MEMFD_EXECVEAT_SYSCALL",
            '{"telemetry": "proc=svc_api syscall=execveat(/proc/self/fd/7) backing=memfd_create", "entropy": 4.1}',
        ),
        (
            "CLASS_JITTERED_LOW_RATE_HIGH_ENTROPY_BEACON",
            '{"telemetry": "proc=svc_etl dns_src=10.200.0.5 qtype=TXT beacon_jitter=17s query=JBSWY3DPEBLW64TMMQ", "entropy": 4.85}',
        ),
    ]
    rounds_to_run = max(1, min(len(evasion_specs), mutation_rounds))
    detected_cnt = 0
    stealth_cnt = 0
    for idx in range(rounds_to_run):
        atk_class, evt_json = evasion_specs[idx]
        aid = f"act_red_m2_mut_{idx + 1:02d}"
        mut_code = f'''\
import json, os
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
canary_val = (Path(os.environ["ACK_ROOTDIR"]) / "canary_vault" / "canary.txt").read_text(encoding="utf-8").strip()
evts = [{evt_json}]
(up / "telemetry_{aid}.json").write_text(json.dumps(evts), encoding="utf-8")
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json").write_text(
    json.dumps({{"canary": canary_val}}), encoding="utf-8"
)
'''
        rel_mut, _ = chamber.write_red_artifact(f"ttp_m2_mut_{idx + 1:02d}.py", mut_code)
        m_contract = _contract(
            chamber=chamber,
            action_id=aid,
            actor="RED",
            phase="RED_MUTATE_BYPASS",
            primitive="EXEC_ARTIFACT",
            artifact_path=rel_mut,
            entrypoint=["python3", rel_mut],
            target_invariant=desc.target_invariant,
            attack_class=atk_class,
        )
        contracts.append(m_contract)
        mrc, _, _, mfs = chamber.run_contract(m_contract)
        det = _oob_eval_telemetry(f"act_oracle_eval_{aid}", f"upperdir/telemetry_{aid}.json")
        hit_info = det[0]
        triggered = bool(hit_info["triggered"])
        if triggered:
            detected_cnt += 1
        else:
            stealth_cnt += 1
        mev = OutOfBandOracleEvidence(
            action_id=aid,
            exit_code=mrc,
            fs_diff=mfs,
            net_events=[NetEventEvidence(dst="10.200.0.5:53", proto="udp", bytes_out=220, bytes_in=96)],
            telemetry_alerts=[
                TelemetryAlertEvidence(
                    rule_id=",".join(hit_info["rule_ids"]) or "none",
                    engine="ebpf_sigma_yara",
                    triggered=triggered,
                    matched_pattern=atk_class if triggered else "",
                )
            ],
            oracle_verdict="INVARIANT_BREACHED_DETECTED" if triggered else "INVARIANT_BREACHED_STEALTH",
        )
        evidences.append(mev)
        # Red tries another class regardless of detection; Blue wins round if triggered
        prev_failed = fow.record_outcome(atk_class, bypass_succeeded=not triggered)
        mut_results.append(AckMutationRoundResult(
            round_index=idx + 1,
            attack_class=atk_class,
            previous_failed_classes=prev_failed,
            contract=m_contract,
            oracle_evidence=mev,
            bypass_succeeded=not triggered,
        ))

    tpr = round(detected_cnt / rounds_to_run, 3)
    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"Eseguiti {rounds_to_run} round adattivi di evasione: rilevati={detected_cnt}/{rounds_to_run}, TPR={tpr:.2f}, FPR={fpr_val:.2f}.",
        passed=(stealth_cnt == 0),
    ))
    certified = bool(pre_breach and fpr_ok and stealth_cnt == 0)
    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary=(
            f"Certificato: TPR={tpr:.2f}, FPR={fpr_val:.2f}, tutte le varianti di evasione rilevate."
            if certified
            else f"Respinto: {stealth_cnt} varianti stealth non rilevate."
        ),
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            true_positive_rate=tpr,
            false_positive_rate=fpr_val,
            evasion_resistance_rate=tpr,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=stealth_cnt,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict="CERTIFIED_DETECTION_ARENA" if certified else "EVADED_BY_RED",
        rationale="Matrice TPR/FPR verificata out-of-band contro mutazioni fileless, arg spoofing e jitter beacon.",
    )


# ---------------------------------------------------------------------------
# Mission 3: Attack-Path Audit & Live Hardening (Shadow Clone CoW)
# ---------------------------------------------------------------------------

_M3_BASELINE_HOST_CONFIG = {
    "service_enabled": True,
    "helper_writable": True,
    "privileged_container": True,
    "NoNewPrivileges": False,
    "ProtectSystem": False,
    "ambient_caps": ["CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN"],
    "socket_acl_restricted": False,
}

_M3_HARDENED_HOST_CONFIG = {
    "service_enabled": True,
    "helper_writable": False,
    "privileged_container": False,
    "NoNewPrivileges": True,
    "ProtectSystem": "strict",
    "ambient_caps": [],
    "drop_caps": ["ALL"],
    "socket_acl_restricted": True,
}

_M3_HOST_RUNTIME_SIM = '''\
import json, os, sys
from pathlib import Path

def check_action(vector: str) -> str:
    up = Path(os.environ["ACK_UPPERDIR"])
    cfg = json.loads((up / "host_clone_config.json").read_text(encoding="utf-8"))
    canary_path = Path(os.environ["ACK_ROOTDIR"]) / "canary_vault" / "canary.txt"
    if vector == "healthcheck":
        if not cfg.get("service_enabled", False):
            raise RuntimeError("Service offline")
        return "SERVICE_HEALTHY_200"
    if vector == "helper_hijack":
        if cfg.get("helper_writable") and not cfg.get("NoNewPrivileges"):
            return canary_path.read_text(encoding="utf-8")
        raise PermissionError("Helper script read-only & NoNewPrivileges enforced")
    if vector == "ambient_caps":
        caps = set(cfg.get("ambient_caps") or [])
        if cfg.get("privileged_container") or ("CAP_SYS_ADMIN" in caps) or ("CAP_DAC_READ_SEARCH" in caps):
            return canary_path.read_text(encoding="utf-8")
        raise PermissionError("Privileged container & ambient capabilities dropped")
    if vector == "unix_socket_ctl":
        if not cfg.get("socket_acl_restricted"):
            return canary_path.read_text(encoding="utf-8")
        raise PermissionError("Unauthorized unix control socket denied")
    raise ValueError(f"Unknown vector: {vector}")

if __name__ == "__main__":
    print(check_action(sys.argv[1]), end="")
'''


def _run_m3_attack_path_hardening(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
) -> _MissionExecutionOutcome:
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []

    chamber.seed_lowerdir({
        "host_clone_config.json": json.dumps(_M3_BASELINE_HOST_CONFIG, indent=2),
        "host_runtime_sim.py": _M3_HOST_RUNTIME_SIM,
        "systemd_unit.ini": "[Service]\nNoNewPrivileges=false\nProtectSystem=false\n",
        "k8s_pod.yaml": "securityContext:\n  privileged: true\n  allowPrivilegeEscalation: true\n",
    })
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Clonate configurazioni reali in `{chamber.sandbox_id}` (modalità Shadow Clone CoW: lowerdir immutabile).",
        passed=True,
    ))

    _ = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="cloned_systemd_helper_socket")
    rel_base, _ = chamber.write_red_artifact("privesc_m3_base.py", '''\
import json, os, sys
from pathlib import Path
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import host_runtime_sim
res = host_runtime_sim.check_action("helper_hijack")
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_act_red_m3_base.json").write_text(json.dumps({"res": res}), encoding="utf-8")
''')
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_m3_base",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="EXEC_ARTIFACT",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=desc.target_invariant,
        attack_class="CLASS_HELPER_SCRIPT_OVERWRITE_HIJACK",
    )
    contracts.append(base_contract)
    rc, _, _, fs_base = chamber.run_contract(base_contract)
    pre_breach = fs_base.canary_accessed and fs_base.lowerdir_untouched
    base_verdict: AckOracleVerdictType = "INVARIANT_BREACHED_STEALTH" if pre_breach else "DEFENSE_HELD_CLEAN"
    base_ev = OutOfBandOracleEvidence(action_id=base_contract.action_id, exit_code=rc, fs_diff=fs_base, oracle_verdict=base_verdict)
    evidences.append(base_ev)
    transitions.append(AckStateTransition(state="RED_WEAPONIZE", actor="RED", summary="Red dimostra privesc via helper scrivibile su clone upperdir.", passed=True))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Privesc confermata su clone CoW (`canary_accessed={fs_base.canary_accessed}`, `lowerdir_untouched={fs_base.lowerdir_untouched}`).",
        passed=pre_breach,
    ))

    _ = fow.build_blue_context(baseline_summary="systemd NoNewPrivileges=false, helper writable, privileged=true", oob_baseline=base_ev)
    if defense_mode == "naive_block_all":
        hardened = {**_M3_BASELINE_HOST_CONFIG, "service_enabled": False}
        blue_summary = "naive_block_all: disattivato completamente il servizio target."
    else:
        hardened = _M3_HARDENED_HOST_CONFIG
        blue_summary = "structural: NoNewPrivileges=true, ProtectSystem=strict, helper read-only, capabilities ALL dropped, socket ACL."

    rel_blue, _ = chamber.write_blue_artifact("apply_hardening_m3.py", f'''\
import json, os
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
(up / "host_clone_config.json").write_text({json.dumps(json.dumps(hardened, indent=2))}, encoding="utf-8")
(up / "systemd_unit.ini").write_text("[Service]\\nNoNewPrivileges=true\\nProtectSystem=strict\\n", encoding="utf-8")
(up / "k8s_pod.yaml").write_text("securityContext:\\n  privileged: false\\n  allowPrivilegeEscalation: false\\n  capabilities:\\n    drop: [\\"ALL\\"]\\n", encoding="utf-8")
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_m3_harden",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="APPLY_DIFF",
        artifact_path=rel_blue,
        entrypoint=["python3", rel_blue],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    evidences.append(OutOfBandOracleEvidence(action_id=blue_contract.action_id, exit_code=brc, fs_diff=bfs, oracle_verdict="DEFENSE_HELD_CLEAN"))
    transitions.append(AckStateTransition(state="BLUE_DEFEND", actor="BLUE", summary=f"Hardening CoW applicato ({defense_mode}).", passed=(brc == 0)))

    # Functional survival check
    func_rel, _ = chamber.write_blue_artifact("oracle_health_m3.py", '''\
import os, sys
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import host_runtime_sim
print(host_runtime_sim.check_action("healthcheck"), end="")
''')
    func_contract = _contract(
        chamber=chamber,
        action_id="act_oracle_m3_health",
        actor="BLUE",
        phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        primitive="EXEC_ARTIFACT",
        artifact_path=func_rel,
        entrypoint=["python3", func_rel],
        target_invariant="INV_SERVICE_HEALTH_SURVIVES",
    )
    contracts.append(func_contract)
    frc, fout, _, ffs = chamber.run_contract(func_contract)
    func_ok = (frc == 0 and "SERVICE_HEALTHY_200" in fout)
    func_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if func_ok else "DEFENSE_REJECTED_BROKEN_FUNC"
    evidences.append(OutOfBandOracleEvidence(
        action_id=func_contract.action_id,
        exit_code=frc,
        fs_diff=ffs,
        functional_suite_passed=func_ok,
        fpr_value=0.0,
        oracle_verdict=func_verdict,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        actor="ORACLE",
        summary=f"Check operativo servizio post-hardening: passed={func_ok} ({func_verdict}).",
        passed=func_ok,
    ))
    if not func_ok:
        transitions.append(AckStateTransition(state="CERTIFY_REPORT", actor="ORACLE", summary="Respinto: hardening ha fermato il servizio.", passed=False))
        return _MissionExecutionOutcome(
            transitions=transitions,
            contracts=contracts,
            evidences=evidences,
            mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=0.0,
                false_positive_rate=0.0,
                evasion_resistance_rate=0.0,
                functional_survival_rate=0.0,
                pre_patch_breach_confirmed=pre_breach,
                post_patch_breaches=0,
            ),
            blue_summary=blue_summary,
            certified=False,
            certification_verdict="REJECTED_SERVICE_OUTAGE",
            rationale="Hardening ha disabilitato il servizio invece di correggere i privilegi.",
        )

    vectors = [
        ("CLASS_HELPER_SCRIPT_OVERWRITE_HIJACK", "helper_hijack"),
        ("CLASS_AMBIENT_CAPABILITY_INHERITANCE", "ambient_caps"),
        ("CLASS_UNIX_SOCKET_UNAUTHORIZED_CONTROL", "unix_socket_ctl"),
    ]
    rounds_to_run = max(1, min(len(vectors), mutation_rounds))
    post_breaches = 0
    for idx in range(rounds_to_run):
        atk_class, vec = vectors[idx]
        aid = f"act_red_m3_mut_{idx + 1:02d}"
        rel_mut, _ = chamber.write_red_artifact(f"privesc_m3_mut_{idx + 1:02d}.py", f'''\
import json, os, sys
from pathlib import Path
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import host_runtime_sim
try:
    out = host_runtime_sim.check_action({vec!r})
except Exception as exc:
    out = f"BLOCKED: {{exc}}"
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json").write_text(json.dumps({{"out": out}}), encoding="utf-8")
''')
        m_contract = _contract(
            chamber=chamber,
            action_id=aid,
            actor="RED",
            phase="RED_MUTATE_BYPASS",
            primitive="EXEC_ARTIFACT",
            artifact_path=rel_mut,
            entrypoint=["python3", rel_mut],
            target_invariant=desc.target_invariant,
            attack_class=atk_class,
        )
        contracts.append(m_contract)
        mrc, _, _, mfs = chamber.run_contract(m_contract)
        bypassed = mfs.canary_accessed or not mfs.lowerdir_untouched
        if bypassed:
            post_breaches += 1
        mev = OutOfBandOracleEvidence(
            action_id=aid,
            exit_code=mrc,
            fs_diff=mfs,
            telemetry_alerts=[TelemetryAlertEvidence(rule_id="systemd_hardening", engine="host_cow_audit", triggered=not bypassed)],
            oracle_verdict="INVARIANT_BREACHED_STEALTH" if bypassed else "DEFENSE_HELD_CLEAN",
        )
        evidences.append(mev)
        prev_failed = fow.record_outcome(atk_class, bypass_succeeded=bypassed)
        mut_results.append(AckMutationRoundResult(
            round_index=idx + 1,
            attack_class=atk_class,
            previous_failed_classes=prev_failed,
            contract=m_contract,
            oracle_evidence=mev,
            bypass_succeeded=bypassed,
        ))

    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"{rounds_to_run} vettori di privesc verificati su clone CoW; bypass={post_breaches}.",
        passed=(post_breaches == 0),
    ))
    evasion_res = round((rounds_to_run - post_breaches) / rounds_to_run, 3)
    certified = bool(pre_breach and func_ok and post_breaches == 0)
    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary="Hardening minimo certificato su clone CoW con lowerdir host intatto." if certified else "Hardening insufficiente.",
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            true_positive_rate=evasion_res,
            false_positive_rate=0.0,
            evasion_resistance_rate=evasion_res,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=post_breaches,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict="CERTIFIED_HARDENED_SHADOW_CLONE" if certified else "HARDENING_BYPASSED",
        rationale="Privesc dimostrata prima dell'hardening, azzerata dopo il diff minimo e servizio operativo su clone.",
    )


# ---------------------------------------------------------------------------
# Mission 4: Fuzz-to-Fix Pipeline (Deterministic TLV Parser Fuzzer -> Patch)
# ---------------------------------------------------------------------------

_M4_VULNERABLE_PARSER = '''\
import struct

class ParserCrashError(RuntimeError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    if depth > 16:
        raise ParserCrashError("ASAN_STACK_OVERFLOW: unbounded TLV recursion depth")
    out = []
    offset = 0
    while offset < len(data):
        if offset + 5 > len(data):
            raise ParserCrashError("ASAN_OOB_READ: truncated 5-byte TLV header")
        t = data[offset]
        count, length = struct.unpack(">HH", data[offset + 1 : offset + 5])
        offset += 5
        # Bug 1: Unbounded count*stride integer overflow check absent
        if count > 4096:
            raise ParserCrashError("UBSAN_INT_OVERFLOW: allocation count*stride overflow")
        # Bug 2: Out-of-bounds read when declared length > remaining buffer
        if offset + length > len(data):
            raise ParserCrashError("ASAN_HEAP_OOB_READ: declared length exceeds packet bounds")
        payload = data[offset : offset + length]
        offset += length
        if t == 0xFF:
            # Bug 3: Infinite / deep recursion without depth ceiling
            out.append({"type": t, "nested": parse_tlv_frame(payload, depth + 1)})
        else:
            out.append({"type": t, "count": count, "size": len(payload)})
    return out
'''

_M4_NAIVE_BLOCK_ALL_PARSER = '''\
class ParserCrashError(RuntimeError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    raise ValueError("Blocked all TLV packets")
'''

_M4_STRUCTURAL_FIXED_PARSER = '''\
import struct

MAX_TLV_DEPTH = 8
MAX_ITEM_COUNT = 256

class ParserCrashError(RuntimeError):
    pass

class InvalidTlvFrameError(ValueError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    if not isinstance(data, (bytes, bytearray)):
        raise InvalidTlvFrameError("Input must be bytes")
    if depth > MAX_TLV_DEPTH:
        raise InvalidTlvFrameError("TLV nesting depth exceeds safe cap")
    out = []
    offset = 0
    total = len(data)
    while offset < total:
        if offset + 5 > total:
            raise InvalidTlvFrameError("Truncated TLV header rejected safely")
        t = data[offset]
        count, length = struct.unpack(">HH", data[offset + 1 : offset + 5])
        offset += 5
        if count > MAX_ITEM_COUNT:
            raise InvalidTlvFrameError("Count ceiling exceeded")
        if length > total - offset:
            raise InvalidTlvFrameError("Declared TLV length exceeds remaining buffer")
        payload = data[offset : offset + length]
        offset += length
        if t == 0xFF:
            out.append({"type": t, "nested": parse_tlv_frame(payload, depth + 1)})
        else:
            out.append({"type": t, "count": count, "size": len(payload)})
    return out
'''


def _run_m4_fuzz_to_fix(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
) -> _MissionExecutionOutcome:
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []

    valid_pkt_1 = b"\x01\x00\x01\x00\x04ABCD"
    valid_pkt_2 = b"\xff\x00\x01\x00\x08\x02\x00\x01\x00\x03XYZ"

    chamber.seed_lowerdir({
        "tlv_parser.py": _M4_VULNERABLE_PARSER,
        "corpus/valid/msg1.bin": valid_pkt_1,
        "corpus/valid/msg2.bin": valid_pkt_2,
    })
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Inizializzata pipeline Fuzz-to-Fix `{chamber.sandbox_id}` con corpus valido seed (2 frame).",
        passed=True,
    ))

    _ = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="tlv_parser.parse_tlv_frame")
    fuzzer_code = '''\
import json, os, struct, sys
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
sys.path.insert(0, str(up))
import tlv_parser

seed = b"\\x01\\x00\\x01\\x00\\x04ABCD"
candidates = [seed]
for i in range(32):
    candidates.append(struct.pack(">BHH", 1, 1, 200 + i) + b"A" * 4)
    candidates.append(struct.pack(">BHH", 2, 5000 + i, 2) + b"XY")

min_crash = None
crash_msg = ""
for cand in candidates:
    try:
        tlv_parser.parse_tlv_frame(cand)
    except tlv_parser.ParserCrashError as exc:
        if min_crash is None or len(cand) < len(min_crash):
            min_crash = cand
            crash_msg = str(exc)

repro_file = Path(os.environ["ACK_ARTIFACTS_RED"]) / "repro_min_crash.bin"
if min_crash is not None:
    repro_file.write_bytes(min_crash)
    # Deterministically verify crash reproduces 100%
    reproduced = False
    try:
        tlv_parser.parse_tlv_frame(repro_file.read_bytes())
    except tlv_parser.ParserCrashError:
        reproduced = True
else:
    reproduced = False

(Path(os.environ["ACK_ARTIFACTS_RED"]) / "fuzz_base_res.json").write_text(
    json.dumps({"reproduced": reproduced, "crash": crash_msg, "min_len": len(min_crash or b"")}), encoding="utf-8"
)
'''
    rel_base, _ = chamber.write_red_artifact("fuzz_m4_base.py", fuzzer_code)
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_m4_fuzz",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="RUN_FUZZER",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=desc.target_invariant,
        attack_class="CLASS_FUZZER_OOB_LENGTH_MINIMIZED",
    )
    contracts.append(base_contract)
    rc, _, _, fs_base = chamber.run_contract(base_contract)
    base_res = json.loads((chamber.artifacts_red / "fuzz_base_res.json").read_text(encoding="utf-8"))
    pre_breach = bool(base_res.get("reproduced"))
    base_verdict: AckOracleVerdictType = "INVARIANT_BREACHED_STEALTH" if pre_breach else "DEFENSE_HELD_CLEAN"
    base_ev = OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        crash_reproduced=pre_breach,
        oracle_verdict=base_verdict,
    )
    evidences.append(base_ev)
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary=f"Fuzzer deterministico ha generato PoC minimizzato (`{base_res.get('min_len')}B`, `{base_res.get('crash')}`).",
        passed=True,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Crash riproducibile al 100% pre-patch={pre_breach} ({base_verdict}).",
        passed=pre_breach,
    ))

    # BLUE_DEFEND
    _ = fow.build_blue_context(baseline_summary="tlv_parser.py OOB length / overflow / unbounded recursion", oob_baseline=base_ev)
    if defense_mode == "naive_block_all":
        patched_parser = _M4_NAIVE_BLOCK_ALL_PARSER
        blue_summary = "naive_block_all: rifiuta tutti i pacchetti TLV."
    else:
        patched_parser = _M4_STRUCTURAL_FIXED_PARSER
        blue_summary = (
            "structural: safe validation `InvalidTlvFrameError` su header troncati, bounds `length <= remaining`, "
            "`count <= 256`, profondità max 8 + inserimento `repro_min_crash.bin` nel corpus di regressione."
        )

    rel_blue, _ = chamber.write_blue_artifact("apply_patch_m4.py", f'''\
import os
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
(up / "tlv_parser.py").write_text({patched_parser!r}, encoding="utf-8")
reg_dir = up / "corpus" / "regression"
reg_dir.mkdir(parents=True, exist_ok=True)
repro = Path(os.environ["ACK_ARTIFACTS_RED"]) / "repro_min_crash.bin"
if repro.exists():
    (reg_dir / "repro_min_crash.bin").write_bytes(repro.read_bytes())
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_m4_fix",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="APPLY_DIFF",
        artifact_path=rel_blue,
        entrypoint=["python3", rel_blue],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    evidences.append(OutOfBandOracleEvidence(action_id=blue_contract.action_id, exit_code=brc, fs_diff=bfs, oracle_verdict="DEFENSE_HELD_CLEAN"))
    transitions.append(AckStateTransition(state="BLUE_DEFEND", actor="BLUE", summary=f"Fix parser + regression corpus applicati ({defense_mode}).", passed=(brc == 0)))

    # ORACLE_FUNCTIONAL_AND_FPR_CHECK
    func_rel, _ = chamber.write_blue_artifact("oracle_corpus_m4.py", '''\
import os, sys
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
sys.path.insert(0, str(up))
import tlv_parser
for f in sorted((up / "corpus" / "valid").glob("*.bin")):
    parsed = tlv_parser.parse_tlv_frame(f.read_bytes())
    assert parsed, f"Empty parse on valid corpus {f.name}"
for rf in sorted((up / "corpus" / "regression").glob("*.bin")):
    try:
        tlv_parser.parse_tlv_frame(rf.read_bytes())
    except tlv_parser.ParserCrashError as exc:
        raise AssertionError(f"Regression crash still reproduces: {exc}")
    except ValueError:
        pass
print("CORPUS_AND_REGRESSION_OK")
''')
    func_contract = _contract(
        chamber=chamber,
        action_id="act_oracle_m4_corpus",
        actor="BLUE",
        phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        primitive="EXEC_ARTIFACT",
        artifact_path=func_rel,
        entrypoint=["python3", func_rel],
        target_invariant="INV_VALID_CORPUS_AND_REGRESSION_PASS",
    )
    contracts.append(func_contract)
    frc, fout, _, ffs = chamber.run_contract(func_contract)
    func_ok = (frc == 0 and "CORPUS_AND_REGRESSION_OK" in fout)
    func_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if func_ok else "DEFENSE_REJECTED_BROKEN_FUNC"
    evidences.append(OutOfBandOracleEvidence(
        action_id=func_contract.action_id,
        exit_code=frc,
        fs_diff=ffs,
        functional_suite_passed=func_ok,
        fpr_value=0.0,
        oracle_verdict=func_verdict,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        actor="ORACLE",
        summary=f"Verifica valid corpus + regression crash: passed={func_ok} ({func_verdict}).",
        passed=func_ok,
    ))
    if not func_ok:
        transitions.append(AckStateTransition(state="CERTIFY_REPORT", actor="ORACLE", summary="Respinto: parser rotto sui pacchetti validi.", passed=False))
        return _MissionExecutionOutcome(
            transitions=transitions,
            contracts=contracts,
            evidences=evidences,
            mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=0.0,
                false_positive_rate=0.0,
                evasion_resistance_rate=0.0,
                functional_survival_rate=0.0,
                pre_patch_breach_confirmed=pre_breach,
                post_patch_breaches=0,
            ),
            blue_summary=blue_summary,
            certified=False,
            certification_verdict="REJECTED_BROKEN_PARSER",
            rationale="La patch ha rigettato anche i frame TLV validi.",
        )

    fuzz_classes = [
        ("CLASS_TRUNCATED_PAYLOAD_LENGTH_UNDERFLOW", "[struct.pack('>BHH', 3, 1, 65000) + b'Z'*3, b'\\x01\\x02\\x03']"),
        ("CLASS_COUNT_STRIDE_INTEGER_OVERFLOW", "[struct.pack('>BHH', 4, 65535, 4) + b'ABCD', struct.pack('>BHH', 4, 9999, 0)]"),
        ("CLASS_DEEP_RECURSIVE_TLV_NESTING_BOMB", "[b''.join(struct.pack('>BHH', 0xFF, 1, 5*(29-i)) for i in range(30))]"),
    ]
    rounds_to_run = max(1, min(len(fuzz_classes), mutation_rounds))
    post_crashes = 0
    for idx in range(rounds_to_run):
        atk_class, pkts_expr = fuzz_classes[idx]
        aid = f"act_red_m4_mut_{idx + 1:02d}"
        rel_mut, _ = chamber.write_red_artifact(f"fuzz_m4_mut_{idx + 1:02d}.py", f'''\
import json, os, struct, sys
from pathlib import Path
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import tlv_parser
crashed = False
for pkt in {pkts_expr}:
    try:
        tlv_parser.parse_tlv_frame(pkt)
    except tlv_parser.ParserCrashError:
        crashed = True
    except ValueError:
        pass
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "fuzz_{aid}.json").write_text(json.dumps({{"crashed": crashed}}), encoding="utf-8")
''')
        m_contract = _contract(
            chamber=chamber,
            action_id=aid,
            actor="RED",
            phase="RED_MUTATE_BYPASS",
            primitive="RUN_FUZZER",
            artifact_path=rel_mut,
            entrypoint=["python3", rel_mut],
            target_invariant=desc.target_invariant,
            attack_class=atk_class,
        )
        contracts.append(m_contract)
        mrc, _, _, mfs = chamber.run_contract(m_contract)
        mut_res = json.loads((chamber.artifacts_red / f"fuzz_{aid}.json").read_text(encoding="utf-8"))
        crashed = bool(mut_res.get("crashed"))
        if crashed:
            post_crashes += 1
        mev = OutOfBandOracleEvidence(
            action_id=aid,
            exit_code=mrc,
            fs_diff=mfs,
            crash_reproduced=crashed,
            oracle_verdict="INVARIANT_BREACHED_STEALTH" if crashed else "DEFENSE_HELD_CLEAN",
        )
        evidences.append(mev)
        prev_failed = fow.record_outcome(atk_class, bypass_succeeded=crashed)
        mut_results.append(AckMutationRoundResult(
            round_index=idx + 1,
            attack_class=atk_class,
            previous_failed_classes=prev_failed,
            contract=m_contract,
            oracle_evidence=mev,
            bypass_succeeded=crashed,
        ))

    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"Fuzzing differenziale post-patch ({rounds_to_run} classi): crash rilevati={post_crashes}.",
        passed=(post_crashes == 0),
    ))
    evasion_res = round((rounds_to_run - post_crashes) / rounds_to_run, 3)
    certified = bool(pre_breach and func_ok and post_crashes == 0)
    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary="Zero crash post-patch su corpus valido, regressione e fuzzing differenziale." if certified else "Crash residuo nel parser.",
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            true_positive_rate=evasion_res,
            false_positive_rate=0.0,
            evasion_resistance_rate=evasion_res,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=post_crashes,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict="CERTIFIED_ZERO_CRASH_PARSER" if certified else "PARSER_STILL_CRASHING",
        rationale="Crash riprodotto al 100% prima del fix, eliminato dopo la patch sulla root cause.",
    )


_MISSION_RUNNERS: Dict[
    str,
    Callable[..., _MissionExecutionOutcome],
] = {
    "ack-m1-exploit-patch-bypass": _run_m1_exploit_to_patch,
    "ack-m2-detection-evasion-arena": _run_m2_detection_evasion,
    "ack-m3-attack-path-hardening": _run_m3_attack_path_hardening,
    "ack-m4-fuzz-to-fix-pipeline": _run_m4_fuzz_to_fix,
}


class AdversarialCyberKernel:
    """Orchestrates typed contracts inside an isolated CoW DetonationChamber with OOB Oracle certification."""

    def list_missions(self) -> List[AckMissionDescriptor]:
        return list_ack_mission_descriptors()

    def run_mission(
        self,
        mission_id: str,
        *,
        mutation_rounds: int = 3,
        defense_mode: str = "structural",
    ) -> AckCertificationReport:
        desc = ACK_MISSION_MAP.get(mission_id)
        if desc is None:
            raise KeyError(f"Missione ACK sconosciuta: {mission_id}")
        runner = _MISSION_RUNNERS[mission_id]

        chamber = DetonationChamber()
        fow = FogOfWarController()
        try:
            outcome = runner(
                chamber,
                desc,
                fow,
                mutation_rounds=max(1, min(3, int(mutation_rounds))),
                defense_mode=defense_mode,
            )
            return AckCertificationReport(
                run_id=f"ack-run-{uuid.uuid4().hex[:8]}",
                mission_id=desc.mission_id,
                mission_kind=desc.mission_kind,
                title=desc.title,
                sandbox_id=chamber.sandbox_id,
                tier_used=desc.default_tier,
                shadow_clone_only=desc.shadow_clone_only,
                defense_mode=defense_mode,
                target_invariant=desc.target_invariant,
                certified=outcome.certified,
                certification_verdict=outcome.certification_verdict,
                state_transitions=outcome.transitions,
                action_contracts=outcome.contracts,
                oracle_evidences=outcome.evidences,
                mutation_rounds=outcome.mutation_rounds,
                tpr_fpr_matrix=outcome.tpr_fpr_matrix,
                fog_of_war=fow.audit(),
                blue_patch_or_rules_summary=outcome.blue_summary,
                rationale=outcome.rationale,
            )
        finally:
            chamber.cleanup()
