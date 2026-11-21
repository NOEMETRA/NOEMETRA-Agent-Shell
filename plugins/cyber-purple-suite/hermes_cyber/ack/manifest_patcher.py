"""Format-preserving manifest hardening and post-patch syntax validation."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from hermes_cyber.ack.manifest_parser import _parse_target_host_config
from hermes_cyber.ack.yaml_compat import _yaml_safe_dump_compat, _yaml_safe_load_compat


def _harden_manifest_text(manifest_text: str, defense_mode: str) -> str:
    """Harden a manifest strictly in its native format (JSON, line-preserving systemd INI, or container-aware YAML)."""
    parsed_meta = _parse_target_host_config(manifest_text)
    fmt = parsed_meta["format"]
    if not parsed_meta["format_valid"]:
        raise ValueError(f"Cannot patch invalid {fmt} manifest")

    if fmt in ("json", "k8s_yaml"):
        doc = json.loads(manifest_text) if fmt == "json" else _yaml_safe_load_compat(manifest_text)
        if not isinstance(doc, dict):
            raise ValueError(f"Expected mapping root in {fmt} manifest")

        if defense_mode == "naive_block_all":
            key = "serviceEnabled" if fmt == "k8s_yaml" or "serviceEnabled" in doc else "service_enabled"
            doc[key] = False
            return (json.dumps(doc, indent=2) + "\n") if fmt == "json" else _yaml_safe_dump_compat(doc)

        containers: List[Dict[str, Any]] = []
        bfs_queue: List[Any] = [doc]
        while bfs_queue:
            cur = bfs_queue.pop(0)
            if isinstance(cur, dict):
                for k in list(cur.keys()):
                    v = cur[k]
                    kl = str(k).lower()
                    if kl in ("service_enabled", "serviceenabled"):
                        cur[k] = True
                    elif kl in ("helper_writable", "helperwritable"):
                        cur[k] = False
                    elif kl in ("socket_acl_restricted", "socketaclrestricted"):
                        cur[k] = True
                    elif kl in ("socketmode", "socket_mode"):
                        cur[k] = "0600"
                    elif isinstance(v, str) and re.search(r"chmod\s+(?:0?777|a\+w)", v.lower()):
                        cur[k] = re.sub(r"(?i)chmod\s+(?:0?777|a\+w)", "chmod 0750", v)
                    if kl in ("containers", "initcontainers", "ephemeralcontainers") and isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict):
                                containers.append(item)
                    bfs_queue.append(v)
            elif isinstance(cur, list):
                bfs_queue.extend(cur)

        def _harden_security_ctx(sc: Dict[str, Any]) -> None:
            sc["privileged"] = False
            sc["allowPrivilegeEscalation"] = False
            sc["readOnlyRootFilesystem"] = True
            sc["capabilities"] = {"drop": ["ALL"]}

        if containers:
            for c in containers:
                sc = c.get("securityContext")
                if not isinstance(sc, dict):
                    sc = {}
                    c["securityContext"] = sc
                _harden_security_ctx(sc)
        else:
            def _harden_standalone(node: Any) -> None:
                if isinstance(node, list):
                    for item in node:
                        _harden_standalone(item)
                    return
                if not isinstance(node, dict):
                    return
                for k in list(node.keys()):
                    kl = str(k).lower()
                    if kl in ("privileged", "privileged_container"):
                        node[k] = False
                    elif kl == "allowprivilegeescalation":
                        node[k] = False
                    elif kl == "nonewprivileges":
                        node[k] = True
                    elif kl == "protectsystem":
                        node[k] = "strict"
                    elif kl == "readonlyrootfilesystem":
                        node[k] = True
                    elif kl in ("ambient_caps", "ambientcapabilities"):
                        node[k] = []
                    elif kl == "capabilities":
                        node[k] = {"drop": ["ALL"]}
                    elif kl == "securitycontext" and isinstance(node[k], dict):
                        _harden_standalone(node[k])
                        _harden_security_ctx(node[k])
                    else:
                        _harden_standalone(node[k])

            _harden_standalone(doc)
            if isinstance(doc.get("securityContext"), dict):
                _harden_security_ctx(doc["securityContext"])
            elif fmt == "json":
                doc["NoNewPrivileges"] = True
                doc["ProtectSystem"] = "strict"
                doc["privileged_container"] = False
                doc["helper_writable"] = False
                doc["ambient_caps"] = []
                doc["capabilities"] = {"drop": ["ALL"]}
                doc["socket_acl_restricted"] = True
            else:
                doc["securityContext"] = {
                    "privileged": False,
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                }

        return (json.dumps(doc, indent=2) + "\n") if fmt == "json" else _yaml_safe_dump_compat(doc)

    # Line-preserving systemd INI patcher
    raw_lines = manifest_text.splitlines()
    has_socket_sec = any(re.match(r"^\s*\[Socket\]\s*(?:[#;].*)?$", ln) for ln in raw_lines)
    if defense_mode == "naive_block_all":
        desired_svc: Dict[str, str] = {"ServiceEnabled": "false"}
    else:
        desired_svc = {
            "NoNewPrivileges": "true",
            "ProtectSystem": "strict",
            "HelperWritable": "false",
            "AmbientCapabilities": "",
            "CapabilityBoundingSet": "",
            "RestrictAddressFamilies": "AF_INET AF_INET6",
        }
    desired_lower = {k.lower(): (k, v) for k, v in desired_svc.items()}

    out_lines: List[str] = []
    cur_sec: Optional[str] = None
    seen_svc: set[str] = set()
    seen_sock_mode = False

    def _flush_section_missing(sec_name: Optional[str]) -> None:
        if sec_name == "Service":
            insert_idx = len(out_lines)
            while insert_idx > 0 and not out_lines[insert_idx - 1].strip():
                insert_idx -= 1
            additions: List[str] = []
            for canonical, val in desired_svc.items():
                if canonical.lower() not in seen_svc:
                    additions.append(f"{canonical}={val}")
            out_lines[insert_idx:insert_idx] = additions
        elif sec_name == "Socket" and defense_mode != "naive_block_all" and not seen_sock_mode:
            insert_idx = len(out_lines)
            while insert_idx > 0 and not out_lines[insert_idx - 1].strip():
                insert_idx -= 1
            out_lines.insert(insert_idx, "SocketMode=0600")

    for raw_ln in raw_lines:
        stripped_ln = raw_ln.strip()
        m_sec = re.match(r"^\[([A-Za-z0-9_.-]+)\]\s*(?:[#;].*)?$", stripped_ln)
        if m_sec:
            _flush_section_missing(cur_sec)
            cur_sec = m_sec.group(1)
            out_lines.append(raw_ln)
            continue

        if not stripped_ln or stripped_ln.startswith(("#", ";")) or "=" not in raw_ln:
            out_lines.append(raw_ln)
            continue

        key_part, val_part = raw_ln.split("=", 1)
        kl = key_part.strip().lower()
        key_clean = key_part.strip()

        if cur_sec == "Service":
            if defense_mode != "naive_block_all" and kl in ("execstart", "execstartpre", "execstartpost"):
                sanitized_val = re.sub(r"(?i)chmod\s+(?:0?777|a\+w)", "chmod 0750", val_part.strip())
                out_lines.append(f"{key_clean}={sanitized_val}")
                continue
            if kl in ("serviceenabled", "service_enabled"):
                target_val = "false" if defense_mode == "naive_block_all" else "true"
                if kl in seen_svc:
                    continue
                seen_svc.add(kl)
                seen_svc.add("serviceenabled")
                out_lines.append(f"{key_clean}={target_val}")
                continue
            if kl in desired_lower:
                if kl in seen_svc:
                    continue
                seen_svc.add(kl)
                out_lines.append(f"{key_clean}={desired_lower[kl][1]}")
                continue
            if defense_mode != "naive_block_all" and kl in ("privileged", "privilegedcontainer"):
                out_lines.append(f"{key_clean}=false")
                continue
            if defense_mode != "naive_block_all" and not has_socket_sec and kl == "socketmode":
                out_lines.append(f"{key_clean}=0600")
                continue
        elif cur_sec == "Socket" and defense_mode != "naive_block_all" and kl == "socketmode":
            seen_sock_mode = True
            out_lines.append(f"{key_clean}=0600")
            continue

        out_lines.append(raw_ln)

    _flush_section_missing(cur_sec)
    return "\n".join(out_lines) + "\n"


def _validate_hardened_manifest_syntax(manifest_text: str, expected_format: str, *, enforce_hardened: bool = True) -> bool:
    """Control-Plane strict parser verification ensuring hardened manifest preserves valid target syntax."""
    try:
        parsed = _parse_target_host_config(manifest_text)
        if not parsed["format_valid"] or parsed["format"] != expected_format:
            return False
        if expected_format == "json":
            doc = json.loads(manifest_text)
            return isinstance(doc, dict) and (not enforce_hardened or bool(parsed["all_containers_hardened"]))
        if expected_format == "systemd_ini":
            return True
        if expected_format == "k8s_yaml":
            doc = _yaml_safe_load_compat(manifest_text)
            if not isinstance(doc, dict):
                return False
            if enforce_hardened and not parsed["all_containers_hardened"]:
                return False
            return True
    except Exception:
        return False
    return False
