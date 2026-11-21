"""Target host manifest parser (JSON, line-by-line systemd INI, and container-aware YAML)."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from hermes_cyber.ack.yaml_compat import _yaml_safe_load_compat


def _parse_target_host_config(manifest_text: str) -> Dict[str, Any]:
    """Parse JSON, systemd INI (preserving repeated directives), or Kubernetes YAML manifests with strict validation."""
    stripped = (manifest_text or "").strip()
    unsafe_caps = ("CAP_SYS_ADMIN", "CAP_DAC_READ_SEARCH", "CAP_NET_ADMIN")

    def _result(
        fmt: str,
        valid: bool,
        *,
        service_enabled: bool = True,
        helper_writable: bool = False,
        privileged_container: bool = False,
        no_new_priv: bool = False,
        protect_sys: Any = False,
        ambient_caps: Optional[List[str]] = None,
        sock_restricted: bool = False,
        all_containers_hardened: bool = True,
    ) -> Dict[str, Any]:
        return {
            "format": fmt,
            "format_valid": valid,
            "service_enabled": service_enabled,
            "helper_writable": helper_writable,
            "privileged_container": privileged_container,
            "NoNewPrivileges": no_new_priv,
            "ProtectSystem": protect_sys,
            "ambient_caps": list(ambient_caps or []),
            "socket_acl_restricted": sock_restricted,
            "all_containers_hardened": all_containers_hardened,
        }

    def _bool_val(val: Any) -> Optional[bool]:
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            s = val.strip().lower()
            if s in ("true", "yes", "1"):
                return True
            if s in ("false", "no", "0"):
                return False
        return None

    def _norm_cap(raw: Any) -> str:
        s = str(raw or "").strip().upper()
        if not s:
            return ""
        return s if s.startswith("CAP_") else f"CAP_{s}"

    def _collect_dicts_and_containers(root_doc: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        dicts: List[Dict[str, Any]] = []
        containers: List[Dict[str, Any]] = []
        bfs_queue: List[Any] = [root_doc]
        while bfs_queue:
            cur = bfs_queue.pop(0)
            if isinstance(cur, dict):
                dicts.append(cur)
                for k, v in cur.items():
                    if str(k).lower() in ("containers", "initcontainers", "ephemeralcontainers") and isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict):
                                containers.append(item)
                    bfs_queue.append(v)
            elif isinstance(cur, list):
                bfs_queue.extend(cur)
        return dicts, containers

    def _eval_structured_doc(fmt: str, doc: Dict[str, Any]) -> Dict[str, Any]:
        dicts, containers = _collect_dicts_and_containers(doc)

        service_enabled = True
        helper_writable = False
        sock_explicit_true = False
        sock_explicit_false = False
        for d in dicts:
            for k, v in d.items():
                kl = str(k).lower()
                bv = _bool_val(v)
                if kl in ("service_enabled", "serviceenabled") and bv is False:
                    service_enabled = False
                elif kl in ("helper_writable", "helperwritable") and bv is True:
                    helper_writable = True
                elif kl in ("socket_acl_restricted", "socketaclrestricted"):
                    if bv is True:
                        sock_explicit_true = True
                    elif bv is False:
                        sock_explicit_false = True
                elif kl in ("socketmode", "socket_mode"):
                    mode_s = str(v).strip().lstrip("0")
                    if mode_s in ("600", "660"):
                        sock_explicit_true = True
                    elif mode_s in ("666", "777"):
                        sock_explicit_false = True
                elif isinstance(v, str) and re.search(r"chmod\s+(?:0?777|a\+w)", v.lower()):
                    helper_writable = True

        # Reject misplaced container-only securityContext at Pod root when containers exist without hardening
        if containers:
            all_hardened = True
            any_priv = False
            all_nnp = True
            all_ro_root = True
            found_caps: List[str] = []
            for c in containers:
                sc = c.get("securityContext")
                if not isinstance(sc, dict):
                    all_hardened = False
                    all_nnp = False
                    all_ro_root = False
                    if "CAP_DAC_READ_SEARCH" not in found_caps:
                        found_caps.append("CAP_DAC_READ_SEARCH")
                    continue
                if sc.get("privileged") is True or sc.get("allowPrivilegeEscalation") is True:
                    any_priv = True
                if sc.get("allowPrivilegeEscalation") is not False:
                    all_hardened = False
                    all_nnp = False
                if sc.get("readOnlyRootFilesystem") is not True:
                    all_hardened = False
                    all_ro_root = False
                if sc.get("privileged") is True:
                    all_hardened = False
                caps = sc.get("capabilities")
                drops = [str(x).strip().upper() for x in (caps.get("drop") or [])] if isinstance(caps, dict) else []
                adds = [_norm_cap(x) for x in (caps.get("add") or [])] if isinstance(caps, dict) else []
                for cap_name in adds:
                    if cap_name in unsafe_caps and cap_name not in found_caps:
                        found_caps.append(cap_name)
                if "ALL" not in drops:
                    all_hardened = False
                    if not adds and "CAP_DAC_READ_SEARCH" not in found_caps:
                        found_caps.append("CAP_DAC_READ_SEARCH")
                elif any(cap_name in unsafe_caps for cap_name in adds):
                    all_hardened = False

            sock_restricted = bool(not sock_explicit_false) if (not sock_explicit_false and not sock_explicit_true) else bool(sock_explicit_true and not sock_explicit_false)
            return _result(
                fmt,
                True,
                service_enabled=service_enabled,
                helper_writable=helper_writable,
                privileged_container=any_priv,
                no_new_priv=all_nnp,
                protect_sys="strict" if all_ro_root else False,
                ambient_caps=found_caps,
                sock_restricted=sock_restricted,
                all_containers_hardened=all_hardened,
            )

        priv = False
        nnp_true = False
        nnp_false = False
        protect_sys: Any = False
        drop_all = False
        found_caps = []
        added_unsafe_caps: List[str] = []
        has_security_ctx = False
        for d in dicts:
            for k, v in d.items():
                kl = str(k).lower()
                bv = _bool_val(v)
                if kl in ("privileged", "privileged_container") and bv is True:
                    priv = True
                elif kl == "allowprivilegeescalation":
                    has_security_ctx = True
                    if bv is True:
                        priv = True
                        nnp_false = True
                    elif bv is False:
                        nnp_true = True
                elif kl == "nonewprivileges":
                    if bv is True:
                        nnp_true = True
                    elif bv is False:
                        nnp_false = True
                elif kl == "protectsystem" and str(v).strip().lower() in ("strict", "full"):
                    protect_sys = "strict"
                elif kl == "readonlyrootfilesystem" and bv is True:
                    protect_sys = "strict"
                elif kl == "securitycontext" and isinstance(v, dict):
                    has_security_ctx = True
                elif kl == "capabilities":
                    if isinstance(v, dict):
                        if "ALL" in [str(x).strip().upper() for x in (v.get("drop") or [])]:
                            drop_all = True
                        for item in (v.get("add") or []):
                            up_item = _norm_cap(item)
                            if up_item in unsafe_caps:
                                if up_item not in found_caps:
                                    found_caps.append(up_item)
                                if up_item not in added_unsafe_caps:
                                    added_unsafe_caps.append(up_item)
                    elif isinstance(v, list):
                        for item in v:
                            up_item = _norm_cap(item)
                            if up_item in unsafe_caps and up_item not in found_caps:
                                found_caps.append(up_item)
                elif kl in ("ambient_caps", "ambientcapabilities") and isinstance(v, list):
                    for item in v:
                        up_item = _norm_cap(item)
                        if up_item in unsafe_caps and up_item not in found_caps:
                            found_caps.append(up_item)
                elif kl == "drop" and isinstance(v, list) and "ALL" in [str(x).strip().upper() for x in v]:
                    drop_all = True

        caps_out = added_unsafe_caps if drop_all else found_caps
        if has_security_ctx and not sock_explicit_true and not sock_explicit_false:
            sock_restricted = True
        else:
            sock_restricted = bool(sock_explicit_true and not sock_explicit_false)
        return _result(
            fmt,
            True,
            service_enabled=service_enabled,
            helper_writable=helper_writable,
            privileged_container=priv,
            no_new_priv=bool(nnp_true and not nnp_false),
            protect_sys=protect_sys,
            ambient_caps=caps_out,
            sock_restricted=sock_restricted,
            all_containers_hardened=True,
        )

    if not stripped:
        return _result("invalid", False)

    # 1) JSON manifest
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
        except Exception:
            return _result("json", False)
        if not isinstance(doc, dict):
            return _result("json", False)
        return _eval_structured_doc("json", doc)

    # 2) systemd INI unit manifest (line-by-line preserving repeated directives)
    if re.search(r"(?m)^\[[A-Za-z0-9_.-]+\]\s*$", stripped):
        current_section: Optional[str] = None
        seen_sections: set[str] = set()
        service_enabled = True
        helper_writable = False
        priv = False
        no_new_priv = False
        protect_sys: Any = False
        ambient_caps: List[str] = []
        sock_mode = ""
        restrict_af = ""
        sock_acl_str = ""

        for raw_ln in manifest_text.splitlines():
            ln = raw_ln.strip()
            if not ln or ln.startswith(("#", ";")):
                continue
            m_sec = re.match(r"^\[([A-Za-z0-9_.-]+)\]\s*(?:[#;].*)?$", ln)
            if m_sec:
                current_section = m_sec.group(1)
                seen_sections.add(current_section)
                continue
            if current_section is None or re.match(r"^[A-Za-z0-9_.-]+\s*:", ln) or "=" not in ln:
                return _result("systemd_ini", False)
            k, v = ln.split("=", 1)
            kl = k.strip().lower()
            vs = v.strip()
            vl = vs.lower()
            if kl in ("serviceenabled", "service_enabled"):
                service_enabled = vl != "false"
            elif kl in ("helperwritable", "helper_writable"):
                if vl == "true":
                    helper_writable = True
                elif vl == "false":
                    helper_writable = False
            elif kl in ("execstart", "execstartpre", "execstartpost"):
                if re.search(r"chmod\s+(?:0?777|a\+w)", vl):
                    helper_writable = True
            elif kl in ("privileged", "privilegedcontainer"):
                priv = vl == "true"
            elif kl == "nonewprivileges":
                no_new_priv = vl == "true"
            elif kl == "protectsystem":
                protect_sys = "strict" if vl in ("strict", "full") else False
            elif kl == "ambientcapabilities":
                if not vs:
                    ambient_caps = []
                else:
                    for cap in unsafe_caps:
                        if cap in vs.upper() and cap not in ambient_caps:
                            ambient_caps.append(cap)
            elif kl == "capabilityboundingset":
                if not vs:
                    ambient_caps = []
            elif kl == "socketmode":
                sock_mode = vs.lstrip("0")
            elif kl == "restrictaddressfamilies":
                restrict_af = vs.upper()
            elif kl in ("socket_acl_restricted", "socketaclrestricted"):
                sock_acl_str = vl

        if "Service" not in seen_sections:
            return _result("systemd_ini", False)

        sock_restricted = False
        if sock_mode in ("600", "660"):
            sock_restricted = True
        elif sock_mode in ("666", "777"):
            sock_restricted = False
        elif restrict_af and "AF_UNIX" not in restrict_af:
            sock_restricted = True
        elif sock_acl_str == "true":
            sock_restricted = True

        return _result(
            "systemd_ini",
            True,
            service_enabled=service_enabled,
            helper_writable=helper_writable,
            privileged_container=priv,
            no_new_priv=no_new_priv,
            protect_sys=protect_sys,
            ambient_caps=ambient_caps,
            sock_restricted=sock_restricted,
        )

    # 3) Kubernetes / container YAML manifest parsed cleanly (ruamel.yaml / PyYAML / stdlib fallback)
    for raw_ln in stripped.splitlines():
        ln = raw_ln.strip()
        if not ln or ln.startswith("#") or ln in ("---", "..."):
            continue
        if re.match(r"^\[[A-Za-z0-9_.-]+\]$", ln):
            return _result("k8s_yaml", False)
    try:
        yaml_doc = _yaml_safe_load_compat(stripped)
    except Exception:
        return _result("k8s_yaml", False)
    if not isinstance(yaml_doc, dict):
        return _result("k8s_yaml", False)
    return _eval_structured_doc("k8s_yaml", yaml_doc)
