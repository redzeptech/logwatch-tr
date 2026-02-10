"""
Actor classifier for Windows logon-related events.

This module is intentionally standalone so it can be imported by the EVTX triage
pipeline later (e.g., from `evtx_triage.py`) without changing parsing logic.

Classification categories (returned as strings):
- "human"
- "service/system"
- "machine"
- "local_builtin"
- "unknown"

Signals used:
- Username / domain patterns (well-known Windows principals)
- LogonType (when available)

Explicitly handled well-known Windows accounts/prefixes:
- Domains: "NT AUTHORITY", "NT SERVICE", "IIS APPPOOL"
- Usernames: "DWM-<n>", "UMFD-<n>"
- Machine accounts: usernames ending with "$"
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping, Optional, Tuple


ACTOR_HUMAN = "human"
ACTOR_SERVICE_SYSTEM = "service/system"
ACTOR_MACHINE = "machine"
ACTOR_LOCAL_BUILTIN = "local_builtin"
ACTOR_UNKNOWN = "unknown"

ACTOR_TYPES = {
    ACTOR_HUMAN,
    ACTOR_SERVICE_SYSTEM,
    ACTOR_MACHINE,
    ACTOR_LOCAL_BUILTIN,
    ACTOR_UNKNOWN,
}


# Windows logon type reference (common values)
LOGON_TYPE_NAMES = {
    "0": "System",
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
    "12": "CachedRemoteInteractive",
    "13": "CachedUnlock",
}


_RE_DWM = re.compile(r"^DWM-\d+$", re.IGNORECASE)
_RE_UMFD = re.compile(r"^UMFD-\d+$", re.IGNORECASE)
_RE_UPN = re.compile(r"^[^\\/@]+@[^\\/@]+\.[^\\/@]+$")
_RE_DOMAIN_USER = re.compile(r"^(?P<domain>[^\\]+)\\(?P<user>.+)$")


_DOMAIN_SERVICE = {"NT SERVICE", "IIS APPPOOL"}
_DOMAIN_AUTHORITY = {"NT AUTHORITY"}
_DOMAIN_BUILTIN = {"BUILTIN"}


_WELL_KNOWN_SYSTEM_USERS = {
    # Often appear as just the username without a domain in some datasets
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "ANONYMOUS LOGON",
}

_LOCAL_BUILTIN_ACCOUNTS = {
    # Built-in local accounts commonly seen on Windows hosts
    "ADMINISTRATOR",
    "GUEST",
    "DEFAULTACCOUNT",
    "WDAGUTILITYACCOUNT",
}


@dataclass(frozen=True)
class ActorClassification:
    """Result of classifying an actor principal."""

    actor_type: str
    confidence: float
    reason: str

    def __post_init__(self) -> None:
        if self.actor_type not in ACTOR_TYPES:
            raise ValueError(f"Unknown actor_type: {self.actor_type!r}")
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")


def _norm(s: Optional[str]) -> str:
    return (s or "").strip()


def _upper(s: Optional[str]) -> str:
    return _norm(s).upper()


def split_principal(username: Optional[str], domain: Optional[str] = None) -> Tuple[str, str]:
    """
    Normalize and split a Windows principal into (domain, user).

    Accepts:
    - username="DOMAIN\\user"
    - username="user", domain="DOMAIN"
    - username="user@domain" (UPN form): returns ("", "user@domain")
    """
    u = _norm(username)
    d = _norm(domain)

    if not u:
        return (d, "")

    m = _RE_DOMAIN_USER.match(u)
    if m:
        return (m.group("domain").strip(), m.group("user").strip())

    # For UPN we keep it in the "user" field (domain empty)
    return (d, u)


def _logon_type_str(logon_type: Optional[object]) -> str:
    if logon_type is None:
        return ""
    s = str(logon_type).strip()
    return s


def classify_actor(
    username: Optional[str],
    domain: Optional[str] = None,
    logon_type: Optional[object] = None,
) -> ActorClassification:
    """
    Classify a logon actor using principal patterns and (optionally) LogonType.

    Precedence (highest first):
    1) machine accounts (user endswith '$')
    2) well-known service/system domains + usernames (NT SERVICE, IIS APPPOOL, DWM-*, UMFD-*, NT AUTHORITY\*)
    3) local_builtin (BUILTIN domain, common built-in local accounts)
    4) human (interactive-ish LogonType + looks like user)
    5) unknown
    """
    d_raw, u_raw = split_principal(username, domain)
    d = _upper(d_raw)
    u = _norm(u_raw)
    u_up = u.upper()
    lt = _logon_type_str(logon_type)

    if not u or u in {"-", "?"} or u_up in {"(NULL)", "NULL"}:
        return ActorClassification(
            actor_type=ACTOR_UNKNOWN,
            confidence=0.2,
            reason="missing/placeholder username",
        )

    # 1) Machine accounts: COMPUTERNAME$ (very strong signal)
    if u.endswith("$"):
        return ActorClassification(
            actor_type=ACTOR_MACHINE,
            confidence=0.95,
            reason="username ends with '$' (machine account)",
        )

    # 2) Explicit service/system principals
    if d in _DOMAIN_SERVICE:
        return ActorClassification(
            actor_type=ACTOR_SERVICE_SYSTEM,
            confidence=0.95,
            reason=f"domain is {d!r} (service virtual account)",
        )

    if d in _DOMAIN_AUTHORITY:
        # "NT AUTHORITY\\SYSTEM", "\\LOCAL SERVICE", "\\NETWORK SERVICE", etc.
        return ActorClassification(
            actor_type=ACTOR_SERVICE_SYSTEM,
            confidence=0.95,
            reason="domain is 'NT AUTHORITY' (built-in OS authority account)",
        )

    if _RE_DWM.match(u) or _RE_UMFD.match(u):
        return ActorClassification(
            actor_type=ACTOR_SERVICE_SYSTEM,
            confidence=0.95,
            reason="username matches DWM-<n> or UMFD-<n> pattern",
        )

    if u_up in _WELL_KNOWN_SYSTEM_USERS:
        return ActorClassification(
            actor_type=ACTOR_SERVICE_SYSTEM,
            confidence=0.9,
            reason="username is a well-known OS/service principal",
        )

    # Strong heuristic: LogonType 5 is "Service" (but keep confidence below explicit principals)
    if lt == "5":
        return ActorClassification(
            actor_type=ACTOR_SERVICE_SYSTEM,
            confidence=0.85,
            reason="LogonType 5 (Service)",
        )

    # 3) Local built-in accounts
    if d in _DOMAIN_BUILTIN:
        return ActorClassification(
            actor_type=ACTOR_LOCAL_BUILTIN,
            confidence=0.9,
            reason="domain is 'BUILTIN' (local built-in principals)",
        )

    if u_up in _LOCAL_BUILTIN_ACCOUNTS:
        conf = 0.75
        if lt in {"2", "10", "11"}:
            conf = 0.8  # interactive use is common for these accounts
        return ActorClassification(
            actor_type=ACTOR_LOCAL_BUILTIN,
            confidence=conf,
            reason="username is a common built-in local account",
        )

    # 4) Human heuristics
    # UPN strongly suggests a human identity (or at least a directory user principal).
    if _RE_UPN.match(u):
        return ActorClassification(
            actor_type=ACTOR_HUMAN,
            confidence=0.85,
            reason="username is in UPN form (user@domain)",
        )

    # Interactive-ish logons are usually humans unless already caught above.
    if lt in {"2", "10", "11", "7"}:
        return ActorClassification(
            actor_type=ACTOR_HUMAN,
            confidence=0.8,
            reason=f"interactive-ish LogonType {lt} ({LOGON_TYPE_NAMES.get(lt, 'unknown')})",
        )

    # Network logons can be humans, services, or machines; ambiguous without extra context.
    if lt == "3":
        return ActorClassification(
            actor_type=ACTOR_UNKNOWN,
            confidence=0.5,
            reason="LogonType 3 (Network) is ambiguous without extra context",
        )

    # Batch / NewCredentials are ambiguous
    if lt in {"4", "9"}:
        return ActorClassification(
            actor_type=ACTOR_UNKNOWN,
            confidence=0.5,
            reason=f"ambiguous LogonType {lt} ({LOGON_TYPE_NAMES.get(lt, 'unknown')})",
        )

    # 5) Fallback
    return ActorClassification(
        actor_type=ACTOR_UNKNOWN,
        confidence=0.4,
        reason="no strong principal or LogonType signals matched",
    )


def classify_logon_event(event_data: Mapping[str, str]) -> ActorClassification:
    """
    Convenience wrapper for Security 4624/4625 style EventData dicts.

    Expected keys (if present):
    - TargetUserName
    - TargetDomainName
    - LogonType
    """
    target_user = event_data.get("TargetUserName")
    target_domain = event_data.get("TargetDomainName")

    # Some events omit Target* fields; fall back to Subject* if present.
    if not _norm(target_user):
        target_user = event_data.get("SubjectUserName")
        subject_domain = event_data.get("SubjectDomainName")
        if _norm(subject_domain) or not _norm(target_domain):
            target_domain = subject_domain

    return classify_actor(
        username=target_user,
        domain=target_domain,
        logon_type=event_data.get("LogonType"),
    )

