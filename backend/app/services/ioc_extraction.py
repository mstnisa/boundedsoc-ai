"""
Deterministic IOC extraction (regex-based, not LLM-based — per AI design
rules, extraction is deterministic code). Extracts IPs, domains, URLs,
file hashes (md5/sha1/sha256), and usernames from normalized alert/event
text.
"""
import re
from dataclasses import dataclass

from app.models.ioc import IOCType

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
# Requires an explicit key/value separator (":" or "=") right after the field
# name, e.g. "Account Name: j.rahman" or "user=j.rahman" — NOT bare
# whitespace, which previously caused phrases like "account failed" to be
# mis-captured as a username.
_USERNAME_RE = re.compile(
    r"\b(?:account name|target ?user ?name|user(?:name)?|logon)\s*[:=]\s*([A-Za-z0-9._\\-]{2,64})",
    re.I,
)

# File-extension-shaped strings (process/image names) that the domain regex
# would otherwise mistake for a hostname, since they end in a short
# alphabetic "TLD"-looking suffix.
_NON_DOMAIN_SUFFIXES = {"exe", "dll", "ps1", "bat", "sh", "py", "js", "json", "log", "tmp", "cfg"}

# A deliberately small, curated allowlist of real TLDs/ccTLDs. Requiring a
# match against this (rather than "any 2-24 letter suffix") is what keeps
# incidental dotted strings like a "j.rahman" username out of the domain
# IOC list. Extend as needed — this is not meant to be exhaustive.
_KNOWN_TLDS = {
    "com", "net", "org", "io", "co", "info", "biz", "xyz", "top", "cc", "me",
    "dev", "app", "gov", "edu", "mil", "int", "onion",
    "ru", "cn", "uk", "de", "fr", "nl", "br", "in", "jp", "kr", "au", "ca",
    "bd", "pk", "ir", "kp", "ua", "pl", "tk", "ml", "ga", "cf", "su",
}

_PRIVATE_OR_RESERVED_PREFIXES = ("10.", "127.", "169.254.", "0.")


@dataclass(frozen=True)
class ExtractedIOC:
    type: IOCType
    value: str


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(_PRIVATE_OR_RESERVED_PREFIXES):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def extract_iocs(text_blob: str) -> list[ExtractedIOC]:
    """
    Extracts IOCs from a single blob of text (caller concatenates whatever
    fields are relevant — full_log, data values, etc.). Hashes are matched
    longest-pattern-first so a sha256 is never mis-tagged as an md5 substring.
    """
    found: dict[tuple[IOCType, str], ExtractedIOC] = {}

    for match in _URL_RE.findall(text_blob):
        found[(IOCType.url, match)] = ExtractedIOC(IOCType.url, match)

    for match in _IPV4_RE.findall(text_blob):
        if not _is_private_ip(match):
            found[(IOCType.ip, match)] = ExtractedIOC(IOCType.ip, match)

    remaining_for_hashes = text_blob
    for match in _SHA256_RE.findall(remaining_for_hashes):
        found[(IOCType.hash_sha256, match.lower())] = ExtractedIOC(IOCType.hash_sha256, match.lower())
    for match in _SHA1_RE.findall(remaining_for_hashes):
        key = (IOCType.hash_sha1, match.lower())
        if not any(match.lower() in v for (t, v) in found if t == IOCType.hash_sha256):
            found[key] = ExtractedIOC(IOCType.hash_sha1, match.lower())
    for match in _MD5_RE.findall(remaining_for_hashes):
        already_longer = any(
            match.lower() in v for (t, v) in found if t in (IOCType.hash_sha256, IOCType.hash_sha1)
        )
        if not already_longer:
            found[(IOCType.hash_md5, match.lower())] = ExtractedIOC(IOCType.hash_md5, match.lower())

    for match in _DOMAIN_RE.findall(text_blob):
        # skip anything that's actually an IP, or a substring of an already-found URL
        if _IPV4_RE.fullmatch(match):
            continue
        if any(match in v for (t, v) in found if t == IOCType.url):
            continue
        suffix = match.rsplit(".", 1)[-1].lower()
        if suffix in _NON_DOMAIN_SUFFIXES or suffix not in _KNOWN_TLDS:
            continue
        found.setdefault((IOCType.domain, match.lower()), ExtractedIOC(IOCType.domain, match.lower()))

    for match in _USERNAME_RE.findall(text_blob):
        found.setdefault((IOCType.username, match), ExtractedIOC(IOCType.username, match))

    return list(found.values())


def extract_from_normalized_event(normalized: dict) -> list[ExtractedIOC]:
    parts = [
        str(normalized.get("full_log", "")),
        str(normalized.get("rule_description", "")),
    ]
    data = normalized.get("data", {})
    if isinstance(data, dict):
        parts.extend(str(v) for v in data.values())
    return extract_iocs("\n".join(parts))
