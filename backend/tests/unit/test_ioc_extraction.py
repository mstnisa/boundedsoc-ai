from app.models.ioc import IOCType
from app.services.ioc_extraction import extract_iocs


def test_extracts_ip_address():
    result = extract_iocs("connection from 185.220.101.47 observed")
    values = {(i.type, i.value) for i in result}
    assert (IOCType.ip, "185.220.101.47") in values


def test_skips_private_ips():
    result = extract_iocs("internal host 10.0.0.5 talked to 192.168.1.10 and 172.16.5.5")
    assert result == []


def test_extracts_url_and_its_domain_not_duplicated():
    result = extract_iocs("beacon to http://evil-c2.badguy.net/payload.ps1 detected")
    types = [i.type for i in result]
    values = [i.value for i in result]
    assert IOCType.url in types
    assert "http://evil-c2.badguy.net/payload.ps1" in values
    # the domain should not ALSO appear standalone since it's inside the URL
    assert not any(i.type == IOCType.domain and i.value == "evil-c2.badguy.net" for i in result)


def test_extracts_standalone_domain_with_known_tld():
    result = extract_iocs("dns query for evil-c2.badguy.net logged")
    values = {(i.type, i.value) for i in result}
    assert (IOCType.domain, "evil-c2.badguy.net") in values


def test_does_not_treat_dotted_username_as_domain():
    result = extract_iocs("Account Name: j.rahman logged on")
    assert not any(i.type == IOCType.domain and i.value == "j.rahman" for i in result)


def test_does_not_treat_process_image_as_domain():
    result = extract_iocs("Image=powershell.exe ParentImage=explorer.exe")
    assert not any(i.type == IOCType.domain for i in result)


def test_extracts_username_from_labeled_field():
    result = extract_iocs("Account Name: j.rahman Source Network Address: 8.8.8.8")
    values = {(i.type, i.value) for i in result}
    assert (IOCType.username, "j.rahman") in values


def test_username_requires_separator_not_bare_whitespace():
    # "account failed to log on" must NOT be mistaken for a username field
    result = extract_iocs("An account failed to log on to the workstation")
    assert not any(i.type == IOCType.username for i in result)


def test_sha256_preferred_over_shorter_hash_substrings():
    sha256 = "8f14e45fceea167a5a36dedd4bea2543dc5c4e6b0a55f8e0c8e5d2f4a1b3c7d9"
    result = extract_iocs(f"sha256={sha256}")
    values = {(i.type, i.value) for i in result}
    assert (IOCType.hash_sha256, sha256) in values
    assert not any(i.type in (IOCType.hash_sha1, IOCType.hash_md5) for i in result)


def test_deterministic_dedup_same_ioc_once():
    text = "185.220.101.47 seen twice: 185.220.101.47"
    result = extract_iocs(text)
    ips = [i for i in result if i.type == IOCType.ip]
    assert len(ips) == 1


def test_empty_input_returns_empty_list():
    assert extract_iocs("") == []
