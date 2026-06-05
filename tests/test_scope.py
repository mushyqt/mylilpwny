import pytest
from pathlib import Path

from mylilpwny.core.scope import OutOfScopeError, ScopeValidator


# --- IP exact match ---

def test_ip_in_scope():
    sv = ScopeValidator(["10.0.0.1"])
    assert sv.is_in_scope("10.0.0.1")

def test_ip_not_in_scope():
    sv = ScopeValidator(["10.0.0.1"])
    assert not sv.is_in_scope("10.0.0.2")


# --- CIDR ---

def test_cidr_host_in_range():
    sv = ScopeValidator(["192.168.1.0/24"])
    assert sv.is_in_scope("192.168.1.100")

def test_cidr_host_out_of_range():
    sv = ScopeValidator(["192.168.1.0/24"])
    assert not sv.is_in_scope("192.168.2.1")

def test_cidr_network_address_in_scope():
    sv = ScopeValidator(["10.0.0.0/8"])
    assert sv.is_in_scope("10.255.255.255")


# --- Hostname ---

def test_hostname_in_scope():
    sv = ScopeValidator(["example.com"])
    assert sv.is_in_scope("example.com")

def test_hostname_case_insensitive():
    sv = ScopeValidator(["Example.COM"])
    assert sv.is_in_scope("example.com")

def test_hostname_not_in_scope():
    sv = ScopeValidator(["example.com"])
    assert not sv.is_in_scope("other.com")

def test_hostname_subdomain_does_not_match_root():
    sv = ScopeValidator(["example.com"])
    assert not sv.is_in_scope("sub.example.com")


# --- Wildcard ---

def test_wildcard_matches_subdomain():
    sv = ScopeValidator(["*.example.com"])
    assert sv.is_in_scope("sub.example.com")

def test_wildcard_matches_deep_subdomain():
    sv = ScopeValidator(["*.example.com"])
    assert sv.is_in_scope("a.b.example.com")

def test_wildcard_does_not_match_root():
    sv = ScopeValidator(["*.example.com"])
    assert not sv.is_in_scope("example.com")

def test_wildcard_does_not_match_other_domain():
    sv = ScopeValidator(["*.example.com"])
    assert not sv.is_in_scope("sub.other.com")


# --- Scope file ---

def test_from_file(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("# my scope\n10.0.0.1\n192.168.0.0/24\nexample.com\n*.test.com\n")
    sv = ScopeValidator.from_file(scope)
    assert sv.is_in_scope("10.0.0.1")
    assert sv.is_in_scope("192.168.0.50")
    assert sv.is_in_scope("example.com")
    assert sv.is_in_scope("api.test.com")
    assert not sv.is_in_scope("10.0.0.2")

def test_from_file_ignores_comments_and_blanks(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("# comment\n\n10.1.1.1\n")
    sv = ScopeValidator.from_file(scope)
    assert sv.is_in_scope("10.1.1.1")
    assert not sv.is_in_scope("10.1.1.2")


# --- from_target ---

def test_from_target_ip():
    sv = ScopeValidator.from_target("172.16.0.1")
    assert sv.is_in_scope("172.16.0.1")
    assert not sv.is_in_scope("172.16.0.2")

def test_from_target_cidr():
    sv = ScopeValidator.from_target("10.10.0.0/16")
    assert sv.is_in_scope("10.10.1.1")


# --- require_in_scope ---

def test_require_in_scope_passes():
    sv = ScopeValidator(["10.0.0.1"])
    sv.require_in_scope("10.0.0.1")  # should not raise

def test_require_in_scope_raises():
    sv = ScopeValidator(["10.0.0.1"])
    with pytest.raises(OutOfScopeError, match="out of scope"):
        sv.require_in_scope("10.0.0.2")


# --- empty scope ---

def test_empty_scope_blocks_everything():
    sv = ScopeValidator([])
    assert not sv.is_in_scope("10.0.0.1")
    assert not sv.is_in_scope("example.com")
