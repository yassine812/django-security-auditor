"""Security utilities of the platform itself (spec 38)."""
import zipfile

import pytest

from apps.audits.utils import (is_local_target, is_within, mask_secret,
                               mask_secrets, safe_extract_zip, target_authorized)


# ---- secret masking ---------------------------------------------------------

def test_mask_secret_long():
    masked = mask_secret("abcdefghijklmnop")
    assert masked.startswith("abcd") and masked.endswith("op")
    assert "*" in masked and "abcdefghijklmnop" not in masked


def test_mask_secret_short():
    assert mask_secret("abc") == "***"


def test_mask_secret_empty():
    assert mask_secret("") == ""


def test_mask_aws_key():
    out = mask_secrets("key = AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert out.startswith("key = AKIA")


def test_mask_github_token():
    out = mask_secrets("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXyz")
    assert "ABCDEFGHIJKLMNOPQRSTUVWXyz" not in out


def test_mask_stripe_key():
    out = mask_secrets("STRIPE=sk_live_abcdef1234567890ZZ")
    assert "abcdef1234567890ZZ" not in out


def test_mask_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEsecretmaterial\n-----END RSA PRIVATE KEY-----"
    out = mask_secrets(pem)
    assert "MIIEsecretmaterial" not in out
    assert "masked" in out


def test_mask_generic_password_assignment():
    out = mask_secrets('password = "hunter2hunter2"')
    assert "hunter2hunter2" not in out


def test_mask_preserves_normal_text():
    text = "SELECT * FROM documents WHERE id = 5"
    assert mask_secrets(text) == text


# ---- path confinement --------------------------------------------------------

def test_is_within_true(tmp_path):
    assert is_within(tmp_path, tmp_path / "a" / "b.txt")


def test_is_within_false(tmp_path):
    assert not is_within(tmp_path / "a", tmp_path / "b.txt")


def test_safe_zip_normal(tmp_path):
    zp = tmp_path / "ok.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("project/manage.py", "print(1)")
        z.writestr("project/app/views.py", "x=1")
    out = safe_extract_zip(str(zp), str(tmp_path / "out"))
    assert len(out) == 2
    assert (tmp_path / "out" / "project" / "manage.py").exists()


def test_safe_zip_rejects_traversal(tmp_path):
    zp = tmp_path / "evil.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("../../etc/passwd", "root:x")
    with pytest.raises(ValueError):
        safe_extract_zip(str(zp), str(tmp_path / "out2"))


def test_safe_zip_rejects_absolute(tmp_path):
    zp = tmp_path / "evil2.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("/etc/evil", "x")
    with pytest.raises(ValueError):
        safe_extract_zip(str(zp), str(tmp_path / "out3"))


# ---- target authorization ------------------------------------------------------

def test_local_targets_allowed_by_default():
    ok, _ = target_authorized("127.0.0.1", {})
    assert ok


def test_localhost_allowed_by_default():
    ok, _ = target_authorized("localhost", {})
    assert ok


def test_public_ip_refused_by_default():
    ok, reason = target_authorized("8.8.8.8", {})
    assert not ok
    assert "authorized" in reason


def test_explicit_allowlist_accepted():
    ok, _ = target_authorized("10.1.2.3", {"network": {"authorized_targets": ["10.1.2.3"]}})
    assert ok


def test_is_local_target_private_ranges():
    assert is_local_target("192.168.1.10")
    assert is_local_target("10.0.0.5")
    assert is_local_target("::1")
    assert not is_local_target("93.184.216.34")
