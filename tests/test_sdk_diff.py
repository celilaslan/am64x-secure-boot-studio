from __future__ import annotations

from pathlib import Path

import pytest

from am64x_secure_toolkit.sdk_diff import compare_sdk_security


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_identical_file_is_pass(tmp_path: Path):
    old = _write(tmp_path / "old.mak", "ENC_ENABLED?=no\nAPP_SIGNING_KEY=$(CUST_MPK)\n")
    new = _write(tmp_path / "new.mak", old.read_text())
    out = compare_sdk_security(old_devconfig=old, new_devconfig=new)
    assert out["status"] == "PASS"
    assert out["comparisons"]["devconfig"]["classification"] == "IDENTICAL"
    assert out["summary"]["identical"] == ["devconfig"]


def test_mapped_devconfig_change_requires_review(tmp_path: Path):
    old = _write(tmp_path / "old.mak", "DEVICE_TYPE?=GP\nENC_ENABLED?=no\nENC_SBL_ENABLED?=yes\nAPP_SIGNING_KEY=$(CUST_MPK)\nAPP_ENCRYPTION_KEY=$(CUST_MEK)\n")
    new = _write(tmp_path / "new.mak", "DEVICE_TYPE?=GP\nENC_ENABLED?=yes\nENC_SBL_ENABLED?=yes\nAPP_SIGNING_KEY=$(CUST_MPK)\nAPP_ENCRYPTION_KEY=$(CUST_MEK)\n")
    out = compare_sdk_security(old_devconfig=old, new_devconfig=new)
    row = out["comparisons"]["devconfig"]
    assert out["status"] == "PARTIAL"
    assert row["classification"] == "MAPPED_SECURITY_BEHAVIOR_CHANGED"
    assert any(c["field"].endswith("ENC_ENABLED.value") for c in row["semantic_changes"])


def test_unmapped_text_change_is_not_called_safe(tmp_path: Path):
    old = _write(tmp_path / "old.py", "opts=['--enc','--enckey','--authtype']\naes='aes-256-cbc'\n-K\nsha512\n1.3.6.1.4.1.294.1.4\n1.3.6.1.4.1.294.1.34\n")
    new = _write(tmp_path / "new.py", old.read_text() + "# comment changed\n")
    out = compare_sdk_security(old_app_tool=old, new_app_tool=new)
    row = out["comparisons"]["app_tool"]
    assert out["status"] == "PARTIAL"
    assert row["classification"] == "CONTENT_CHANGED_NO_MAPPED_SECURITY_CHANGE"
    assert row["review"] == "RECOMMENDED"


def test_oid_change_is_detected(tmp_path: Path):
    base = "opts=['--enc','--enckey','--authtype']\naes='aes-256-cbc'\n-K\nsha512\n1.3.6.1.4.1.294.1.4\n1.3.6.1.4.1.294.1.34\n"
    old = _write(tmp_path / "old.py", base)
    new = _write(tmp_path / "new.py", base.replace("1.3.6.1.4.1.294.1.34", "1.3.6.1.4.1.294.1.99"))
    out = compare_sdk_security(old_app_tool=old, new_app_tool=new)
    changes = out["comparisons"]["app_tool"]["semantic_changes"]
    assert any(c["field"] == "oids.integrity_1_34" and c["before"] is True and c["after"] is False for c in changes)


def test_secret_literal_is_never_echoed(tmp_path: Path):
    secret = "ab" * 32
    old = _write(tmp_path / "old.mak", "ENC_ENABLED?=no\n")
    new = _write(tmp_path / "new.mak", f"ENC_ENABLED?=no\nCUST_MEK={secret}\n")
    out = compare_sdk_security(old_devconfig=old, new_devconfig=new)
    assert out["status"] == "FAIL"
    assert secret not in str(out)
    assert out["summary"]["secret_hygiene_errors"]


def test_incomplete_pair_is_rejected(tmp_path: Path):
    old = _write(tmp_path / "old.mak", "ENC_ENABLED?=no\n")
    with pytest.raises(ValueError):
        compare_sdk_security(old_devconfig=old)


def test_report_does_not_overwrite(tmp_path: Path):
    old = _write(tmp_path / "old.mak", "ENC_ENABLED?=no\n")
    new = _write(tmp_path / "new.mak", "ENC_ENABLED?=no\n")
    report = tmp_path / "diff.json"
    out = compare_sdk_security(old_devconfig=old, new_devconfig=new, report=report)
    assert out["status"] == "PASS"
    assert report.exists()
    with pytest.raises(FileExistsError):
        compare_sdk_security(old_devconfig=old, new_devconfig=new, report=report)
