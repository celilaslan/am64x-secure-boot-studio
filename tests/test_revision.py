from am64x_secure_toolkit.revision import (
    key_revision_matrix,
    simulate_key_revision,
    simulate_swrev,
    swrev_field_info,
)


def test_keycnt_zero_has_no_numeric_keyrev():
    assert simulate_key_revision(0, None)["status"] == "PASS"
    assert simulate_key_revision(0, 1)["status"] == "FAIL"


def test_keycnt_keyrev_valid_contexts():
    p = simulate_key_revision(1, 1)
    assert p["status"] == "PASS"
    assert p["active_key_context"]["label"] == "SMPK/SMEK"
    b = simulate_key_revision(2, 2)
    assert b["status"] == "PASS"
    assert b["active_key_context"]["label"] == "BMPK/BMEK"


def test_keyrev_cannot_exceed_keycnt():
    out = simulate_key_revision(1, 2)
    assert out["status"] == "FAIL"


def test_requested_keyrev_does_not_claim_write_feasibility():
    out = simulate_key_revision(2, 1, 2)
    assert out["requested_state"]["status"] == "PASS"
    assert out["requested_state"]["write_feasibility"] == "NOT_CHECKED"
    assert out["execution"]["keyrev_write"] == "NOT_EXECUTED"


def test_key_matrix_contains_expected_valid_states():
    out = key_revision_matrix()
    valid = {(r["key_count"], r["key_revision"]) for r in out["rows"] if r["status"] == "PASS"}
    assert valid == {(0, None), (1, 1), (2, 1), (2, 2)}


def test_tiboot3_swrev_compare():
    assert simulate_swrev("tiboot3", 3, 2)["decision"] == "REJECT_BY_SWREV"
    assert simulate_swrev("tiboot3", 3, 3)["decision"] == "ACCEPT_BY_SWREV"
    assert simulate_swrev("tiboot3", 3, 4)["decision"] == "ACCEPT_BY_SWREV"


def test_boardcfg_swrev_compare():
    assert simulate_swrev("boardcfg", 5, 4)["decision"] == "REJECT_BY_SWREV"
    assert simulate_swrev("boardcfg", 5, 5)["decision"] == "ACCEPT_BY_SWREV"


def test_debug_revision_gate_is_not_full_authorization():
    out = simulate_swrev("debug", 7, 7)
    assert out["decision"] == "PASS_REVISION_GATE"
    assert "tek başına" in out["important"]


def test_application_does_not_claim_rollback_enforcement():
    out = simulate_swrev("application", 9, 1)
    assert out["decision"] == "NO_CURRENT_ENFORCEMENT_MODELED"
    assert out["application_swrev_enforcement"] == "NOT_VERIFIED"


def test_swrev_info_lengths_and_no_encoding():
    out = swrev_field_info()
    assert out["keywriter_fields"]["SWREV-SBL"]["encoded_bits"] == 96
    assert out["keywriter_fields"]["SWREV-SYSFW"]["single_copy_bits"] == 48
    assert out["keywriter_fields"]["SWREV-BOARDCONFIG"]["encoded_bits"] == 128
    assert out["encoding_generation"] == "NOT_IMPLEMENTED"
