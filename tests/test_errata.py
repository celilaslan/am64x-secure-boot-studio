from am64x_secure_toolkit.errata import check_errata, list_errata


def _by_id(out, advisory_id):
    return next(row for row in out["security_rom_advisories"] if row["id"] == advisory_id)


def test_errata_index_revision_filter_sr1_has_i2257():
    out = list_errata(revision="1.0")
    ids = {row["id"] for row in out["advisories"]}
    assert "i2257" in ids
    assert "i2413" in ids


def test_errata_index_revision_filter_sr2_drops_i2257():
    out = list_errata(revision="SR2.0")
    ids = {row["id"] for row in out["advisories"]}
    assert "i2257" not in ids
    assert "i2413" in ids


def test_errata_index_boot_mode_uart():
    out = list_errata(revision="2.0", boot_mode="uart")
    ids = {row["id"] for row in out["advisories"]}
    assert "i2371" in ids
    assert "i2415" in ids
    assert "i2307" not in ids


def test_i2413_non_degenerate_risk_condition():
    out = check_errata(
        revision="2.0", device_state="hs-fs", flow="full-combined", outer_rsa="non-degenerate"
    )
    row = _by_id(out, "i2413")
    assert row["assessment"] == "RISK_CONDITION_MATCH"
    assert out["assessment"] == "ATTENTION_REQUIRED"


def test_i2413_degenerate_matches_workaround_condition():
    out = check_errata(
        revision="1.0", device_state="hs-fs", flow="full-combined", outer_rsa="degenerate"
    )
    assert _by_id(out, "i2413")["assessment"] == "WORKAROUND_CONDITION_SATISFIED"


def test_i2413_not_generalized_to_hsse():
    out = check_errata(
        revision="2.0", device_state="hs-se", flow="full-combined", outer_rsa="non-degenerate"
    )
    assert _by_id(out, "i2413")["assessment"] == "OUTSIDE_DOCUMENTED_CONTEXT"


def test_i2418_absent_certificate_info_risk():
    out = check_errata(revision="2.0", flow="normal", certificate_info="absent")
    assert _by_id(out, "i2418")["assessment"] == "RISK_CONDITION_MATCH"


def test_i2418_full_combined_outside_documented_flow():
    out = check_errata(revision="2.0", flow="full-combined", certificate_info="absent")
    assert _by_id(out, "i2418")["assessment"] == "OUTSIDE_DOCUMENTED_CONTEXT"


def test_i2415_specific_failure_topology_and_workaround():
    risk = check_errata(
        revision="2.0", device_state="hs-se", flow="redundant-backup",
        primary_boot="ospi", backup_boot="uart", redundant_content="tifs-only"
    )
    assert _by_id(risk, "i2415")["assessment"] == "RISK_CONDITION_MATCH"
    mitigated = check_errata(
        revision="2.0", device_state="hs-se", flow="redundant-backup",
        primary_boot="xspi", backup_boot="uart", redundant_content="complete-boot"
    )
    assert _by_id(mitigated, "i2415")["assessment"] == "WORKAROUND_CONDITION_SATISFIED"


def test_i2423_hsfs_external_emulator_context():
    out = check_errata(revision="2.0", device_state="hs-fs", external_emulator="yes")
    row = _by_id(out, "i2423")
    assert row["assessment"] == "APPLICABLE_TO_ACCESS_CONTEXT"
    assert "TIFS" in row["workaround"]


def test_errata_check_never_claims_root_cause_or_executes_target_actions():
    out = check_errata(revision="2.0", device_state="hs-fs")
    assert "kök neden" in out["interpretation"]
    assert out["execution"]["target_access"] == "NO"
    assert out["execution"]["otp_efuse"] == "NOT_EXECUTED"


def test_errata_check_uses_backup_boot_for_media_index():
    out = check_errata(revision="2.0", backup_boot="uart")
    ids = {row["id"] for row in out["boot_media_matrix_candidates"]}
    assert "i2371" in ids
