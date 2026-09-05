from am64x_secure_toolkit.services.claim_boundary import claims_for


def test_provision_and_debug_claim_boundaries_are_explicit():
    claims, non = claims_for("provision_preflight", "PASS")
    assert any("host-side preflight" in x for x in claims)
    assert any("eFuse" in x or "Keywriter" in x for x in non)

    claims, non = claims_for("secure_debug", "PASS")
    assert any("offline" in x for x in claims)
    assert any("JTAG unlock" in x for x in non)


def test_rom_claim_does_not_become_hardware_claim():
    claims, non = claims_for("rom_build", "PASS", encrypted=True)
    assert any("rom_image_gen.py" in x for x in claims)
    assert any("fiziksel cihaz" in x for x in non)
