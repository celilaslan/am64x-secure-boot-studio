"""AM64x/TISCI 12.00.02 için sürüme bağlı sabitler."""

TI_OIDS = {
    "rom_boot_info": "1.3.6.1.4.1.294.1.1",
    "rom_image_integrity": "1.3.6.1.4.1.294.1.2",
    "software_revision": "1.3.6.1.4.1.294.1.3",
    "sysfw_encryption": "1.3.6.1.4.1.294.1.4",
    "sysfw_debug": "1.3.6.1.4.1.294.1.8",
    "rom_ext_boot_info": "1.3.6.1.4.1.294.1.9",
    "rom_ext_boot_encryption": "1.3.6.1.4.1.294.1.10",
    "sysfw_boot": "1.3.6.1.4.1.294.1.33",
    "sysfw_image_integrity": "1.3.6.1.4.1.294.1.34",
    "sysfw_image_load": "1.3.6.1.4.1.294.1.35",
    "sysfw_hs_boardcfg": "1.3.6.1.4.1.294.1.36",
    "sysfw_firewall": "1.3.6.1.4.1.294.1.37",
    "sysfw_key_info": "1.3.6.1.4.1.294.1.38",
    "sysfw_keyring_info": "1.3.6.1.4.1.294.1.39",
    "sysfw_extended_encryption": "1.3.6.1.4.1.294.1.40",
    "sysfw_debug_suspend": "1.3.6.1.4.1.294.1.41",
    "keywriter_encrypted_aes": "1.3.6.1.4.1.294.1.64",
    "keywriter_encrypted_smpk_signed_aes": "1.3.6.1.4.1.294.1.65",
    "keywriter_encrypted_bmpk_signed_aes": "1.3.6.1.4.1.294.1.66",
    "keywriter_aes_encrypted_smpkh": "1.3.6.1.4.1.294.1.67",
    "keywriter_aes_encrypted_smek": "1.3.6.1.4.1.294.1.68",
    "keywriter_mpk_options": "1.3.6.1.4.1.294.1.69",
    "keywriter_aes_encrypted_bmpkh": "1.3.6.1.4.1.294.1.70",
    "keywriter_aes_encrypted_bmek": "1.3.6.1.4.1.294.1.71",
    "keywriter_mek_options": "1.3.6.1.4.1.294.1.72",
    "keywriter_extended_otp": "1.3.6.1.4.1.294.1.73",
    "keywriter_key_revision": "1.3.6.1.4.1.294.1.74",
    "keywriter_msv": "1.3.6.1.4.1.294.1.76",
    "keywriter_key_count": "1.3.6.1.4.1.294.1.77",
    "keywriter_swrev_sysfw": "1.3.6.1.4.1.294.1.78",
    "keywriter_swrev_sbl": "1.3.6.1.4.1.294.1.79",
    "keywriter_swrev_sec_boardcfg": "1.3.6.1.4.1.294.1.80",
    "keywriter_version": "1.3.6.1.4.1.294.1.81",
}

OID_NAMES = {v: k for k, v in TI_OIDS.items()}
SHA512_OID = "2.16.840.1.101.3.4.2.3"

KEYWRITER_OIDS = {
    value for key, value in TI_OIDS.items() if key.startswith("keywriter_")
}

ROM_COMPONENT_TYPES = {
    0x01: "SBL binary",
    0x02: "SYSFW binary",
    0x03: "SYSFW Inner Certificate",
    0x11: "SBL memory-load section",
    0x12: "SYSFW memory-load section",
}

VERIFICATION_SCOPE = {
    "hardware_application_authentication_enforcement": "NOT VERIFIED / NOT EXECUTED",
    "hardware_application_decryption_enforcement": "NOT VERIFIED / NOT EXECUTED",
    "customer_root_of_trust_enforcement": "NOT VERIFIED",
    "otp_efuse_customer_key_provisioning": "NOT EXECUTED",
    "hs_fs_to_hs_se": "NOT EXECUTED",
    "secure_debug_unlock": "NOT EXECUTED",
}
