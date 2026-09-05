from __future__ import annotations

KEY_ROLE_CARDS: tuple[dict[str, str], ...] = (
    {
        "role": "application-signing",
        "title": "Application Signing Key",
        "algorithm": "RSA-4096",
        "purpose": "Application X.509 certificate'ını imzalar.",
        "consumer": "System Firmware / TIFS doğrulama bağlamı",
        "classification": "Development/test local key veya external production signer",
        "warning": "Local key üretimi customer Root of Trust provisioning'i değildir.",
    },
    {
        "role": "application-mek",
        "title": "Application MEK",
        "algorithm": "AES-256",
        "purpose": "Application payload confidentiality için kullanılır.",
        "consumer": "System Firmware / TIFS decryption bağlamı",
        "classification": "Development/test local secret",
        "warning": "Confidentiality, authenticity ve integrity aynı özellik değildir.",
    },
    {
        "role": "smpk",
        "title": "SMPK",
        "algorithm": "RSA-4096",
        "purpose": "Primary customer signing Root of Trust hazırlık rolü.",
        "consumer": "OTP Keywriter / HS-SE customer trust bağlamı",
        "classification": "Provisioning-class material",
        "warning": "Toolkit yalnız synthetic/offline hazırlık yapar; OTP/eFuse write yapmaz.",
    },
    {
        "role": "bmpk",
        "title": "BMPK",
        "algorithm": "RSA-4096",
        "purpose": "Optional backup customer signing Root of Trust rolü.",
        "consumer": "OTP Keywriter / key revision strategy",
        "classification": "Provisioning-class material",
        "warning": "Backup key üretmek KEYREV değişikliği veya target activation değildir.",
    },
    {
        "role": "smek",
        "title": "SMEK",
        "algorithm": "AES-256",
        "purpose": "Primary customer encryption-key provisioning rolü.",
        "consumer": "OTP Keywriter / active customer MEK bağlamı",
        "classification": "Provisioning-class secret",
        "warning": "Synthetic SMEK production/customer secret değildir.",
    },
    {
        "role": "bmek",
        "title": "BMEK",
        "algorithm": "AES-256",
        "purpose": "Optional backup customer encryption-key provisioning rolü.",
        "consumer": "OTP Keywriter / backup customer MEK bağlamı",
        "classification": "Provisioning-class secret",
        "warning": "Synthetic BMEK target üzerinde active key değildir.",
    },
)


def list_key_roles() -> list[dict[str, str]]:
    return [dict(x) for x in KEY_ROLE_CARDS]


def key_role(role: str) -> dict[str, str]:
    for item in KEY_ROLE_CARDS:
        if item["role"] == role:
            return dict(item)
    raise KeyError(role)
