from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class SourceRecord:
    id: str
    title: str
    scope: str
    priority: int
    expected_filename: str | None = None
    summary: str | None = None


_SOURCE_ROWS = [
    SourceRecord(
        "SDK-INSTALLED",
        "Installed MCU+ SDK source / Makefile / verbose build",
        "Exact installed configuration-to-consumer behavior",
        1,
        None,
        "Exact option, path, Makefile chain veya signer behavior sorularında ilk tercih. Studio bu kaynağı ancak kullanıcının SDK kurulumundan gerçekten resolve edebildiğinde authoritative sayar.",
    ),
    SourceRecord(
        "SDK-SECURE-BOOT",
        "MCU+ SDK 12.00.00.27 Secure Boot",
        "devconfig, signing tools, application/ROM image generation",
        2,
        "SDK-02_AM64x_12.00.00.27_SECURE_BOOT.pdf",
        "HS-SE secure-boot flow, devconfig.mak rolleri, combined image ve application signing/encryption ilişkisi.",
    ),
    SourceRecord(
        "SDK-TOOLS-SECURITY",
        "MCU+ SDK 12.00.00.27 Security Related Tools",
        "rom_image_gen.py / appimage_x509_cert_gen.py usage",
        2,
        "SDK03_AM64x_12.00.00.27_TOOLS_SECURITY.pdf",
        "ROM ve application signer komutları, image integrity ve encryption tool seçenekleri.",
    ),
    SourceRecord(
        "TISCI-SIGNING",
        "TISCI 12.00.02 Secure Boot Signing",
        "Signed and encrypted binary preparation",
        2,
        "TISCI-01_12.00.02_Secure_Boot_Signing.pdf",
        "Unencrypted ve encrypted binary signing sırası; SHA2-512, Load/SWREV/Boot extensions, active MPK/MEK ve AES-256-CBC hazırlığı.",
    ),
    SourceRecord(
        "TISCI-X509",
        "TISCI 12.00.02 Security X509 Certificate",
        "System Firmware X.509 extensions",
        2,
        "TISCI-02_12.00.02_Security_X509_Certificate.pdf",
        "System Firmware ve Keywriter X.509 extension aileleri ile image-type applicability tablosu.",
    ),
    SourceRecord(
        "TISCI-KEYWRITER",
        "TISCI 12.00.02 Key Writer",
        "HS-FS/HS-SE lifecycle and customer key roles",
        2,
        "TISCI-03_12.00.02_Key_Writer_rendered.pdf",
        "HS-FS→HS-SE provisioning mimarisi, SMPK/BMPK, SMEK/BMEK ve Keywriter certificate flow.",
    ),
    SourceRecord(
        "TISCI-AUTH",
        "TISCI 12.00.02 Authentication and Decryption Requests",
        "RSA-4K authentication, SHA2-512 integrity, AES-256-CBC decryption",
        2,
        "TISCI-04_12.00.02_Authentication_and_Decryption_Requests_rendered.pdf",
        "TISCI_MSG_PROC_AUTH_BOOT sırasında public-key integrity, certificate authentication, payload integrity, optional decryption ve decrypted-result correctness sırası.",
    ),
    SourceRecord(
        "TISCI-PROC-BOOT",
        "TISCI 12.00.02 Processor Boot Management",
        "Authenticated processor boot API and secure-host access control",
        2,
        "TISCI-05_12.00.02_Processor_Boot_Management_rendered.pdf",
        "TISCI_MSG_PROC_AUTH_BOOT availability, secure-host/current-control şartları ve processor boot API sequencing.",
    ),
    SourceRecord(
        "TISCI-DEBUG",
        "TISCI 12.00.02 Secure Debug User Guide",
        "Secure Debug certificate and runtime authorization",
        2,
        "TISCI-06_12.00.02_Secure_Debug_User_Guide_rendered.pdf",
        "HS device JTAG defaults, boot certificate'tan ayrı debug certificate ve BoardCfg/eFuse authorization sınırları.",
    ),
    SourceRecord(
        "TISCI-BOARDCFG",
        "TISCI 12.00.02 Security Board Configuration",
        "Runtime security initialization and policy",
        2,
        "TISCI-07_12.00.02_Security_Board_Configuration_rendered.pdf",
        "Security BoardCfg message, secure-queue requirement ve HS device authenticity/confidentiality requirement.",
    ),
    SourceRecord(
        "ERRATA-REVJ",
        "AM64x/AM243x Errata RevJ",
        "Boot/security advisories",
        3,
        "SIL-01_AM64x_AM243x_Errata_RevJ.pdf",
        "Silicon revision-specific boot/security advisories; özellikle i2413 ve i2423 gibi AM64x boot/security maddeleri.",
    ),
    SourceRecord(
        "TRM-BOOT",
        "AM64x/AM243x TRM RevJ Initialization and Boot",
        "Boot flow and lifecycle terminology",
        4,
        "TRM-FOCUS-01_AM64x_AM243x_RevJ_Initialization_and_Boot_p0078-0139.pdf",
        "ROM initialization, boot process ve HS-FS/HS-SE terminology.",
    ),
    SourceRecord(
        "TRM-INTERCONNECT",
        "AM64x/AM243x TRM RevJ System Interconnect and Firewall",
        "Interconnect/firewall access model",
        4,
        "TRM-FOCUS-02_AM64x_AM243x_RevJ_System_Interconnect_and_Firewall_p0050-0077.pdf",
        "PrivID/Secure/Priv attributes, ISC ve firewall davranışı.",
    ),
    SourceRecord(
        "DATASHEET-REVJ",
        "AM64x Datasheet RevJ",
        "Device-level security capability summary",
        4,
        "SIL-02_AM64x_Datasheet_RevJ.pdf",
        "Hardware-enforced Root-of-Trust, backup key, anti-rollback, crypto accelerators ve security controller capability summary.",
    ),
]

SOURCES: dict[str, SourceRecord] = {row.id: row for row in _SOURCE_ROWS}


def get_source(source_id: str) -> dict[str, object]:
    try:
        return asdict(SOURCES[source_id])
    except KeyError:
        raise KeyError(source_id) from None


def list_sources() -> list[dict[str, object]]:
    return [asdict(x) for x in sorted(_SOURCE_ROWS, key=lambda r: (r.priority, r.id))]


def source_card(source_id: str) -> str:
    row = SOURCES[source_id]
    bits = [row.title, f"Scope: {row.scope}", f"Source priority: {row.priority}"]
    if row.expected_filename:
        bits.append(f"Local reference: {row.expected_filename}")
    if row.summary:
        bits += ["", row.summary]
    return "\n".join(bits)
