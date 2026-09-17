from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ERRATA_SOURCE = {
    "document": "AM64x/AM243x Processor Silicon Revision 1.0, 2.0 Errata",
    "document_id": "SPRZ457J",
    "revision": "Rev. J / revised October 2025",
}


# Table 1-2 içindeki Boot advisories. Bu tablo yalnız revision/index filtresi içindir;
# ayrıntılı koşul ve workaround yorumu aşağıdaki CURATED_SECURITY_ERRATA içinde tutulur.
BOOT_ERRATA_INDEX: tuple[dict[str, Any], ...] = (
    {"id": "i2328", "title": "Boot: USB MSC boots intermittently", "revisions": ("1.0", "2.0"), "tags": ("usb", "boot-media")},
    {"id": "i2257", "title": "xSPI boot mode redundant image boot failure", "revisions": ("1.0",), "tags": ("xspi", "redundant", "boot-media")},
    {"id": "i2307", "title": "Boot: ROM does not properly select OSPI clocking modes based on BOOTMODE", "revisions": ("1.0", "2.0"), "tags": ("ospi", "boot-media")},
    {"id": "i2306", "title": "Boot: ROM does not turn off internal termination resistors in SERDES", "revisions": ("1.0",), "tags": ("serdes", "boot-media")},
    {"id": "i2363", "title": "Boot: Peak voltage transitions may exceed PCIe spec during PCIe boot", "revisions": ("1.0", "2.0"), "tags": ("pcie", "boot-media")},
    {"id": "i2366", "title": "Boot: ROM does not comprehend specific JEDEC SFDP features for 8D-8D-8D operation", "revisions": ("1.0", "2.0"), "tags": ("xspi", "sfdp", "boot-media")},
    {"id": "i2371", "title": "Boot: ROM code may hang in UART boot mode during data transfer", "revisions": ("1.0", "2.0"), "tags": ("uart", "boot-media")},
    {"id": "i2413", "title": "Boot: HS-FS ROM boots corrupted ROM boot image", "revisions": ("1.0", "2.0"), "tags": ("security", "hs-fs", "combined-image", "integrity")},
    {"id": "i2414", "title": "Boot: Ethernet PHY Scan and Bring-Up Flow doesn't work with PHYs that don't support Auto Negotiation", "revisions": ("1.0", "2.0"), "tags": ("ethernet", "boot-media")},
    {"id": "i2415", "title": "Boot: UART Backup Boot Authentication Failure w/ xSPI Primary Boot Mode", "revisions": ("1.0", "2.0"), "tags": ("security", "hs-se", "xspi", "uart", "redundant", "backup")},
    {"id": "i2417", "title": "Boot: GPMC NAND configured to slower clock speed", "revisions": ("1.0", "2.0"), "tags": ("gpmc", "nand", "boot-media")},
    {"id": "i2418", "title": "Boot: Secure ROM Panic due to Certificate Info not present", "revisions": ("1.0", "2.0"), "tags": ("security", "certificate", "rom")},
    {"id": "i2419", "title": "Boot: When disabling deskew calibration, ROM does not check if deskew calibration was enabled", "revisions": ("1.0", "2.0"), "tags": ("rom", "initialization")},
    {"id": "i2420", "title": "Boot: XSPI Boot time is not consistent in SFDP mode", "revisions": ("1.0", "2.0"), "tags": ("xspi", "sfdp", "boot-media")},
    {"id": "i2422", "title": "Boot: ROM timeout for MMCSD filesystem boot too long", "revisions": ("1.0", "2.0"), "tags": ("mmcsd", "filesystem", "boot-media")},
    {"id": "i2423", "title": "Boot: HS-FS ROM applies debug access restrictions to all address space covered by the efuse controller firewall", "revisions": ("1.0", "2.0"), "tags": ("security", "hs-fs", "debug", "firewall", "efuse")},
    {"id": "i2435", "title": "Boot: ROM timeout for eMMC boot too long", "revisions": ("1.0", "2.0"), "tags": ("emmc", "boot-media")},
    {"id": "i2482", "title": "Boot: ROM does not provide enough clocks during SD card initialization", "revisions": ("1.0", "2.0"), "tags": ("sd", "mmcsd", "boot-media")},
)


CURATED_SECURITY_ERRATA: dict[str, dict[str, Any]] = {
    "i2413": {
        "title": "Boot: HS-FS ROM boots corrupted ROM boot image",
        "revisions": ("1.0", "2.0"),
        "device_state": "hs-fs",
        "flow": "full-combined",
        "summary": (
            "HS-FS combined image non-degenerate RSA outer certificate ile hazırlandığında ROM, "
            "TIFS component integrity kontrolünü atlayabilir."
        ),
        "workaround": (
            "Outer X.509 certificate için RSA degenerate key kullan; errata bu seçimle bootloader ve "
            "TIFS component integrity kontrollerinin etkinleştiğini belirtir."
        ),
        "boundary": "Degenerate RSA workaround customer authenticity veya provisioned Root of Trust kanıtı değildir.",
    },
    "i2415": {
        "title": "Boot: UART Backup Boot Authentication Failure w/ xSPI Primary Boot Mode",
        "revisions": ("1.0", "2.0"),
        "device_state": "hs-se",
        "flow": "redundant-backup",
        "summary": (
            "HS-SE cihazda redundant address destekleyen xSPI/OSPI primary boot sonrasında, redundant offset'te "
            "tam ROM boot image yerine yalnız geçerli TIFS/SYSFW image bulunması ve ardından UART backup'a geçilmesi "
            "durumunda Secure ROM iç state'i tamamen sıfırlamayabilir; geçerli backup image authentication da başarısız olabilir."
        ),
        "workaround": "Redundant offset'te yalnız TIFS/SYSFW certificate/image değil, tam bir boot certificate/image bulundur.",
        "boundary": "Bu advisory belirli primary/redundant/backup failure sırasına bağlıdır; yalnız xSPI veya UART kullanımı tek başına yeterli değildir.",
    },
    "i2418": {
        "title": "Boot: Secure ROM Panic due to Certificate Info not present",
        "revisions": ("1.0", "2.0"),
        "flow": "normal",
        "summary": (
            "Full Combined Image dışındaki normal boot flow'da certificate içinde Extended info veya Legacy info bulunmazsa "
            "Secure ROM infinite loop/panic durumuna girebilir. Errata ayrıca address translation ve hash computation failure "
            "durumlarını da panic koşulları arasında listeler."
        ),
        "workaround": "Certificate içinde Extended info veya Legacy info bulunduğunu doğrula.",
        "boundary": "Araç address translation veya ROM hash-computation failure durumunu host üzerinde kanıtlayamaz.",
    },
    "i2423": {
        "title": "Boot: HS-FS ROM applies debug access restrictions to all address space covered by the efuse controller firewall",
        "revisions": ("1.0", "2.0"),
        "device_state": "hs-fs",
        "summary": (
            "HS-FS ROM, secure assets içeren FWL 33 ve 66 için debug restriction'ı yalnız secure-asset alt bölgesine değil "
            "firewall region'ın tamamına uygular; bu durum external emulator ile ilk flash programlama gibi erişimleri engelleyebilir."
        ),
        "workaround": "İhtiyaç duyulan firewall erişimini açtırmak için TIFS/SYSFW devrede olmalıdır.",
        "boundary": "Bu kayıt firewall erişim kısıtını açıklar; adresin yanlış olduğu veya secret'ın okunabilir/okunamaz olduğu sonucunu tek başına kurmaz.",
    },
}


_BOOT_MODE_TAGS = {
    "uart": {"uart"},
    "ospi": {"ospi", "xspi"},
    "xspi": {"xspi"},
    "qspi": {"qspi"},
    "spi": {"spi"},
    "ethernet": {"ethernet"},
    "mmcsd": {"mmcsd", "sd"},
    "sd": {"sd", "mmcsd"},
    "emmc": {"emmc"},
    "usb": {"usb"},
    "pcie": {"pcie"},
    "gpmc": {"gpmc"},
    "unknown": set(),
}


def _norm_revision(revision: str) -> str:
    value = revision.strip().lower().replace("sr", "")
    if value not in {"1.0", "2.0"}:
        raise ValueError("silicon revision yalnız 1.0 veya 2.0 olabilir")
    return value


def _write_report(result: dict[str, Any], report: Path | None) -> None:
    if report is None:
        return
    if report.exists():
        raise FileExistsError(f"rapor zaten mevcut: {report}")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    result["report"] = str(report)


def list_errata(*, revision: str, category: str = "all", boot_mode: str = "unknown") -> dict[str, Any]:
    """Errata Rev. J Table 1-2 Boot indexini revision ve basit kullanım etiketiyle filtreler."""
    rev = _norm_revision(revision)
    if category not in {"all", "security", "boot-media", "debug"}:
        raise ValueError("category: all, security, boot-media veya debug olmalıdır")
    if boot_mode not in _BOOT_MODE_TAGS:
        raise ValueError("desteklenmeyen boot_mode")

    mode_tags = _BOOT_MODE_TAGS[boot_mode]
    rows: list[dict[str, Any]] = []
    for item in BOOT_ERRATA_INDEX:
        if rev not in item["revisions"]:
            continue
        tags = set(item["tags"])
        if category != "all" and category not in tags:
            # debug ayrı category; security+debug kaydı i2423 için iki etiket de var.
            continue
        if boot_mode != "unknown" and not (tags & mode_tags):
            continue
        rows.append({
            "id": item["id"],
            "title": item["title"],
            "matrix_applicable_to_revision": True,
            "tags": list(item["tags"]),
            "details_modeled": item["id"] in CURATED_SECURITY_ERRATA,
        })

    return {
        "status": "PASS",
        "tool": "am64x_errata_index",
        "silicon_revision": rev,
        "category": category,
        "boot_mode": boot_mode,
        "source": ERRATA_SOURCE,
        "advisories": rows,
        "interpretation": (
            "Bu liste Errata Rev. J applicability matrix'ini filtreler. Bir satırın listelenmesi, mevcut karttaki problemin "
            "o advisory'den kaynaklandığını kanıtlamaz; Details ve Workaround koşulları ayrıca değerlendirilmelidir."
        ),
    }


def _base_eval(erratum_id: str, revision: str) -> dict[str, Any]:
    item = CURATED_SECURITY_ERRATA[erratum_id]
    return {
        "id": erratum_id,
        "title": item["title"],
        "revision_applicable": revision in item["revisions"],
        "summary": item["summary"],
        "workaround": item["workaround"],
        "boundary": item["boundary"],
        "source": {**ERRATA_SOURCE, "advisory": erratum_id},
        "assessment": "REVIEW",
        "reason": "Bağlam bilgileriyle advisory koşulu değerlendirilmedi.",
    }


def _eval_i2413(revision: str, device_state: str, flow: str, outer_rsa: str) -> dict[str, Any]:
    out = _base_eval("i2413", revision)
    if not out["revision_applicable"]:
        out.update(assessment="NOT_APPLICABLE", reason="Seçilen silicon revision advisory matrix'inde affected değil.")
        return out
    if device_state not in {"hs-fs", "unknown"}:
        out.update(assessment="OUTSIDE_DOCUMENTED_CONTEXT", reason="i2413 documented device state HS-FS'tir.")
        return out
    if flow not in {"full-combined", "unknown"}:
        out.update(assessment="OUTSIDE_DOCUMENTED_CONTEXT", reason="i2413 combined ROM image akışına ilişkindir.")
        return out
    if device_state == "hs-fs" and flow == "full-combined":
        if outer_rsa == "non-degenerate":
            out.update(assessment="RISK_CONDITION_MATCH", reason="HS-FS + combined image + non-degenerate RSA koşulu erratum ile eşleşiyor.")
        elif outer_rsa == "degenerate":
            out.update(assessment="WORKAROUND_CONDITION_SATISFIED", reason="Errata'nın önerdiği RSA degenerate outer certificate seçimi belirtilmiş.")
        else:
            out.update(assessment="POTENTIALLY_APPLICABLE", reason="HS-FS combined image eşleşiyor; outer RSA türü bilinmiyor.")
    else:
        out.update(assessment="POTENTIALLY_APPLICABLE", reason="Device state veya flow bilinmediği için applicability tam daraltılamıyor.")
    return out


def _eval_i2415(
    revision: str,
    device_state: str,
    flow: str,
    primary_boot: str,
    backup_boot: str,
    redundant_content: str,
) -> dict[str, Any]:
    out = _base_eval("i2415", revision)
    if not out["revision_applicable"]:
        out.update(assessment="NOT_APPLICABLE", reason="Seçilen silicon revision advisory matrix'inde affected değil.")
        return out
    if device_state not in {"hs-se", "unknown"}:
        out.update(assessment="OUTSIDE_DOCUMENTED_CONTEXT", reason="i2415 documented device state HS-SE'dir.")
        return out
    primary_match = primary_boot in {"xspi", "ospi"}
    backup_match = backup_boot == "uart"
    flow_match = flow == "redundant-backup"
    if device_state == "hs-se" and primary_match and backup_match and flow_match:
        if redundant_content == "tifs-only":
            out.update(assessment="RISK_CONDITION_MATCH", reason="HS-SE + xSPI/OSPI primary + UART backup + redundant offset'te TIFS-only koşulu eşleşiyor.")
        elif redundant_content == "complete-boot":
            out.update(assessment="WORKAROUND_CONDITION_SATISFIED", reason="Redundant offset için tam boot certificate/image belirtildi.")
        else:
            out.update(assessment="POTENTIALLY_APPLICABLE", reason="Boot topolojisi eşleşiyor; redundant offset içeriği tam bilinmiyor.")
    elif any(v == "unknown" for v in (device_state, primary_boot, backup_boot, flow)):
        out.update(assessment="POTENTIALLY_APPLICABLE", reason="i2415 için gerekli boot/failure bağlamının bir kısmı bilinmiyor.")
    else:
        out.update(assessment="OUTSIDE_DOCUMENTED_CONTEXT", reason="Verilen device-state/primary/backup/flow kombinasyonu documented i2415 koşuluyla eşleşmiyor.")
    return out


def _eval_i2418(revision: str, flow: str, certificate_info: str) -> dict[str, Any]:
    out = _base_eval("i2418", revision)
    if not out["revision_applicable"]:
        out.update(assessment="NOT_APPLICABLE", reason="Seçilen silicon revision advisory matrix'inde affected değil.")
        return out
    if flow == "full-combined":
        out.update(assessment="OUTSIDE_DOCUMENTED_CONTEXT", reason="i2418 details metni Full Combined Image dışındaki normal boot flow'u tanımlar.")
        return out
    if flow == "normal":
        if certificate_info == "absent":
            out.update(assessment="RISK_CONDITION_MATCH", reason="Normal boot flow + certificate info absent koşulu erratum ile eşleşiyor.")
        elif certificate_info == "present":
            out.update(assessment="WORKAROUND_CONDITION_SATISFIED", reason="Certificate içinde Extended veya Legacy info bulunduğu belirtilmiş.")
        else:
            out.update(assessment="POTENTIALLY_APPLICABLE", reason="Normal boot flow eşleşiyor; certificate info varlığı bilinmiyor.")
    else:
        out.update(assessment="POTENTIALLY_APPLICABLE", reason="Full Combined Image dışı normal flow olup olmadığı bilinmiyor.")
    return out


def _eval_i2423(revision: str, device_state: str, external_emulator: str) -> dict[str, Any]:
    out = _base_eval("i2423", revision)
    if not out["revision_applicable"]:
        out.update(assessment="NOT_APPLICABLE", reason="Seçilen silicon revision advisory matrix'inde affected değil.")
        return out
    if device_state not in {"hs-fs", "unknown"}:
        out.update(assessment="OUTSIDE_DOCUMENTED_CONTEXT", reason="i2423 documented device state HS-FS'tir.")
        return out
    if device_state == "hs-fs":
        if external_emulator == "yes":
            out.update(assessment="APPLICABLE_TO_ACCESS_CONTEXT", reason="HS-FS + external emulator/debug access kullanımı i2423 erişim bağlamıyla eşleşiyor.")
        elif external_emulator == "no":
            out.update(assessment="APPLICABLE_DEVICE_STATE_CONTEXT_NOT_SELECTED", reason="HS-FS affected revision ancak external emulator/debug erişimi bu kullanımda seçilmemiş.")
        else:
            out.update(assessment="POTENTIALLY_APPLICABLE", reason="HS-FS eşleşiyor; external emulator/debug erişim bağlamı bilinmiyor.")
    else:
        out.update(assessment="POTENTIALLY_APPLICABLE", reason="Device state bilinmediği için HS-FS applicability daraltılamıyor.")
    return out


def check_errata(
    *,
    revision: str,
    device_state: str = "unknown",
    flow: str = "unknown",
    primary_boot: str = "unknown",
    backup_boot: str = "unknown",
    outer_rsa: str = "unknown",
    certificate_info: str = "unknown",
    redundant_content: str = "unknown",
    external_emulator: str = "unknown",
    report: Path | None = None,
) -> dict[str, Any]:
    """Secure Boot/ROM/security açısından seçilmiş advisories'i verilen bağlamla değerlendirir."""
    rev = _norm_revision(revision)
    if device_state not in {"gp", "hs-fs", "hs-se", "unknown"}:
        raise ValueError("device_state: gp, hs-fs, hs-se veya unknown olmalıdır")
    if flow not in {"full-combined", "normal", "redundant-backup", "unknown"}:
        raise ValueError("flow: full-combined, normal, redundant-backup veya unknown olmalıdır")
    if primary_boot not in _BOOT_MODE_TAGS or backup_boot not in _BOOT_MODE_TAGS:
        raise ValueError("desteklenmeyen primary/backup boot mode")
    if outer_rsa not in {"degenerate", "non-degenerate", "unknown"}:
        raise ValueError("outer_rsa: degenerate, non-degenerate veya unknown olmalıdır")
    if certificate_info not in {"present", "absent", "unknown"}:
        raise ValueError("certificate_info: present, absent veya unknown olmalıdır")
    if redundant_content not in {"complete-boot", "tifs-only", "other", "unknown"}:
        raise ValueError("redundant_content: complete-boot, tifs-only, other veya unknown olmalıdır")
    if external_emulator not in {"yes", "no", "unknown"}:
        raise ValueError("external_emulator: yes, no veya unknown olmalıdır")

    evaluations = [
        _eval_i2413(rev, device_state, flow, outer_rsa),
        _eval_i2415(rev, device_state, flow, primary_boot, backup_boot, redundant_content),
        _eval_i2418(rev, flow, certificate_info),
        _eval_i2423(rev, device_state, external_emulator),
    ]

    attention_codes = {"RISK_CONDITION_MATCH", "APPLICABLE_TO_ACCESS_CONTEXT"}
    potential_codes = {"POTENTIALLY_APPLICABLE"}
    attention = [row["id"] for row in evaluations if row["assessment"] in attention_codes]
    potential = [row["id"] for row in evaluations if row["assessment"] in potential_codes]
    mitigated = [row["id"] for row in evaluations if row["assessment"] == "WORKAROUND_CONDITION_SATISFIED"]

    media_by_id: dict[str, dict[str, Any]] = {}
    for role, mode in (("primary_boot", primary_boot), ("backup_boot", backup_boot)):
        if mode == "unknown":
            continue
        mode_index = list_errata(revision=rev, category="all", boot_mode=mode)
        for row in mode_index["advisories"]:
            if row["id"] in CURATED_SECURITY_ERRATA:
                continue
            existing = media_by_id.get(row["id"])
            if existing is None:
                existing = dict(row)
                existing["matched_via"] = []
                media_by_id[row["id"]] = existing
            existing["matched_via"].append({"role": role, "boot_mode": mode})
    media_candidates = list(media_by_id.values())

    if attention:
        assessment = "ATTENTION_REQUIRED"
    elif potential:
        assessment = "REVIEW_INCOMPLETE_CONTEXT"
    else:
        assessment = "NO_CURATED_RISK_CONDITION_MATCH"

    result: dict[str, Any] = {
        "status": "PASS",
        "tool": "am64x_errata_check",
        "assessment": assessment,
        "inputs": {
            "silicon_revision": rev,
            "device_state": device_state,
            "flow": flow,
            "primary_boot": primary_boot,
            "backup_boot": backup_boot,
            "outer_rsa": outer_rsa,
            "certificate_info": certificate_info,
            "redundant_content": redundant_content,
            "external_emulator": external_emulator,
        },
        "source": ERRATA_SOURCE,
        "security_rom_advisories": evaluations,
        "boot_media_matrix_candidates": media_candidates,
        "summary": {
            "attention_required": attention,
            "potentially_applicable": potential,
            "workaround_condition_satisfied": mitigated,
        },
        "interpretation": (
            "Bu çıktı bir teşhis yardımcısıdır. Advisory applicability veya risk koşulu eşleşmesi, observed failure'ın "
            "kök nedeninin o erratum olduğunu kanıtlamaz. Önce image/configuration/hash/load path kontrolleri, ardından "
            "ilgili advisory'nin exact Details ve Workaround metni değerlendirilmelidir."
        ),
        "execution": {
            "target_access": "NO",
            "files_modified": "NO",
            "otp_efuse": "NOT_EXECUTED",
            "debug_unlock": "NOT_EXECUTED",
            "lifecycle_change": "NOT_EXECUTED",
        },
    }
    _write_report(result, report)
    return result
