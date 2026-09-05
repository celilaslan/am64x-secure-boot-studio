"""İnsan tarafından okunabilir doğrulama raporları üretir."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .inspect import inspect_artifact
from .verify import verify_artifact


def _status_counts(checks: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"PASS": 0, "FAIL": 0, "NOT_CHECKED": 0, "OTHER": 0}
    for check in checks:
        status = str(check.get("status", "OTHER"))
        if status in counts:
            counts[status] += 1
        else:
            counts["OTHER"] += 1
    return counts


def _safe_text(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _verification_summary(inspected: dict[str, Any], verified: dict[str, Any]) -> dict[str, Any]:
    checks = verified.get("checks", [])
    counts = _status_counts(checks)
    return {
        "file": inspected.get("file"),
        "classification": inspected.get("classification"),
        "tisci_request_semantics": inspected.get("tisci_request_semantics"),
        "file_size": inspected.get("file_size"),
        "file_sha256": inspected.get("file_sha256"),
        "certificate_size": inspected.get("certificate_size"),
        "certificate_sha256": inspected.get("certificate_sha256"),
        "appended_size": inspected.get("appended_size"),
        "signature_algorithm_oid": inspected.get("signature_algorithm_oid"),
        "signature_hash_algorithm": inspected.get("signature_hash_algorithm"),
        "spki_sha256": inspected.get("spki_sha256"),
        "overall_host_side_verification": verified.get("overall_host_side_verification"),
        "check_counts": counts,
        "checks": checks,
        "verification_scope": verified.get("verification_scope"),
        "note": verified.get("note"),
    }


def image_report_data(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    inspected = inspect_artifact(p)
    verified = verify_artifact(p)
    out = _verification_summary(inspected, verified)
    out["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    return out


def render_image_report_markdown(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Secure image doğrulama raporu — `{_safe_text(data.get('file'))}`")
    lines.append("")
    lines.append("Bu rapor, dosyanın X.509 yapısını ve toolkit tarafından desteklenen host-side doğrulamaları özetler.")
    lines.append("")
    lines.append("## Dosya özeti")
    lines.append("")
    lines.append("| Alan | Değer |")
    lines.append("|---|---|")
    for key, label in [
        ("classification", "Tür"),
        ("tisci_request_semantics", "TISCI kullanım biçimi"),
        ("file_size", "Dosya boyutu (byte)"),
        ("file_sha256", "Dosya SHA-256"),
        ("certificate_size", "X.509 certificate boyutu (byte)"),
        ("certificate_sha256", "Certificate SHA-256"),
        ("appended_size", "Certificate sonrasındaki veri (byte)"),
        ("signature_hash_algorithm", "Certificate signature hash"),
        ("spki_sha256", "DER-SPKI SHA-256"),
    ]:
        lines.append(f"| {label} | `{_safe_text(data.get(key))}` |")

    overall = data.get("overall_host_side_verification", "NOT_CHECKED")
    counts = data.get("check_counts", {})
    lines.extend([
        "",
        "## Sonuç",
        "",
        f"**Host-side doğrulama sonucu:** `{overall}`",
        "",
        f"Kontroller: `{counts.get('PASS', 0)} PASS`, `{counts.get('FAIL', 0)} FAIL`, "
        f"`{counts.get('NOT_CHECKED', 0)} NOT_CHECKED`.",
        "",
        "## Kontroller",
        "",
        "| Kontrol | Durum | Açıklama |",
        "|---|---|---|",
    ])
    for check in data.get("checks", []):
        detail = check.get("reason") or check.get("trust_note") or ""
        if not detail:
            pairs = []
            for left, right in [("declared", "actual"), ("expected", "actual"), ("declared_component_sum", "actual_appended")]:
                if left in check or right in check:
                    pairs.append(f"{left}={_safe_text(check.get(left))}, {right}={_safe_text(check.get(right))}")
                    break
            detail = "; ".join(pairs)
        lines.append(
            f"| `{_safe_text(check.get('check'))}` | `{_safe_text(check.get('status'))}` | {_safe_text(detail)} |"
        )

    lines.extend([
        "",
        "## Sınır",
        "",
        "Bu rapor host-side dosya yapısı, certificate signature tutarlılığı ve ilgili integrity kontrollerini değerlendirir. "
        "Customer Root of Trust provisioning, HS-SE enforcement, OTP/eFuse durumu veya hedef cihazın image'ı kabul edeceği sonucunu tek başına kanıtlamaz.",
        "",
    ])
    return "\n".join(lines)


def write_image_report(
    image: str | Path,
    output: str | Path,
    *,
    json_output: str | Path | None = None,
) -> dict[str, Any]:
    out_path = Path(output)
    if out_path.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {out_path}")
    if json_output is not None and Path(json_output).exists():
        raise FileExistsError(f"çıktı zaten mevcut: {json_output}")

    data = image_report_data(image)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_image_report_markdown(data), encoding="utf-8")
    if json_output is not None:
        jp = Path(json_output)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    outputs = [{"type": "markdown_report", "path": str(out_path)}]
    if json_output is not None:
        outputs.append({"type": "json_report", "path": str(json_output)})
    return {
        "status": data["overall_host_side_verification"],
        "operation": "image_report",
        "summary": "Host-side image report üretildi.",
        "image": Path(image).name,
        "report": str(out_path),
        "json": str(json_output) if json_output is not None else None,
        "file_sha256": data["file_sha256"],
        "classification": data["classification"],
        "outputs": outputs,
    }


def batch_report_data(inputs: Iterable[str | Path]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for item in inputs:
        p = Path(item)
        try:
            data = image_report_data(p)
            items.append({"file": p.name, "status": data["overall_host_side_verification"], "data": data})
        except Exception as exc:
            items.append({
                "file": p.name,
                "status": "ERROR",
                "error": f"{type(exc).__name__}: secure image/certificate okunamadı",
            })

    statuses = [x["status"] for x in items]
    if "ERROR" in statuses or "FAIL" in statuses:
        overall = "FAIL"
    elif any(x in {"PARTIAL", "NOT_CHECKED"} for x in statuses):
        overall = "PARTIAL"
    else:
        overall = "PASS" if items else "NOT_CHECKED"

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall,
        "item_count": len(items),
        "items": items,
        "note": "Toplu rapor yalnız açıkça verilen dosyaları okur; dizin taraması yapmaz.",
    }


def render_batch_report_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# Secure image toplu doğrulama özeti",
        "",
        f"**Genel sonuç:** `{data.get('overall_status')}`",
        "",
        "| Dosya | Tür | Sonuç | PASS | FAIL | NOT_CHECKED |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for item in data.get("items", []):
        if "data" not in item:
            lines.append(f"| `{item['file']}` | okunamadı | `ERROR` | - | - | - |")
            continue
        d = item["data"]
        c = d.get("check_counts", {})
        lines.append(
            f"| `{_safe_text(d.get('file'))}` | {_safe_text(d.get('classification'))} | "
            f"`{_safe_text(item.get('status'))}` | {c.get('PASS', 0)} | {c.get('FAIL', 0)} | {c.get('NOT_CHECKED', 0)} |"
        )

    errors = [x for x in data.get("items", []) if "error" in x]
    if errors:
        lines.extend(["", "## Okunamayan dosyalar", ""])
        for item in errors:
            lines.append(f"- `{item['file']}`: {_safe_text(item['error'])}")

    lines.extend([
        "",
        "## Not",
        "",
        "Toplu sonuç, her dosya için yapılan host-side kontrollerin özetidir. Hardware/customer enforcement sonucu değildir.",
        "",
    ])
    return "\n".join(lines)


def write_batch_report(
    inputs: Iterable[str | Path],
    output: str | Path,
    *,
    json_output: str | Path | None = None,
) -> dict[str, Any]:
    out_path = Path(output)
    if out_path.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {out_path}")
    if json_output is not None and Path(json_output).exists():
        raise FileExistsError(f"çıktı zaten mevcut: {json_output}")

    data = batch_report_data(inputs)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_batch_report_markdown(data), encoding="utf-8")
    if json_output is not None:
        jp = Path(json_output)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    outputs = [{"type": "markdown_batch_report", "path": str(out_path)}]
    if json_output is not None:
        outputs.append({"type": "json_batch_report", "path": str(json_output)})
    return {
        "status": data["overall_status"],
        "operation": "batch_report",
        "summary": "Toplu host-side report üretildi.",
        "item_count": data["item_count"],
        "report": str(out_path),
        "json": str(json_output) if json_output is not None else None,
        "outputs": outputs,
    }
