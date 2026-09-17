from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from ..certificate import SysfwIntegrity, SysfwSwrev
from ..constants import SHA512_OID, TI_OIDS
from ..keygen import generate_key_set
from ..negative import create_negative_variant
from ..verify import verify_artifact
from .claim_boundary import claims_for
from .secret_policy import sanitize_for_record


def _write_demo_artifact(root: Path, private_key_path: Path, payload: bytes) -> Path:
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 4096:
        raise ValueError("demo signing key RSA-4096 olmalıdır")
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AM64x Studio Educational Demo")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    swrev = SysfwSwrev({"swrv": 1}).dump()
    integrity = SysfwIntegrity({"shaType": SHA512_OID, "shaValue": hashlib.sha512(payload).digest(), "imageSize": len(payload)}).dump()
    builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(TI_OIDS["software_revision"]), swrev), critical=False)
    builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(TI_OIDS["sysfw_image_integrity"]), integrity), critical=False)
    cert = builder.sign(key, hashes.SHA512())
    out = root / "educational-demo.secure"
    out.write_bytes(cert.public_bytes(serialization.Encoding.DER) + payload)
    return out


def create_demo_workspace(output_dir: str | Path) -> dict[str, Any]:
    """Target-ready olmayan, host-side kavramları öğreten izole demo workspace üretir.

    Exact Load Extension değerleri uydurulmaması için eğitim artifact'ı kasıtlı olarak
    Load Extension içermez. Demo-level PASS, bu eksikliğin görünür olması + signature/hash
    ayrımının doğru gözlenmesi anlamına gelir; target-ready image anlamına gelmez.
    """
    root = Path(output_dir).expanduser().resolve()
    if root.exists() and any(root.iterdir()):
        raise FileExistsError(f"demo dizini boş değil: {root}")
    root.mkdir(parents=True, exist_ok=True)
    keys_dir = root / "keys"
    keys_dir.mkdir()
    key_result = generate_key_set(keys_dir, profile="development")
    payload = (b"AM64x Secure Boot Studio educational payload\n" * 8)[:320]
    payload_path = root / "demo-payload.bin"
    payload_path.write_bytes(payload)
    artifact = _write_demo_artifact(root, keys_dir / "app-signing-private.pem", payload)
    baseline = verify_artifact(artifact)
    neg = create_negative_variant(artifact, "payload", root / "educational-demo.neg-payload")

    def status(check_id: str) -> str | None:
        for c in baseline["checks"]:
            if c.get("check") == check_id:
                return c.get("status")
        return None

    expected = {
        "certificate_signature": status("certificate_signature_with_embedded_public_key") == "PASS",
        "payload_integrity": status("appended_payload_sha512_binding") == "PASS",
        "load_extension_intentionally_missing": status("system_firmware_load_extension_present") == "FAIL",
        "negative_payload_detected": neg.get("negative_test_result") == "PASS",
    }
    demo_status = "PASS" if all(expected.values()) else "FAIL"
    claims, non_claims = claims_for("inspect", "PASS")
    non_claims = list(dict.fromkeys(non_claims + [
        "Demo artifact target-ready application image değildir; exact Load Extension değeri bilinçli olarak uydurulmamıştır.",
        "Demo artifact TI installed signer çıktısı olduğunu kanıtlamaz.",
        "Demo MEK oluşturur ancak encrypted application hardware/decryption enforcement testi yapmaz.",
    ]))
    return sanitize_for_record({
        "status": demo_status,
        "operation": "educational_demo",
        "classification": "development/test / synthetic / non-production / unprovisioned / offline-only / NOT_TARGET_READY",
        "summary": "Signature vs payload-integrity ayrımını ve exact-source eksikliğinde target-ready claim yapılmamasını gösteren 5 dakikalık host-side demo.",
        "workspace": root.name,
        "key_generation": key_result,
        "payload": {"file": payload_path.name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
        "artifact": artifact.name,
        "expected_observations": expected,
        "baseline_verification": baseline,
        "negative_test": neg,
        "claims": claims,
        "non_claims": non_claims,
        "sources": ["TISCI-AUTH", "TISCI-X509"],
    })
