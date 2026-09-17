import hashlib
import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from am64x_secure_toolkit.constants import TI_OIDS
from am64x_secure_toolkit.reporting import (
    batch_report_data,
    image_report_data,
    render_batch_report_markdown,
    render_image_report_markdown,
    write_batch_report,
    write_image_report,
)
from am64x_secure_toolkit.x509ext import SysfwImageIntegrity, SysfwImageLoad


def _signed_data(tmp_path, name="data.secure"):
    payload = b"report-data" * 4
    integ = SysfwImageIntegrity({
        "shaType": "2.16.840.1.101.3.4.2.3",
        "shaValue": hashlib.sha512(payload).digest(),
        "imageSize": len(payload),
    }).dump()
    load = SysfwImageLoad({
        "destAddr": bytes.fromhex("0000000000000000"),
        "authType": 1,
    }).dump()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "report-test")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.UnrecognizedExtension(ObjectIdentifier(TI_OIDS["sysfw_image_integrity"]), integ), critical=False)
        .add_extension(x509.UnrecognizedExtension(ObjectIdentifier(TI_OIDS["sysfw_image_load"]), load), critical=False)
    )
    cert = builder.sign(key, hashes.SHA512()).public_bytes(serialization.Encoding.DER)
    p = tmp_path / name
    p.write_bytes(cert + payload)
    return p


def test_image_report_data_and_markdown(tmp_path):
    image = _signed_data(tmp_path)
    data = image_report_data(image)
    assert data["overall_host_side_verification"] == "PASS"
    assert data["classification"] == "signed application/generic data"
    text = render_image_report_markdown(data)
    assert "Secure image doğrulama raporu" in text
    assert "Host-side doğrulama sonucu" in text
    assert "Customer Root of Trust" in text


def test_write_image_report_creates_markdown_and_json(tmp_path):
    image = _signed_data(tmp_path)
    md = tmp_path / "report.md"
    js = tmp_path / "report.json"
    out = write_image_report(image, md, json_output=js)
    assert out["status"] == "PASS"
    assert md.exists() and js.exists()
    parsed = json.loads(js.read_text(encoding="utf-8"))
    assert parsed["file_sha256"] == hashlib.sha256(image.read_bytes()).hexdigest()


def test_batch_report_explicit_inputs_and_error(tmp_path):
    good = _signed_data(tmp_path, "good.secure")
    bad = tmp_path / "not-a-certificate.bin"
    bad.write_bytes(b"plain-data")
    data = batch_report_data([good, bad])
    assert data["item_count"] == 2
    assert data["overall_status"] == "FAIL"
    assert data["items"][0]["status"] == "PASS"
    assert data["items"][1]["status"] == "ERROR"
    text = render_batch_report_markdown(data)
    assert "toplu doğrulama özeti" in text
    assert "Okunamayan dosyalar" in text


def test_write_batch_report(tmp_path):
    a = _signed_data(tmp_path, "a.secure")
    b = _signed_data(tmp_path, "b.secure")
    md = tmp_path / "batch.md"
    js = tmp_path / "batch.json"
    out = write_batch_report([a, b], md, json_output=js)
    assert out["status"] == "PASS"
    assert out["item_count"] == 2
    assert md.exists() and js.exists()
