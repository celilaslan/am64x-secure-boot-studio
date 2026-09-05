from __future__ import annotations

import json
from pathlib import Path

from am64x_secure_toolkit.build import build_app, build_rom


def _write_fake_tool(path: Path, kind: str) -> None:
    if kind == "app":
        body = r'''
import argparse
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--bin', required=True)
p.add_argument('--authtype', required=True)
p.add_argument('--key', required=True)
p.add_argument('--enc')
p.add_argument('--enckey')
p.add_argument('--output', required=True)
a=p.parse_args()
print('key=' + a.key)
if a.enckey: print('enckey=' + a.enckey)
Path(a.output).write_bytes(b'APP:' + Path(a.bin).read_bytes())
'''
    else:
        body = r'''
import argparse
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--swrv', required=True)
p.add_argument('--sbl-bin', required=True)
p.add_argument('--sysfw-bin', required=True)
p.add_argument('--sysfw-inner-cert')
p.add_argument('--boardcfg-blob', required=True)
p.add_argument('--sbl-loadaddr', required=True)
p.add_argument('--sysfw-loadaddr', required=True)
p.add_argument('--bcfg-loadaddr', required=True)
p.add_argument('--key', required=True)
p.add_argument('--debug')
p.add_argument('--sbl-enc', action='store_true')
p.add_argument('--enc-key')
p.add_argument('--rom-image', required=True)
a=p.parse_args()
print('key=' + a.key)
if a.enc_key: print('enc=' + a.enc_key)
parts=[Path(a.sbl_bin).read_bytes(),Path(a.sysfw_bin).read_bytes()]
if a.sysfw_inner_cert: parts.append(Path(a.sysfw_inner_cert).read_bytes())
parts.append(Path(a.boardcfg_blob).read_bytes())
Path(a.rom_image).write_bytes(b'ROM:' + b''.join(parts))
'''
    path.write_text(body, encoding="utf-8")


def test_build_app_encrypted_redacts_secrets_and_attests(tmp_path: Path):
    tool = tmp_path / "fake_app.py"
    _write_fake_tool(tool, "app")
    inp = tmp_path / "app.mcelf"; inp.write_bytes(b"payload")
    key = tmp_path / "private signing key.pem"; key.write_text("secret")
    mek = tmp_path / "mek.txt"; mek.write_text("00" * 32)
    out = tmp_path / "app.hs"

    result = build_app(
        signing_tool=tool,
        input_image=inp,
        signing_key=key,
        encryption_key=mek,
        output=out,
    )
    assert result["exit_code"] == 0
    assert out.read_bytes() == b"APP:payload"

    record_path = Path(str(out) + ".build-record.json")
    log_path = Path(str(out) + ".build.log")
    record_text = record_path.read_text()
    log_text = log_path.read_text()
    assert str(key) not in record_text
    assert str(mek) not in record_text
    assert str(key) not in log_text
    assert str(mek) not in log_text
    assert "<REDACTED_SECRET_PATH>" in record_text
    assert "<REDACTED_SECRET_PATH>" in log_text

    record = json.loads(record_text)
    assert record["operation"] == "build_app_encrypted_signed"
    assert record["secret_inputs"][0]["sha256"] == "NOT_RECORDED"
    assert record["secret_inputs"][1]["sha256"] == "NOT_RECORDED"
    assert record["result"]["output"]["sha256"]
    assert record["inputs"][0]["role"] == "application_input"


def test_build_rom_full_chain_and_secret_redaction(tmp_path: Path):
    tool = tmp_path / "fake_rom.py"
    _write_fake_tool(tool, "rom")
    sbl = tmp_path / "sbl.bin"; sbl.write_bytes(b"SBL")
    sysfw = tmp_path / "sysfw.bin"; sysfw.write_bytes(b"FW")
    inner = tmp_path / "inner.cert"; inner.write_bytes(b"INNER")
    bcfg = tmp_path / "bcfg.bin"; bcfg.write_bytes(b"BCFG")
    key = tmp_path / "romkey.pem"; key.write_text("private")
    mek = tmp_path / "rommek.txt"; mek.write_text("11" * 32)
    out = tmp_path / "tiboot3.bin"

    result = build_rom(
        signing_tool=tool,
        sbl_bin=sbl,
        sysfw_bin=sysfw,
        sysfw_inner_cert=inner,
        boardcfg_blob=bcfg,
        sbl_loadaddr="0x70000000",
        sysfw_loadaddr="0x44000",
        bcfg_loadaddr="0x70000",
        swrv=1,
        signing_key=key,
        sbl_encryption_key=mek,
        debug="DBG_FULL_ENABLE",
        output=out,
    )
    assert result["exit_code"] == 0
    assert out.read_bytes() == b"ROM:SBLFWINNERBCFG"
    record_text = Path(str(out) + ".build-record.json").read_text()
    assert str(key) not in record_text
    assert str(mek) not in record_text
    record = json.loads(record_text)
    roles = {x["role"] for x in record["inputs"]}
    assert roles == {"sbl_binary", "sysfw_binary", "sysfw_inner_certificate", "boardcfg_blob"}
    assert record["operation"] == "build_rom_combined_sbl_encrypted"


def test_dry_run_creates_no_output_and_records_not_executed(tmp_path: Path):
    tool = tmp_path / "fake_app.py"
    _write_fake_tool(tool, "app")
    inp = tmp_path / "in.bin"; inp.write_bytes(b"abc")
    key = tmp_path / "k.pem"; key.write_text("secret")
    out = tmp_path / "out.hs"

    result = build_app(
        signing_tool=tool,
        input_image=inp,
        signing_key=key,
        output=out,
        dry_run=True,
    )
    assert result["execution_state"] == "DRY_RUN_NOT_EXECUTED"
    assert not out.exists()
    record = json.loads(Path(str(out) + ".build-record.json").read_text())
    assert record["execution_state"] == "DRY_RUN_NOT_EXECUTED"
    assert record["result"]["exit_code"] is None
    assert record["result"]["output"]["exists"] is False


def test_existing_output_is_refused(tmp_path: Path):
    tool = tmp_path / "fake_app.py"
    _write_fake_tool(tool, "app")
    inp = tmp_path / "in.bin"; inp.write_bytes(b"abc")
    key = tmp_path / "k.pem"; key.write_text("secret")
    out = tmp_path / "out.hs"; out.write_bytes(b"STALE")
    import pytest
    with pytest.raises(FileExistsError):
        build_app(signing_tool=tool, input_image=inp, signing_key=key, output=out)
    assert out.read_bytes() == b"STALE"


def test_post_verify_failure_changes_overall_result(tmp_path: Path):
    tool = tmp_path / "fake_app.py"
    _write_fake_tool(tool, "app")
    inp = tmp_path / "in.bin"; inp.write_bytes(b"abc")
    key = tmp_path / "k.pem"; key.write_text("secret")
    out = tmp_path / "out.hs"
    result = build_app(
        signing_tool=tool,
        input_image=inp,
        signing_key=key,
        output=out,
        post_verify=True,
    )
    assert result["exit_code"] == 0
    assert result["post_verify"] == "ERROR"
    assert result["overall_result"] == "FAIL"
