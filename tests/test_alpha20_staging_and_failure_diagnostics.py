from __future__ import annotations

import json
from pathlib import Path

from am64x_secure_toolkit.build import build_app


def _write_shell_fragile_fake_signer(path: Path) -> None:
    path.write_text(
        r'''
import argparse
import subprocess
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--bin', required=True)
p.add_argument('--authtype', required=True)
p.add_argument('--key', required=True)
p.add_argument('--enc')
p.add_argument('--enckey')
p.add_argument('--output', required=True)
a=p.parse_args()
assert Path(a.key).is_file()
if a.enckey:
    assert Path(a.enckey).is_file()
# Intentionally shell-fragile: no quoting around input/output. This simulates the
# upstream TI signer pattern that breaks if user paths with spaces are passed through.
rc = subprocess.run(f"cat {a.bin} > {a.output}", shell=True).returncode
raise SystemExit(rc)
''',
        encoding='utf-8',
    )


def _write_failing_secret_echo_signer(path: Path) -> None:
    path.write_text(
        r'''
import argparse
import sys
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--bin', required=True)
p.add_argument('--authtype', required=True)
p.add_argument('--key', required=True)
p.add_argument('--enc')
p.add_argument('--enckey')
p.add_argument('--output', required=True)
a=p.parse_args()
mek = Path(a.enckey).read_text().strip() if a.enckey else ''
print('OpenSSL command failed while processing ' + a.bin, file=sys.stderr)
print('MEK=' + mek, file=sys.stderr)
print('key_alias=' + a.key, file=sys.stderr)
raise SystemExit(7)
''',
        encoding='utf-8',
    )


def test_application_build_uses_relative_staging_aliases_for_space_paths(tmp_path: Path):
    root = tmp_path / 'Celil Aslan workspace'
    root.mkdir()
    tool = root / 'fake TI signer.py'
    _write_shell_fragile_fake_signer(tool)
    inp = root / 'hello world.mcelf'; inp.write_bytes(b'payload')
    key = root / 'private signing key.pem'; key.write_text('private', encoding='utf-8')
    mek = root / 'application mek.txt'; mek.write_text('ab' * 32, encoding='ascii')
    out = root / 'outputs with spaces' / 'encrypted secure application'

    result = build_app(
        signing_tool=tool,
        input_image=inp,
        signing_key=key,
        encryption_key=mek,
        output=out,
    )

    assert result['exit_code'] == 0
    assert result['overall_result'] == 'PASS'
    assert out.read_bytes() == b'payload'
    assert result['staging']['used'] is True
    assert result['staging']['relative_aliases'] is True
    assert result['staging']['secret_copy_fallback'] is False
    assert result['staging']['signing_key_alias'] in {'hardlink', 'symlink'}
    assert result['staging']['encryption_key_alias'] in {'hardlink', 'symlink'}
    assert result['staging']['cleaned'] is True
    assert not list(out.parent.glob('.am64x-studio-*'))

    record = json.loads(Path(str(out) + '.build-record.json').read_text(encoding='utf-8'))
    cmd = record['command']['argv']
    assert 'application_input.mcelf' in cmd
    assert '<REDACTED_SECRET_PATH>' in cmd
    assert str(inp) not in ' '.join(cmd)
    assert str(key) not in json.dumps(record)
    assert str(mek) not in json.dumps(record)


def test_failure_excerpt_is_bounded_redacted_and_not_persisted(tmp_path: Path):
    root = tmp_path / 'space path'
    root.mkdir()
    tool = root / 'fail signer.py'; _write_failing_secret_echo_signer(tool)
    inp = root / 'app.mcelf'; inp.write_bytes(b'payload')
    key = root / 'private key.pem'; key.write_text('private', encoding='utf-8')
    mek_value = 'cd' * 32
    mek = root / 'mek secret.txt'; mek.write_text(mek_value, encoding='ascii')
    out = root / 'out image'

    result = build_app(
        signing_tool=tool,
        input_image=inp,
        signing_key=key,
        encryption_key=mek,
        output=out,
    )

    assert result['exit_code'] == 7
    assert result['overall_result'] == 'FAIL'
    assert result['output_created'] is False
    assert result['failure_excerpt_source'] == 'stderr'
    excerpt = result['failure_excerpt']
    assert 'OpenSSL command failed' in excerpt
    assert mek_value not in excerpt
    assert '<REDACTED_SECRET_PATH>' in excerpt
    assert result['failure_excerpt_persisted'] is False
    assert result['staging']['cleaned'] is True

    log_text = Path(str(out) + '.build.log').read_text(encoding='utf-8')
    record_text = Path(str(out) + '.build-record.json').read_text(encoding='utf-8')
    assert mek_value not in log_text
    assert mek_value not in record_text
    assert 'OpenSSL command failed' not in log_text
    assert 'OpenSSL command failed' not in record_text
    assert 'FAILURE_EXCERPT_PERSISTED=NO' in log_text
    assert 'STDOUT_SHA256=' not in log_text
    assert 'STDERR_SHA256=' not in log_text
    assert 'STREAM_HASHES_RECORDED=NO' in log_text
