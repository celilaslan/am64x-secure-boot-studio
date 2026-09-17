"""Kurulu TI SDK secure-image araçlarını kontrollü biçimde çalıştırır.

TI certificate üretim mantığı yeniden yazılmaz. Seçilen SDK aracının komutu hazırlanır,
secret yolları kayıtlardan çıkarılır ve build sonucu için izlenebilir bir JSON kayıt üretilir.

Application build'lerinde upstream TI signer'ın shell tabanlı alt-komutlarında boşluk içeren
host path'lerinin kırılmasını önlemek için gerçek execution, kullanıcı dosyalarını kopyalamadan
oluşturulan kısa relative alias'ların bulunduğu izole bir staging directory içinde yapılır.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .build_record import make_build_record, normalize_path, redact_argv, redact_text, write_json
from .verify import verify_artifact

_FAILURE_EXCERPT_MAX_CHARS = 3000
_FAILURE_EXCERPT_MAX_LINES = 28


def _require_file(path: str | Path, role: str) -> Path:
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"{role} bulunamadı: {normalize_path(p)}")
    return p.resolve()


def _prepare_output(path: str | Path) -> Path:
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        raise FileExistsError(
            f"output zaten mevcut; yanlış/stale çıktı kullanımını önlemek için üzerine yazılmadı: {normalize_path(p)}"
        )
    return p


def _create_noncopying_alias(source: Path, target: Path, *, secret: bool) -> str:
    """Create a same-content alias without copying secret material.

    Hardlink is preferred because it works without elevated symlink privileges on common
    Linux/Windows filesystems when source and staging share a filesystem. Symlink is the
    fallback. Non-secret inputs may be copied only if both alias methods are unavailable.
    Secret inputs are never copied as a fallback.
    """
    try:
        os.link(source, target)
        return "hardlink"
    except OSError:
        pass
    try:
        os.symlink(source, target)
        return "symlink"
    except OSError as exc:
        if secret:
            raise RuntimeError(
                "Secret input için kopyasız staging alias oluşturulamadı. "
                "Studio secret dosyayı geçici klasöre kopyalamaz; output ile key'in aynı filesystem/volume üzerinde "
                "olduğunu veya symlink desteğini kontrol edin."
            ) from exc
        shutil.copy2(source, target)
        return "copy_non_secret"


def _publish_staged_output(staged: Path, final: Path) -> None:
    """Publish a generated artifact without silently overwriting an existing destination."""
    if not staged.is_file():
        raise FileNotFoundError("TI signing tool başarılı döndü ancak staged output oluşturulmadı")
    if final.exists():
        raise FileExistsError(
            f"output publish sırasında mevcut hale geldi; üzerine yazılmadı: {normalize_path(final)}"
        )

    # O_EXCL keeps the no-overwrite rule even if another process creates the path after
    # the initial preflight. The generated artifact is not secret key material.
    fd = os.open(final, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as dst, staged.open("rb") as src:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
    except Exception:
        try:
            final.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def _safe_failure_excerpt(
    *,
    stdout: str,
    stderr: str,
    signing_key: Path,
    encryption_key: Path | None,
) -> tuple[str | None, str | None]:
    """Return a bounded in-memory diagnostic excerpt with known secrets redacted.

    The excerpt is intentionally not persisted to the build log/build record. stderr is
    preferred because OpenSSL/TI signer failures normally report there; stdout is used only
    when stderr is empty.
    """
    source = "stderr" if stderr.strip() else ("stdout" if stdout.strip() else None)
    if source is None:
        return None, None
    text = stderr if source == "stderr" else stdout

    redaction_values: list[str | Path] = [signing_key]
    if encryption_key is not None:
        redaction_values.append(encryption_key)
        # TI's signer may embed the MEK text into an OpenSSL `-K` command. Read only the
        # short text key locally for exact redaction; the value is never returned or stored.
        try:
            mek_text = encryption_key.read_text(encoding="ascii").strip()
            if 0 < len(mek_text) <= 512:
                redaction_values.append(mek_text)
        except Exception:
            pass

    cleaned = redact_text(text, redaction_values)
    # Defense in depth: if an upstream exception ever dumps PEM content, remove it.
    cleaned = re.sub(
        r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?-----END [^-\n]*PRIVATE KEY-----",
        "<REDACTED_PRIVATE_KEY_MATERIAL>",
        cleaned,
        flags=re.DOTALL,
    )
    lines = [line.rstrip() for line in cleaned.splitlines() if line.strip()]
    if len(lines) > _FAILURE_EXCERPT_MAX_LINES:
        lines = lines[-_FAILURE_EXCERPT_MAX_LINES:]
    excerpt = "\n".join(lines)
    if len(excerpt) > _FAILURE_EXCERPT_MAX_CHARS:
        excerpt = "…" + excerpt[-(_FAILURE_EXCERPT_MAX_CHARS - 1):]
    return excerpt or None, source


def _run(
    *,
    operation: str,
    argv: list[str],
    cwd: Path,
    signing_tool: Path,
    non_secret_inputs: list[tuple[str, Path]],
    signing_key: Path,
    encryption_key: Path | None,
    output: Path,
    execution_output: Path | None,
    build_record: Path,
    log: Path,
    dry_run: bool,
    post_verify: bool,
) -> dict[str, Any]:
    secret_values = [signing_key]
    if encryption_key is not None:
        secret_values.append(encryption_key)

    if dry_run:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(
            "DRY-RUN / NOT EXECUTED\n"
            + "COMMAND=" + redact_text(" ".join(redact_argv(argv))) + "\n",
            encoding="utf-8",
        )
        record = make_build_record(
            operation=operation,
            argv=argv,
            working_directory=cwd,
            signing_tool=signing_tool,
            non_secret_inputs=[(r, p) for r, p in non_secret_inputs],
            signing_key_supplied=True,
            encryption_key_supplied=encryption_key is not None,
            exit_code=None,
            execution_state="DRY_RUN_NOT_EXECUTED",
            output_path=output,
            log_path=log,
            duration_ms=None,
            stream_meta=None,
            post_verify=None,
            overall_result=None,
        )
        write_json(build_record, record)
        return {
            "operation": operation,
            "execution_state": "DRY_RUN_NOT_EXECUTED",
            "exit_code": None,
            "output": normalize_path(output),
            "output_created": output.is_file(),
            "build_record": normalize_path(build_record),
            "redacted_log": normalize_path(log),
            "command_redacted": redact_argv(argv),
        }

    start = time.monotonic()
    proc = subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    duration_ms = round((time.monotonic() - start) * 1000)

    stdout_text = proc.stdout or ""
    stderr_text = proc.stderr or ""
    stdout_bytes = stdout_text.encode("utf-8", errors="replace")
    stderr_bytes = stderr_text.encode("utf-8", errors="replace")

    # Stream bodies are never persisted. We keep byte counts only; stream hashes were
    # deliberately removed because an upstream tool could unexpectedly echo secret material.
    stream_meta = {
        "content_recorded": False,
        "hashes_recorded": False,
        "stdout_bytes": len(stdout_bytes),
        "stderr_bytes": len(stderr_bytes),
    }

    failure_excerpt, failure_excerpt_source = (None, None)
    if proc.returncode != 0:
        failure_excerpt, failure_excerpt_source = _safe_failure_excerpt(
            stdout=stdout_text,
            stderr=stderr_text,
            signing_key=signing_key,
            encryption_key=encryption_key,
        )

    wrapper_error: str | None = None
    if proc.returncode == 0:
        try:
            if execution_output is not None and execution_output.resolve() != output.resolve():
                _publish_staged_output(execution_output, output)
            elif not output.is_file():
                raise FileNotFoundError("TI signing tool exit 0 döndü ancak output oluşturulmadı")
        except Exception as exc:
            wrapper_error = redact_text(f"{type(exc).__name__}: {exc}", secret_values)

    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(
        "COMMAND=" + redact_text(" ".join(redact_argv(argv))) + "\n"
        + f"WORKING_DIRECTORY={normalize_path(cwd)}\n"
        + f"EXIT_CODE={proc.returncode}\n"
        + "STREAM_CONTENT_RECORDED=NO\n"
        + "STREAM_HASHES_RECORDED=NO\n"
        + f"STDOUT_BYTES={stream_meta['stdout_bytes']}\n"
        + f"STDERR_BYTES={stream_meta['stderr_bytes']}\n"
        + "FAILURE_EXCERPT_PERSISTED=NO\n",
        encoding="utf-8",
    )

    verify_result = None
    if post_verify and proc.returncode == 0 and wrapper_error is None and output.is_file():
        try:
            verify_result = verify_artifact(output)
        except Exception as exc:
            verify_result = {
                "overall_host_side_verification": "ERROR",
                "error": f"{type(exc).__name__}: {redact_text(str(exc), secret_values)}",
            }

    if proc.returncode != 0 or wrapper_error is not None:
        overall_result = "FAIL"
    elif post_verify:
        verify_status = None if verify_result is None else verify_result.get("overall_host_side_verification")
        if verify_status == "PASS":
            overall_result = "PASS"
        elif verify_status in {"PARTIAL", "NOT_CHECKED"}:
            overall_result = "PARTIAL"
        else:
            overall_result = "FAIL"
    else:
        overall_result = "PASS"

    record = make_build_record(
        operation=operation,
        argv=argv,
        working_directory=cwd,
        signing_tool=signing_tool,
        non_secret_inputs=[(r, p) for r, p in non_secret_inputs],
        signing_key_supplied=True,
        encryption_key_supplied=encryption_key is not None,
        exit_code=proc.returncode,
        execution_state="EXECUTED",
        output_path=output,
        log_path=log,
        duration_ms=duration_ms,
        stream_meta=stream_meta,
        post_verify=verify_result,
        overall_result=overall_result,
    )
    write_json(build_record, record)

    result: dict[str, Any] = {
        "operation": operation,
        "execution_state": "EXECUTED",
        "exit_code": proc.returncode,
        "output": normalize_path(output),
        "output_created": output.is_file(),
        "build_record": normalize_path(build_record),
        "redacted_log": normalize_path(log),
        "post_verify": None if verify_result is None else verify_result.get("overall_host_side_verification"),
        "overall_result": overall_result,
    }
    if failure_excerpt is not None:
        result["failure_excerpt"] = failure_excerpt
        result["failure_excerpt_source"] = failure_excerpt_source
        result["failure_excerpt_persisted"] = False
    if wrapper_error is not None:
        result["wrapper_error"] = wrapper_error
    return result


def build_app(
    *,
    signing_tool: str | Path,
    input_image: str | Path,
    signing_key: str | Path,
    output: str | Path,
    encryption_key: str | Path | None = None,
    authtype: int = 1,
    python_executable: str | Path | None = None,
    working_directory: str | Path | None = None,
    build_record: str | Path | None = None,
    log: str | Path | None = None,
    dry_run: bool = False,
    post_verify: bool = False,
) -> dict[str, Any]:
    tool = _require_file(signing_tool, "application signing tool")
    inp = _require_file(input_image, "application input")
    key = _require_file(signing_key, "signing key")
    enckey = _require_file(encryption_key, "encryption key") if encryption_key is not None else None
    out = _prepare_output(output)
    py = str(Path(python_executable).expanduser().resolve()) if python_executable else sys.executable

    record_path = Path(build_record).expanduser().resolve() if build_record else Path(str(out) + ".build-record.json")
    lg = Path(log).expanduser().resolve() if log else Path(str(out) + ".build.log")

    # Dry-run does not execute the upstream shell-based signer, so staging is unnecessary.
    if dry_run:
        cwd = Path(working_directory).expanduser().resolve() if working_directory else tool.parent
        if not cwd.is_dir():
            raise FileNotFoundError(f"working directory bulunamadı: {normalize_path(cwd)}")
        argv = [
            py, str(tool), "--bin", str(inp), "--authtype", str(authtype), "--key", str(key),
        ]
        if enckey is not None:
            argv += ["--enc", "y", "--enckey", str(enckey)]
        argv += ["--output", str(out)]
        return _run(
            operation="build_app_encrypted_signed" if enckey is not None else "build_app_signed",
            argv=argv,
            cwd=cwd,
            signing_tool=tool,
            non_secret_inputs=[("application_input", inp)],
            signing_key=key,
            encryption_key=enckey,
            output=out,
            execution_output=None,
            build_record=record_path,
            log=lg,
            dry_run=True,
            post_verify=False,
        )

    stage_parent = Path(working_directory).expanduser().resolve() if working_directory else out.parent
    if not stage_parent.is_dir():
        raise FileNotFoundError(f"working directory bulunamadı: {normalize_path(stage_parent)}")
    stage = Path(tempfile.mkdtemp(prefix=".am64x-studio-", dir=stage_parent))
    stage_meta: dict[str, Any] = {
        "used": True,
        "relative_aliases": True,
        "secret_copy_fallback": False,
        "cleaned": False,
    }
    result: dict[str, Any] | None = None
    try:
        inp_alias = stage / "application_input.mcelf"
        key_alias = stage / "signing_key.pem"
        mek_alias = stage / "encryption_key.txt" if enckey is not None else None
        staged_out = stage / "generated_output.bin"

        stage_meta["application_input_alias"] = _create_noncopying_alias(inp, inp_alias, secret=False)
        stage_meta["signing_key_alias"] = _create_noncopying_alias(key, key_alias, secret=True)
        if enckey is not None and mek_alias is not None:
            stage_meta["encryption_key_alias"] = _create_noncopying_alias(enckey, mek_alias, secret=True)

        # The TI script receives only short relative filenames. Its own shell=True OpenSSL
        # calls therefore never see user paths such as '<HOME>/.../Celil Aslan/...'.
        argv = [
            py,
            str(tool),
            "--bin", inp_alias.name,
            "--authtype", str(authtype),
            "--key", key_alias.name,
        ]
        if enckey is not None and mek_alias is not None:
            argv += ["--enc", "y", "--enckey", mek_alias.name]
        argv += ["--output", staged_out.name]

        result = _run(
            operation="build_app_encrypted_signed" if enckey is not None else "build_app_signed",
            argv=argv,
            cwd=stage,
            signing_tool=tool,
            non_secret_inputs=[("application_input", inp)],
            signing_key=key,
            encryption_key=enckey,
            output=out,
            execution_output=staged_out,
            build_record=record_path,
            log=lg,
            dry_run=False,
            post_verify=post_verify,
        )
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        stage_meta["cleaned"] = not stage.exists()

    assert result is not None
    result["staging"] = stage_meta
    return result


def build_rom(
    *,
    signing_tool: str | Path,
    sbl_bin: str | Path,
    sysfw_bin: str | Path,
    boardcfg_blob: str | Path,
    sbl_loadaddr: str,
    sysfw_loadaddr: str,
    bcfg_loadaddr: str,
    swrv: int,
    signing_key: str | Path,
    output: str | Path,
    sysfw_inner_cert: str | Path | None = None,
    debug: str | None = None,
    sbl_encryption_key: str | Path | None = None,
    python_executable: str | Path | None = None,
    working_directory: str | Path | None = None,
    build_record: str | Path | None = None,
    log: str | Path | None = None,
    dry_run: bool = False,
    post_verify: bool = False,
) -> dict[str, Any]:
    tool = _require_file(signing_tool, "ROM signing tool")
    sbl = _require_file(sbl_bin, "SBL binary")
    sysfw = _require_file(sysfw_bin, "SYSFW binary")
    bcfg = _require_file(boardcfg_blob, "BoardCfg blob")
    inner = _require_file(sysfw_inner_cert, "SYSFW inner certificate") if sysfw_inner_cert is not None else None
    key = _require_file(signing_key, "signing key")
    enckey = _require_file(sbl_encryption_key, "SBL encryption key") if sbl_encryption_key is not None else None
    out = _prepare_output(output)
    cwd = Path(working_directory).expanduser().resolve() if working_directory else tool.parent
    if not cwd.is_dir():
        raise FileNotFoundError(f"working directory bulunamadı: {normalize_path(cwd)}")
    py = str(Path(python_executable).expanduser().resolve()) if python_executable else sys.executable

    argv = [
        py,
        str(tool),
        "--swrv", str(swrv),
        "--sbl-bin", str(sbl),
        "--sysfw-bin", str(sysfw),
    ]
    if inner is not None:
        argv += ["--sysfw-inner-cert", str(inner)]
    argv += [
        "--boardcfg-blob", str(bcfg),
        "--sbl-loadaddr", str(sbl_loadaddr),
        "--sysfw-loadaddr", str(sysfw_loadaddr),
        "--bcfg-loadaddr", str(bcfg_loadaddr),
        "--key", str(key),
    ]
    if debug is not None:
        argv += ["--debug", debug]
    if enckey is not None:
        argv += ["--sbl-enc", "--enc-key", str(enckey)]
    argv += ["--rom-image", str(out)]

    inputs: list[tuple[str, Path]] = [
        ("sbl_binary", sbl),
        ("sysfw_binary", sysfw),
        ("boardcfg_blob", bcfg),
    ]
    if inner is not None:
        inputs.append(("sysfw_inner_certificate", inner))

    record_path = Path(build_record).expanduser().resolve() if build_record else Path(str(out) + ".build-record.json")
    lg = Path(log).expanduser().resolve() if log else Path(str(out) + ".build.log")
    return _run(
        operation="build_rom_combined_sbl_encrypted" if enckey is not None else "build_rom_combined",
        argv=argv,
        cwd=cwd,
        signing_tool=tool,
        non_secret_inputs=inputs,
        signing_key=key,
        encryption_key=enckey,
        output=out,
        execution_output=None,
        build_record=record_path,
        log=lg,
        dry_run=dry_run,
        post_verify=post_verify,
    )
