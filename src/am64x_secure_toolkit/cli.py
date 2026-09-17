from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .boardcfg import (
    check_boardcfg_profile,
    evaluate_debug_policy,
    evaluate_revision_writer,
    save_boardcfg_profile,
    template_boardcfg_profile,
)
from .build import build_app, build_rom
from .certificate import build_certificate, explain_certificate, render_openssl_config
from .errata import check_errata, list_errata
from .generic_data import (
    build_generic_data,
    save_generic_data_profile,
    template_generic_data_profile,
    validate_generic_data_profile,
    verify_generic_data,
)
from .inspect import inspect_artifact
from .keycheck import compare_key_material, preflight_mek, preflight_signing_key
from .keygen import generate_key_set, generate_mek, generate_signing_key
from .negative import create_negative_variant, run_negative_suite
from .profiles import save_profile, template_profile, validate_profile_file
from .provision import provision_preflight, save_provision_profile, template_provision_profile
from .release_scan import scan_release_tree
from .reporting import write_batch_report, write_image_report
from .revision import key_revision_matrix, simulate_key_revision, simulate_swrev, swrev_field_info
from .sdk_diff import compare_sdk_security
from .sdk_lint import lint_sdk_security
from .services.beta_readiness import beta_readiness
from .services.certificate_center import (
    add_certificate_to_library,
    certificate_metadata,
    compare_certificate_with_private_key,
    compare_certificates,
    export_certificate,
    export_public_key_der,
    list_certificate_library,
    remove_certificate_from_library,
    save_cloned_profile,
)
from .services.diagnostics import diagnostics_snapshot, write_diagnostics
from .services.environment import resolve_environment
from .services.network_policy import runtime_network_policy
from .services.project import create_project, open_project
from .verify import verify_artifact


def _emit(obj: dict, pretty: bool = True) -> None:
    print(json.dumps(obj, indent=2 if pretty else None, ensure_ascii=False, sort_keys=False))


def _tr_help(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p._positionals.title = "komutlar / girdiler"
    p._optionals.title = "seçenekler"
    for action in p._actions:
        if action.dest == "help":
            action.help = "Bu yardım metnini göster ve çık"
    return p


def _add_common_build_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--tool", required=True, type=Path, help="Kurulu SDK içindeki exact TI signing script yolu")
    p.add_argument("--python", dest="python_executable", type=Path, help="Python interpreter; verilmezse mevcut Python kullanılır")
    p.add_argument("--working-dir", type=Path, help="Çalışma dizini; verilmezse signing tool dizini kullanılır")
    p.add_argument("--build-record", type=Path, help="Build kayıt JSON dosyasının yolu")
    p.add_argument("--log", type=Path, help="Secret yolları gizlenmiş build log yolu")
    p.add_argument("--dry-run", action="store_true", help="Komutu ve girdileri kontrol et, TI tool'u çalıştırma")
    p.add_argument("--post-verify", action="store_true", help="Image üretildikten sonra bağımsız host-side verify çalıştır")
    p.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")


def main(argv: list[str] | None = None) -> int:
    parser = _tr_help(argparse.ArgumentParser(
        prog="securectl",
        description="AM64x/AM6442 Secure Boot için image, X.509 certificate ve build araçları",
    ))
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}", help="Toolkit sürümünü göster ve çık")
    sub = parser.add_subparsers(dest="command", required=True)

    _tr_help(sub.add_parser("gui", help="AM64x Secure Boot Studio masaüstü arayüzünü aç"))

    p_env = _tr_help(sub.add_parser("environment", help="MCU+ SDK ve security tool environment durumunu otomatik kontrol et"))
    p_env.add_argument("--sdk-root", type=Path, help="İsteğe bağlı MCU+ SDK root; verilmezse güvenli adaylar aranır")
    p_env.add_argument("--compact", action="store_true")

    p_project = _tr_help(sub.add_parser("project", help="Secret path saklamayan Studio project workspace işlemleri"))
    project_sub = p_project.add_subparsers(dest="project_kind", required=True)
    p_project_init = _tr_help(project_sub.add_parser("init", help="Yeni Studio workspace oluştur"))
    p_project_init.add_argument("root", type=Path)
    p_project_init.add_argument("--name", required=True)
    p_project_init.add_argument("--device", default="AM6442")
    p_project_init.add_argument("--silicon-revision", default="SR2.0")
    p_project_init.add_argument("--lifecycle", choices=["GP", "HS-FS", "HS-SE"], default="HS-FS")
    p_project_init.add_argument("--compact", action="store_true")
    p_project_open = _tr_help(project_sub.add_parser("open", help="Studio workspace metadata oku"))
    p_project_open.add_argument("root", type=Path)
    p_project_open.add_argument("--compact", action="store_true")

    p_inspect = _tr_help(sub.add_parser("inspect", help="X.509 ve secure image içeriğini değiştirmeden incele"))
    p_inspect.add_argument("image", type=Path, help="İncelenecek secure image veya DER certificate")
    p_inspect.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_verify = _tr_help(sub.add_parser("verify", help="Bağımsız host-side signature ve integrity kontrolleri"))
    p_verify.add_argument("image", type=Path, help="Doğrulanacak secure image veya certificate")
    p_verify.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_build = _tr_help(sub.add_parser("build", help="Kurulu TI SDK araçlarıyla secure image üretimi"))
    build_sub = p_build.add_subparsers(dest="build_kind", required=True)

    p_app = _tr_help(build_sub.add_parser("app", help="Signed veya encrypted+signed application image üret"))
    _add_common_build_args(p_app)
    p_app.add_argument("--input", required=True, type=Path, help="TI signer tarafından kullanılacak application/MCELF girdisi")
    p_app.add_argument("--key", required=True, type=Path, help="Signing private-key yolu; build kayıtlarına yazılmaz")
    p_app.add_argument("--enckey", type=Path, help="Application encryption-key yolu; build kayıtlarına yazılmaz")
    p_app.add_argument("--authtype", type=int, default=1, help="TI SDK application authtype değeri (varsayılan: 1)")
    p_app.add_argument("--output", required=True, type=Path, help="Üretilecek application image yolu")

    p_rom = _tr_help(build_sub.add_parser("rom", help="rom_image_gen.py ile ROM combined image üret"))
    _add_common_build_args(p_rom)
    p_rom.add_argument("--sbl-bin", required=True, type=Path)
    p_rom.add_argument("--sysfw-bin", required=True, type=Path)
    p_rom.add_argument("--sysfw-inner-cert", type=Path)
    p_rom.add_argument("--boardcfg-blob", required=True, type=Path)
    p_rom.add_argument("--sbl-loadaddr", required=True, help="Kaynak veya exact build recipe ile doğrulanmış SBL load address")
    p_rom.add_argument("--sysfw-loadaddr", required=True, help="Kaynak veya exact build recipe ile doğrulanmış SYSFW load address")
    p_rom.add_argument("--bcfg-loadaddr", required=True, help="Kaynak veya exact build recipe ile doğrulanmış BoardCfg load address")
    p_rom.add_argument("--swrv", required=True, type=int, help="Software revision; toolkit bu değeri tahmin etmez")
    p_rom.add_argument("--key", required=True, type=Path, help="Signing private-key yolu; build kayıtlarına yazılmaz")
    p_rom.add_argument("--debug", help="İsteğe bağlı exact TI debug mode; toolkit varsayılan debug policy seçmez")
    p_rom.add_argument("--sbl-enckey", type=Path, help="Bu key yolu ile --sbl-enc kullan; key yolu build kayıtlarına yazılmaz")
    p_rom.add_argument("--output", required=True, type=Path, help="Üretilecek ROM combined image yolu")

    p_cert = _tr_help(sub.add_parser("cert", help="X.509 certificate profile oluştur, doğrula, üret veya açıkla"))
    cert_sub = p_cert.add_subparsers(dest="cert_kind", required=True)

    p_cert_new = _tr_help(cert_sub.add_parser("new", help="Doldurulabilir certificate profile oluştur"))
    p_cert_new.add_argument("type", choices=["app", "debug", "rom", "keywriter"], help="Profile türü")
    p_cert_new.add_argument("--output", required=True, type=Path, help="YAML profile çıktı yolu")

    p_cert_validate = _tr_help(cert_sub.add_parser("validate", help="Certificate profile alanlarını kontrol et"))
    p_cert_validate.add_argument("profile", type=Path)
    p_cert_validate.add_argument("--compact", action="store_true")

    p_cert_render = _tr_help(cert_sub.add_parser("render", help="Application/debug profile için OpenSSL config üret"))
    p_cert_render.add_argument("profile", type=Path)
    p_cert_render.add_argument("--output", required=True, type=Path)

    p_cert_build = _tr_help(cert_sub.add_parser("build", help="Application veya Secure Debug DER certificate üret"))
    p_cert_build.add_argument("profile", type=Path)
    p_cert_build.add_argument("--key", required=True, type=Path, help="RSA-4096 private signing key; path veya içerik çıktıya kaydedilmez")
    p_cert_build.add_argument("--output", required=True, type=Path, help="DER certificate çıktı yolu")
    p_cert_build.add_argument("--package", type=Path, help="Application için DER certificate + payload çıktısı")
    p_cert_build.add_argument("--compact", action="store_true")

    p_cert_explain = _tr_help(cert_sub.add_parser("explain", help="Certificate/image içindeki önemli alanları kısa biçimde açıkla"))
    p_cert_explain.add_argument("certificate", type=Path)

    p_cert_meta = _tr_help(cert_sub.add_parser("metadata", help="Certificate Subject/Issuer/validity/fingerprint ve context metadata'sını göster"))
    p_cert_meta.add_argument("certificate", type=Path)
    p_cert_meta.add_argument("--compact", action="store_true")

    p_cert_export = _tr_help(cert_sub.add_parser("export", help="Certificate'ı DER veya PEM formatında public olarak export et"))
    p_cert_export.add_argument("certificate", type=Path)
    p_cert_export.add_argument("--format", choices=["der", "pem"], required=True)
    p_cert_export.add_argument("--output", required=True, type=Path)
    p_cert_export.add_argument("--compact", action="store_true")

    p_cert_pub = _tr_help(cert_sub.add_parser("public-key", help="Certificate içindeki public key'i DER-SPKI olarak export et"))
    p_cert_pub.add_argument("certificate", type=Path)
    p_cert_pub.add_argument("--output", required=True, type=Path)
    p_cert_pub.add_argument("--compact", action="store_true")

    p_cert_match = _tr_help(cert_sub.add_parser("match", help="Certificate public key ile private signing key'in public tarafını karşılaştır"))
    p_cert_match.add_argument("certificate", type=Path)
    p_cert_match.add_argument("--key", required=True, type=Path)
    p_cert_match.add_argument("--compact", action="store_true")

    p_cert_clone = _tr_help(cert_sub.add_parser("clone", help="Application/debug certificate alanlarından yeni reissue YAML profile oluştur"))
    p_cert_clone.add_argument("certificate", type=Path)
    p_cert_clone.add_argument("--payload", type=Path, help="Application reissue için payload yolu")
    p_cert_clone.add_argument("--output", required=True, type=Path)
    p_cert_clone.add_argument("--compact", action="store_true")

    p_cert_compare = _tr_help(cert_sub.add_parser("compare", help="İki public certificate metadata/extension farklarını karşılaştır"))
    p_cert_compare.add_argument("left", type=Path)
    p_cert_compare.add_argument("right", type=Path)
    p_cert_compare.add_argument("--compact", action="store_true")

    p_cert_library = _tr_help(cert_sub.add_parser("library", help="Project Certificate Library işlemleri"))
    p_cert_library.add_argument("action", choices=["list", "add", "remove"])
    p_cert_library.add_argument("--project", required=True, type=Path)
    p_cert_library.add_argument("--certificate", type=Path, help="add için public certificate")
    p_cert_library.add_argument("--name", help="add için Library adı")
    p_cert_library.add_argument("--relative-path", help="remove için public/certificates/... relative path")
    p_cert_library.add_argument("--compact", action="store_true")

    p_negative = _tr_help(sub.add_parser("negative", help="Kaynak dosyayı değiştirmeden kontrollü negatif test kopyaları üret"))
    negative_sub = p_negative.add_subparsers(dest="negative_kind", required=True)

    for kind, help_text in [
        ("signature", "Certificate signatureValue alanını değiştir ve beklenen doğrulama hatasını kontrol et"),
        ("tbs", "TBSCertificate serialNumber alanını değiştir ve signature kontrolünü sınar"),
        ("payload", "Signed application payload kopyasında tek byte değiştir"),
        ("ciphertext", "Encrypted application ciphertext kopyasında tek byte değiştir"),
    ]:
        pn = _tr_help(negative_sub.add_parser(kind, help=help_text))
        pn.add_argument("image", type=Path, help="Kaynak secure image; dosya değiştirilmez")
        pn.add_argument("--output", required=True, type=Path, help="Üretilecek negatif test kopyası")
        if kind in {"payload", "ciphertext"}:
            pn.add_argument("--offset", type=int, help="Certificate sonrasındaki data içinde değiştirilecek byte offset'i; verilmezse orta byte seçilir")
        pn.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_component = _tr_help(negative_sub.add_parser("component", help="ROM combined image içindeki seçili component kopyasında tek byte değiştir"))
    p_component.add_argument("image", type=Path, help="Kaynak ROM combined image; dosya değiştirilmez")
    p_component.add_argument("--component-index", required=True, type=int, help="1 tabanlı ROM component index")
    p_component.add_argument("--output", required=True, type=Path, help="Üretilecek negatif test kopyası")
    p_component.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_suite = _tr_help(negative_sub.add_parser("suite", help="Image türüne uygun negatif test setini çalıştır"))
    p_suite.add_argument("image", type=Path, help="Kaynak secure image; dosya değiştirilmez")
    p_suite.add_argument("--output-dir", required=True, type=Path, help="Test kopyaları ve JSON raporunun yazılacağı boş dizin")
    p_suite.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_key = _tr_help(sub.add_parser("key", help="Signing key ve MEK dosyalarını secret içeriği yazdırmadan kontrol et"))
    key_sub = p_key.add_subparsers(dest="key_kind", required=True)

    p_key_signing = _tr_help(key_sub.add_parser("signing", help="RSA signing key/public key/certificate yapısını ve public fingerprint'i kontrol et"))
    p_key_signing.add_argument("input", type=Path, help="Local PEM/DER key veya X.509 certificate")
    p_key_signing.add_argument("--purpose", choices=["application", "debug", "keywriter", "rom", "generic"], default="application", help="Kontrolün kullanılacağı akış")
    p_key_signing.add_argument("--public-der-output", type=Path, help="İsteğe bağlı public DER-SPKI çıktısı; private material içermez")
    p_key_signing.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_key_mek = _tr_help(key_sub.add_parser("mek", help="MEK text dosyasının AES-256 raw-hex formatını kontrol et"))
    p_key_mek.add_argument("input", type=Path, help="Local MEK text dosyası; içerik/hash çıktıya yazılmaz")
    p_key_mek.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_key_compare = _tr_help(key_sub.add_parser("compare", help="Private key'in public tarafını public key/certificate ile karşılaştır"))
    p_key_compare.add_argument("private_key", type=Path, help="Local private key; içerik/hash çıktıya yazılmaz")
    p_key_compare.add_argument("reference", type=Path, help="Public key veya X.509 certificate")
    p_key_compare.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_key_generate = _tr_help(key_sub.add_parser("generate", help="Synthetic/non-production key material üret ve otomatik preflight yap"))
    key_generate_sub = p_key_generate.add_subparsers(dest="key_generate_kind", required=True)

    p_key_gen_signing = _tr_help(key_generate_sub.add_parser("signing", help="RSA-4096 signing key pair üret"))
    p_key_gen_signing.add_argument("--role", choices=["application", "smpk", "bmpk", "debug"], default="application")
    p_key_gen_signing.add_argument("--output-dir", required=True, type=Path)
    p_key_gen_signing.add_argument("--compact", action="store_true")

    p_key_gen_mek = _tr_help(key_generate_sub.add_parser("mek", help="Strict 256-bit/64-hex synthetic MEK üret"))
    p_key_gen_mek.add_argument("--role", choices=["application", "smek", "bmek"], default="application")
    p_key_gen_mek.add_argument("--output-dir", required=True, type=Path)
    p_key_gen_mek.add_argument("--compact", action="store_true")

    p_key_gen_set = _tr_help(key_generate_sub.add_parser("set", help="Development veya offline provisioning-test key set üret"))
    p_key_gen_set.add_argument("--profile", choices=["development", "provisioning-test"], default="development")
    p_key_gen_set.add_argument("--backup", action="store_true", help="provisioning-test profilinde BMPK/BMEK de üret")
    p_key_gen_set.add_argument("--output-dir", required=True, type=Path)
    p_key_gen_set.add_argument("--compact", action="store_true")

    p_provision = _tr_help(sub.add_parser("provision", help="HS-FS -> HS-SE için yalnız offline provisioning hazırlık kontrolleri"))
    provision_sub = p_provision.add_subparsers(dest="provision_kind", required=True)

    p_provision_new = _tr_help(provision_sub.add_parser("new", help="Secret içermeyen provisioning preflight YAML şablonu oluştur"))
    p_provision_new.add_argument("--output", required=True, type=Path, help="YAML profile çıktı yolu")

    p_provision_preflight = _tr_help(provision_sub.add_parser("preflight", help="KEYCNT/KEYREV ve customer key girdilerini offline kontrol et"))
    p_provision_preflight.add_argument("profile", type=Path, help="Provisioning preflight YAML profile")
    p_provision_preflight.add_argument("--smek", type=Path, help="İsteğe bağlı local SMEK dosyası; içerik/path/hash raporlanmaz")
    p_provision_preflight.add_argument("--bmek", type=Path, help="İsteğe bağlı local BMEK dosyası; içerik/path/hash raporlanmaz")
    p_provision_preflight.add_argument("--report", type=Path, help="Secret içermeyen JSON preflight raporu")
    p_provision_preflight.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_revision = _tr_help(sub.add_parser("revision", help="KEYREV ve SWREV kurallarını target'a yazmadan offline değerlendir"))
    revision_sub = p_revision.add_subparsers(dest="revision_kind", required=True)

    p_revision_key = _tr_help(revision_sub.add_parser("key", help="KEYCNT/KEYREV kombinasyonunu ve active key context'i değerlendir"))
    p_revision_key.add_argument("--keycnt", required=True, type=int, help="Customer key-set sayısı: 0, 1 veya 2")
    p_revision_key.add_argument("--keyrev", type=int, help="Mevcut KEYREV; KEYCNT=0 için verilmez")
    p_revision_key.add_argument("--target-keyrev", type=int, help="İsteğe bağlı hedef KEYREV; yalnız mantıksal tutarlılık kontrol edilir")
    p_revision_key.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_revision_matrix = _tr_help(revision_sub.add_parser("key-matrix", help="KEYCNT/KEYREV geçerli durum tablosunu göster"))
    p_revision_matrix.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_revision_swrev = _tr_help(revision_sub.add_parser("swrev", help="Belirli certificate bağlamında SWREV karşılaştırmasını simüle et"))
    p_revision_swrev.add_argument("--context", required=True, choices=["tiboot3", "boardcfg", "debug", "application", "generic"], help="SWREV karşılaştırma bağlamı")
    p_revision_swrev.add_argument("--reference", required=True, type=int, help="eFuse SWREV veya debug min_cert_rev karşılaştırma değeri")
    p_revision_swrev.add_argument("--certificate", required=True, type=int, help="Certificate içindeki revision değeri")
    p_revision_swrev.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_revision_info = _tr_help(revision_sub.add_parser("swrev-info", help="Keywriter SWREV alan boyutlarını ve temel özellikleri göster"))
    p_revision_info.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_boardcfg = _tr_help(sub.add_parser("boardcfg", help="Security Board Configuration policy alanlarını offline kontrol et"))
    boardcfg_sub = p_boardcfg.add_subparsers(dest="boardcfg_kind", required=True)

    p_boardcfg_new = _tr_help(boardcfg_sub.add_parser("new", help="Security BoardCfg policy YAML şablonu oluştur"))
    p_boardcfg_new.add_argument("--output", required=True, type=Path, help="YAML profile çıktı yolu")

    p_boardcfg_check = _tr_help(boardcfg_sub.add_parser("check", help="Secure Debug ve Extended OTP policy alanlarını kontrol et"))
    p_boardcfg_check.add_argument("profile", type=Path, help="Security BoardCfg policy YAML profile")
    p_boardcfg_check.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_boardcfg_debug = _tr_help(boardcfg_sub.add_parser("debug-policy", help="Debug certificate'ı BoardCfg runtime policy açısından değerlendir"))
    p_boardcfg_debug.add_argument("profile", type=Path, help="Security BoardCfg policy YAML profile")
    p_boardcfg_debug.add_argument("--certificate", required=True, type=Path, help="Secure Debug DER certificate")
    p_boardcfg_debug.add_argument("--transport", required=True, choices=["tisci", "sec-ap"], help="Runtime debug certificate taşıma yolu")
    p_boardcfg_debug.add_argument("--host-id", type=int, help="TISCI requester Host ID; sec-ap için kullanılmaz")
    p_boardcfg_debug.add_argument("--soc-uid", help="Wildcard kapalıysa target SOC UID: 64 hex karakter")
    p_boardcfg_debug.add_argument("--jtag-efuse", choices=["enabled", "disabled", "unknown"], default="unknown", help="JTAG connectivity eFuse durumu; varsayılan unknown")
    p_boardcfg_debug.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_boardcfg_writer = _tr_help(boardcfg_sub.add_parser("revision-writer", help="SWREV/KEYREV write_host authorization policy'sini değerlendir"))
    p_boardcfg_writer.add_argument("profile", type=Path, help="Security BoardCfg policy YAML profile")
    p_boardcfg_writer.add_argument("--host-id", required=True, type=int, help="TISCI requester Host ID")
    p_boardcfg_writer.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_sdk = _tr_help(sub.add_parser("sdk", help="MCU+ SDK security configuration ve consumer zincirlerini read-only kontrol et"))
    sdk_sub = p_sdk.add_subparsers(dest="sdk_kind", required=True)

    p_sdk_lint = _tr_help(sdk_sub.add_parser("lint", help="devconfig, Makefile ve signing script zincirini statik olarak incele"))
    p_sdk_lint.add_argument("--devconfig", type=Path, help="SDK devconfig/devconfig.mak dosyası")
    p_sdk_lint.add_argument("--app-makefile", type=Path, help="İncelenecek application Makefile")
    p_sdk_lint.add_argument("--sbl-makefile", type=Path, help="İncelenecek SBL Makefile")
    p_sdk_lint.add_argument("--app-tool", type=Path, help="Kurulu appimage_x509_cert_gen.py")
    p_sdk_lint.add_argument("--rom-tool", type=Path, help="Kurulu rom_image_gen.py")
    p_sdk_lint.add_argument("--make-db", type=Path, help="İsteğe bağlı önceden alınmış make -pn çıktısı; toolkit make çalıştırmaz")
    p_sdk_lint.add_argument("--intent", choices=["development", "production"], default="development", help="Debug policy değerlendirmesi için kullanım amacı")
    p_sdk_lint.add_argument("--report", type=Path, help="Secret değer/path içermeyen JSON raporu")
    p_sdk_lint.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_sdk_diff = _tr_help(sdk_sub.add_parser("diff", help="İki SDK/config source setindeki security açısından anlamlı değişiklikleri karşılaştır"))
    p_sdk_diff.add_argument("--old-label", default="old", help="Eski/source set için rapor etiketi")
    p_sdk_diff.add_argument("--new-label", default="new", help="Yeni/source set için rapor etiketi")
    p_sdk_diff.add_argument("--old-devconfig", type=Path, help="Eski devconfig.mak")
    p_sdk_diff.add_argument("--new-devconfig", type=Path, help="Yeni devconfig.mak")
    p_sdk_diff.add_argument("--old-app-makefile", type=Path, help="Eski application Makefile")
    p_sdk_diff.add_argument("--new-app-makefile", type=Path, help="Yeni application Makefile")
    p_sdk_diff.add_argument("--old-sbl-makefile", type=Path, help="Eski SBL Makefile")
    p_sdk_diff.add_argument("--new-sbl-makefile", type=Path, help="Yeni SBL Makefile")
    p_sdk_diff.add_argument("--old-app-tool", type=Path, help="Eski appimage_x509_cert_gen.py")
    p_sdk_diff.add_argument("--new-app-tool", type=Path, help="Yeni appimage_x509_cert_gen.py")
    p_sdk_diff.add_argument("--old-rom-tool", type=Path, help="Eski rom_image_gen.py")
    p_sdk_diff.add_argument("--new-rom-tool", type=Path, help="Yeni rom_image_gen.py")
    p_sdk_diff.add_argument("--report", type=Path, help="Secret değer/path içermeyen JSON karşılaştırma raporu")
    p_sdk_diff.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_data = _tr_help(sub.add_parser("data", help="TISCI generalized authentication için generic binary hazırla ve doğrula"))
    data_sub = p_data.add_subparsers(dest="data_kind", required=True)

    p_data_new = _tr_help(data_sub.add_parser("new", help="Generic data profile YAML şablonu oluştur"))
    p_data_new.add_argument("--output", required=True, type=Path, help="YAML profile çıktı yolu")

    p_data_validate = _tr_help(data_sub.add_parser("validate", help="Generic data profile alanlarını kontrol et"))
    p_data_validate.add_argument("profile", type=Path, help="Generic data YAML profile")
    p_data_validate.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_data_build = _tr_help(data_sub.add_parser("build", help="Signed veya encrypted+signed generic data package üret"))
    p_data_build.add_argument("profile", type=Path, help="Generic data YAML profile")
    p_data_build.add_argument("--key", required=True, type=Path, help="RSA-4096 private signing key; path veya içerik çıktıya kaydedilmez")
    p_data_build.add_argument("--mek", type=Path, help="Encryption açıksa 64-hex AES-256 MEK dosyası; path veya içerik çıktıya kaydedilmez")
    p_data_build.add_argument("--certificate", type=Path, help="DER certificate çıktı yolu; verilmezse package adının sonuna .der eklenir")
    p_data_build.add_argument("--output", required=True, type=Path, help="DER certificate + payload/ciphertext package çıktı yolu")
    p_data_build.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_data_verify = _tr_help(data_sub.add_parser("verify", help="Generic data package için host-side integrity ve isteğe bağlı decryption kontrolü yap"))
    p_data_verify.add_argument("package", type=Path, help="Doğrulanacak generic data package")
    p_data_verify.add_argument("--mek", type=Path, help="Encrypted package için optional AES-256 MEK; decryption correctness kontrolü")
    p_data_verify.add_argument("--original", type=Path, help="İsteğe bağlı original data; plaintext/padding identity kontrolü")
    p_data_verify.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_report = _tr_help(sub.add_parser("report", help="Secure image doğrulama sonuçlarını okunabilir rapora dönüştür"))
    report_sub = p_report.add_subparsers(dest="report_kind", required=True)

    p_report_image = _tr_help(report_sub.add_parser("image", help="Tek bir secure image için Markdown doğrulama raporu üret"))
    p_report_image.add_argument("image", type=Path, help="Raporlanacak secure image veya DER certificate")
    p_report_image.add_argument("--output", required=True, type=Path, help="Markdown rapor yolu")
    p_report_image.add_argument("--json", dest="json_output", type=Path, help="İsteğe bağlı machine-readable JSON rapor yolu")
    p_report_image.add_argument("--compact", action="store_true", help="Komut sonucunu tek satır JSON yaz")

    p_report_batch = _tr_help(report_sub.add_parser("batch", help="Açıkça verilen birden çok image için toplu doğrulama özeti üret"))
    p_report_batch.add_argument("images", nargs="+", type=Path, help="Raporlanacak secure image/certificate dosyaları; dizin taraması yapılmaz")
    p_report_batch.add_argument("--output", required=True, type=Path, help="Markdown toplu rapor yolu")
    p_report_batch.add_argument("--json", dest="json_output", type=Path, help="İsteğe bağlı machine-readable JSON rapor yolu")
    p_report_batch.add_argument("--compact", action="store_true", help="Komut sonucunu tek satır JSON yaz")

    p_errata = _tr_help(sub.add_parser("errata", help="AM64x/AM243x Rev. J Boot errata kayıtlarını kullanım bağlamına göre incele"))
    errata_sub = p_errata.add_subparsers(dest="errata_kind", required=True)

    p_errata_list = _tr_help(errata_sub.add_parser("list", help="Boot advisory indexini silicon revision ve kullanım alanına göre filtrele"))
    p_errata_list.add_argument("--revision", required=True, choices=["1.0", "2.0", "SR1.0", "SR2.0"], help="AM64x/AM243x silicon revision")
    p_errata_list.add_argument("--category", choices=["all", "security", "boot-media", "debug"], default="all", help="Advisory kategorisi")
    p_errata_list.add_argument("--boot-mode", choices=["unknown", "uart", "ospi", "xspi", "qspi", "spi", "ethernet", "mmcsd", "sd", "emmc", "usb", "pcie", "gpmc"], default="unknown", help="İsteğe bağlı boot-mode filtresi")
    p_errata_list.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_errata_check = _tr_help(errata_sub.add_parser("check", help="Secure Boot/ROM/security advisories için koşul bazlı offline değerlendirme yap"))
    p_errata_check.add_argument("--revision", required=True, choices=["1.0", "2.0", "SR1.0", "SR2.0"], help="AM64x/AM243x silicon revision")
    p_errata_check.add_argument("--device-state", choices=["gp", "hs-fs", "hs-se", "unknown"], default="unknown", help="Cihaz lifecycle durumu; bilinmiyorsa unknown")
    p_errata_check.add_argument("--flow", choices=["full-combined", "normal", "redundant-backup", "unknown"], default="unknown", help="ROM boot/certificate akış bağlamı")
    p_errata_check.add_argument("--primary-boot", choices=["unknown", "uart", "ospi", "xspi", "qspi", "spi", "ethernet", "mmcsd", "sd", "emmc", "usb", "pcie", "gpmc"], default="unknown", help="Primary boot mode")
    p_errata_check.add_argument("--backup-boot", choices=["unknown", "uart", "ospi", "xspi", "qspi", "spi", "ethernet", "mmcsd", "sd", "emmc", "usb", "pcie", "gpmc"], default="unknown", help="Backup boot mode")
    p_errata_check.add_argument("--outer-rsa", choices=["degenerate", "non-degenerate", "unknown"], default="unknown", help="Combined-image outer X.509 RSA türü")
    p_errata_check.add_argument("--certificate-info", choices=["present", "absent", "unknown"], default="unknown", help="Normal ROM certificate'ta Extended/Legacy info varlığı")
    p_errata_check.add_argument("--redundant-content", choices=["complete-boot", "tifs-only", "other", "unknown"], default="unknown", help="Redundant offset içeriği; i2415 bağlamı")
    p_errata_check.add_argument("--external-emulator", choices=["yes", "no", "unknown"], default="unknown", help="HS-FS debug/external emulator erişim bağlamı")
    p_errata_check.add_argument("--report", type=Path, help="JSON değerlendirme raporu")
    p_errata_check.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_release = _tr_help(sub.add_parser("release-scan", help="Release tree içinde accidental secret material ve user-specific path taraması yap"))
    p_release.add_argument("root", type=Path, help="Taranacak release/workspace root")
    p_release.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_network = _tr_help(sub.add_parser("network-policy", help="Studio runtime network/telemetry politikasını göster"))
    p_network.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_beta = _tr_help(sub.add_parser("beta-readiness", help="Gerçek GUI/standalone release blokajlarını yapılmış saymadan beta hazırlığını göster"))
    p_beta.add_argument("--source-root", type=Path, help="İsteğe bağlı source package root; release hygiene/packaging recipe kontrolleri için")
    p_beta.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    p_diag = _tr_help(sub.add_parser("diagnostics", help="Secret/path içermeyen paylaşılabilir environment ve release diagnostic özeti üret"))
    p_diag.add_argument("--sdk-root", type=Path, help="İsteğe bağlı SDK root; diagnostic çıktısına full path yazılmaz")
    p_diag.add_argument("--project", type=Path, help="İsteğe bağlı Project Workspace; root path çıktıya yazılmaz")
    p_diag.add_argument("--source-root", type=Path, help="İsteğe bağlı source package root; beta readiness için")
    p_diag.add_argument("--output", type=Path, help="İsteğe bağlı .json veya .md share-safe diagnostic dosyası")
    p_diag.add_argument("--compact", action="store_true", help="JSON çıktısını tek satır yaz")

    args = parser.parse_args(argv)
    try:
        if args.command == "gui":
            from .gui import launch_gui
            return launch_gui()

        if args.command == "release-scan":
            out = scan_release_tree(args.root)
            _emit(out, pretty=not args.compact)
            return 0 if out["status"] == "PASS" else 2

        if args.command == "network-policy":
            out = runtime_network_policy().to_dict()
            _emit(out, pretty=not args.compact)
            return 0

        if args.command == "beta-readiness":
            out = beta_readiness(args.source_root)
            _emit(out, pretty=not args.compact)
            return 0 if out.get("status") == "PASS" else (3 if out.get("status") == "PARTIAL" else 2)

        if args.command == "diagnostics":
            env = resolve_environment(args.sdk_root)
            project = open_project(args.project) if args.project else None
            out = diagnostics_snapshot(environment=env, project=project, source_root=args.source_root)
            if args.output:
                written = write_diagnostics(out, args.output)
                out = {**out, "diagnostic_output": written.name}
            _emit(out, pretty=not args.compact)
            return 0

        if args.command == "environment":
            out = resolve_environment(args.sdk_root).to_dict()
            _emit(out, pretty=not args.compact)
            return 0 if out["status"] == "PASS" else (3 if out["status"] == "PARTIAL" else 2)

        if args.command == "project":
            if args.project_kind == "init":
                project = create_project(args.root, name=args.name, device=args.device, silicon_revision=args.silicon_revision, lifecycle=args.lifecycle)
            else:
                project = open_project(args.root)
            _emit({"status": "PASS", "operation": f"project_{args.project_kind}", "project": project.to_dict(), "secret_paths_stored": False}, pretty=not args.compact)
            return 0

        if args.command == "inspect":
            _emit(inspect_artifact(args.image), pretty=not args.compact)
            return 0
        if args.command == "verify":
            out = verify_artifact(args.image)
            _emit(out, pretty=not args.compact)
            status = out["overall_host_side_verification"]
            return 0 if status == "PASS" else (3 if status in {"PARTIAL", "NOT_CHECKED"} else 2)

        if args.command == "negative":
            if args.negative_kind == "suite":
                out = run_negative_suite(args.image, args.output_dir)
            elif args.negative_kind == "component":
                out = create_negative_variant(args.image, "component", args.output, component_index=args.component_index)
            else:
                out = create_negative_variant(
                    args.image,
                    args.negative_kind,
                    args.output,
                    offset=getattr(args, "offset", None),
                )
            _emit(out, pretty=not args.compact)
            status = out.get("suite_result", out.get("negative_test_result"))
            return 0 if status == "PASS" else (3 if status == "PARTIAL" else 2)

        if args.command == "key":
            if args.key_kind == "signing":
                out = preflight_signing_key(args.input, purpose=args.purpose, public_der_output=args.public_der_output)
            elif args.key_kind == "mek":
                out = preflight_mek(args.input)
            elif args.key_kind == "compare":
                out = compare_key_material(args.private_key, args.reference)
            else:
                if args.key_generate_kind == "signing":
                    out = generate_signing_key(args.output_dir, role=args.role)
                elif args.key_generate_kind == "mek":
                    out = generate_mek(args.output_dir, role=args.role)
                else:
                    out = generate_key_set(args.output_dir, profile=args.profile, backup=args.backup)
            _emit(out, pretty=not args.compact)
            status = out.get("status", "FAIL")
            return 0 if status == "PASS" else (3 if status == "PARTIAL" else 2)

        if args.command == "provision":
            if args.provision_kind == "new":
                save_provision_profile(template_provision_profile(), args.output)
                _emit({"status": "PASS", "profile_type": "hsfs_to_hsse_preflight", "output": str(args.output)})
                return 0
            out = provision_preflight(
                args.profile,
                smek=args.smek,
                bmek=args.bmek,
                report=args.report,
            )
            _emit(out, pretty=not args.compact)
            status = out.get("status", "FAIL")
            return 0 if status == "PASS" else (3 if status == "PARTIAL" else 2)

        if args.command == "revision":
            if args.revision_kind == "key":
                out = simulate_key_revision(args.keycnt, args.keyrev, args.target_keyrev)
            elif args.revision_kind == "key-matrix":
                out = key_revision_matrix()
            elif args.revision_kind == "swrev":
                out = simulate_swrev(args.context, args.reference, args.certificate)
            else:
                out = swrev_field_info()
            _emit(out, pretty=not args.compact)
            status = out.get("status", "FAIL")
            return 0 if status == "PASS" else (3 if status == "PARTIAL" else 2)

        if args.command == "boardcfg":
            if args.boardcfg_kind == "new":
                save_boardcfg_profile(template_boardcfg_profile(), args.output)
                _emit({"status": "PASS", "profile_type": "security_boardcfg_policy", "output": str(args.output)})
                return 0
            if args.boardcfg_kind == "check":
                out = check_boardcfg_profile(args.profile)
            elif args.boardcfg_kind == "debug-policy":
                out = evaluate_debug_policy(
                    args.profile,
                    args.certificate,
                    transport=args.transport,
                    host_id=args.host_id,
                    soc_uid=args.soc_uid,
                    jtag_efuse=args.jtag_efuse,
                )
            else:
                out = evaluate_revision_writer(args.profile, args.host_id)
            _emit(out, pretty=not args.compact)
            status = out.get("status", "FAIL")
            return 0 if status == "PASS" else (3 if status == "PARTIAL" else 2)

        if args.command == "sdk":
            if args.sdk_kind == "lint":
                out = lint_sdk_security(
                    devconfig=args.devconfig,
                    app_makefile=args.app_makefile,
                    sbl_makefile=args.sbl_makefile,
                    app_tool=args.app_tool,
                    rom_tool=args.rom_tool,
                    make_db=args.make_db,
                    intent=args.intent,
                    report=args.report,
                )
            else:
                out = compare_sdk_security(
                    old_devconfig=args.old_devconfig, new_devconfig=args.new_devconfig,
                    old_app_makefile=args.old_app_makefile, new_app_makefile=args.new_app_makefile,
                    old_sbl_makefile=args.old_sbl_makefile, new_sbl_makefile=args.new_sbl_makefile,
                    old_app_tool=args.old_app_tool, new_app_tool=args.new_app_tool,
                    old_rom_tool=args.old_rom_tool, new_rom_tool=args.new_rom_tool,
                    old_label=args.old_label, new_label=args.new_label, report=args.report,
                )
            _emit(out, pretty=not args.compact)
            status = out.get("status", "FAIL")
            return 0 if status == "PASS" else (3 if status == "PARTIAL" else 2)

        if args.command == "data":
            if args.data_kind == "new":
                save_generic_data_profile(template_generic_data_profile(), args.output)
                _emit({"status": "PASS", "profile_type": "generic_data", "output": str(args.output)})
                return 0
            if args.data_kind == "validate":
                out = validate_generic_data_profile(args.profile)
            elif args.data_kind == "build":
                out = build_generic_data(
                    args.profile, args.key, args.output,
                    certificate_output=args.certificate, mek=args.mek,
                )
            else:
                out = verify_generic_data(args.package, mek=args.mek, original=args.original)
            _emit(out, pretty=not args.compact)
            status = out.get("status", "FAIL")
            return 0 if status == "PASS" else (3 if status in {"PARTIAL", "NOT_CHECKED"} else 2)

        if args.command == "report":
            if args.report_kind == "image":
                out = write_image_report(args.image, args.output, json_output=args.json_output)
            else:
                out = write_batch_report(args.images, args.output, json_output=args.json_output)
            _emit(out, pretty=not args.compact)
            status = out.get("status", "FAIL")
            return 0 if status == "PASS" else (3 if status in {"PARTIAL", "NOT_CHECKED"} else 2)

        if args.command == "errata":
            if args.errata_kind == "list":
                out = list_errata(revision=args.revision, category=args.category, boot_mode=args.boot_mode)
            else:
                out = check_errata(
                    revision=args.revision,
                    device_state=args.device_state,
                    flow=args.flow,
                    primary_boot=args.primary_boot,
                    backup_boot=args.backup_boot,
                    outer_rsa=args.outer_rsa,
                    certificate_info=args.certificate_info,
                    redundant_content=args.redundant_content,
                    external_emulator=args.external_emulator,
                    report=args.report,
                )
            _emit(out, pretty=not args.compact)
            return 0

        if args.command == "cert" and args.cert_kind == "new":
            save_profile(template_profile(args.type), args.output)
            _emit({"status": "PASS", "profile_type": args.type, "output": str(args.output)})
            return 0
        if args.command == "cert" and args.cert_kind == "validate":
            out = validate_profile_file(args.profile)
            _emit(out, pretty=not args.compact)
            return 0 if out["status"] == "PASS" else 2
        if args.command == "cert" and args.cert_kind == "render":
            if args.output.exists():
                raise FileExistsError(f"çıktı zaten mevcut: {args.output}")
            text = render_openssl_config(args.profile)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
            _emit({"status": "PASS", "output": str(args.output)})
            return 0
        if args.command == "cert" and args.cert_kind == "build":
            out = build_certificate(args.profile, args.key, args.output, args.package)
            _emit(out, pretty=not args.compact)
            return 0
        if args.command == "cert" and args.cert_kind == "explain":
            print(explain_certificate(args.certificate))
            return 0
        if args.command == "cert" and args.cert_kind == "metadata":
            out = certificate_metadata(args.certificate)
            _emit(out, pretty=not args.compact)
            return 0
        if args.command == "cert" and args.cert_kind == "export":
            out = export_certificate(args.certificate, args.output, encoding=args.format)
            _emit(out, pretty=not args.compact)
            return 0
        if args.command == "cert" and args.cert_kind == "public-key":
            out = export_public_key_der(args.certificate, args.output)
            _emit(out, pretty=not args.compact)
            return 0
        if args.command == "cert" and args.cert_kind == "match":
            out = compare_certificate_with_private_key(args.certificate, args.key)
            _emit(out, pretty=not args.compact)
            return 0 if out.get("status") == "PASS" else 2
        if args.command == "cert" and args.cert_kind == "clone":
            out = save_cloned_profile(args.certificate, args.output, payload_path=args.payload)
            _emit(out, pretty=not args.compact)
            return 0
        if args.command == "cert" and args.cert_kind == "compare":
            out = compare_certificates(args.left, args.right)
            _emit(out, pretty=not args.compact)
            return 0
        if args.command == "cert" and args.cert_kind == "library":
            if args.action == "list":
                out = {"status": "PASS", "certificates": list_certificate_library(args.project)}
            elif args.action == "add":
                if not args.certificate:
                    raise ValueError("library add için --certificate gerekli")
                out = add_certificate_to_library(args.project, args.certificate, name=args.name)
            else:
                if not args.relative_path:
                    raise ValueError("library remove için --relative-path gerekli")
                out = remove_certificate_from_library(args.project, args.relative_path)
            _emit(out, pretty=not args.compact)
            return 0

        if args.command == "build" and args.build_kind == "app":
            out = build_app(
                signing_tool=args.tool,
                input_image=args.input,
                signing_key=args.key,
                encryption_key=args.enckey,
                authtype=args.authtype,
                output=args.output,
                python_executable=args.python_executable,
                working_directory=args.working_dir,
                build_record=args.build_record,
                log=args.log,
                dry_run=args.dry_run,
                post_verify=args.post_verify,
            )
            _emit(out, pretty=not args.compact)
            if args.dry_run:
                return 0
            return 0 if out.get("overall_result") == "PASS" else (3 if out.get("overall_result") == "PARTIAL" else 2)

        if args.command == "build" and args.build_kind == "rom":
            out = build_rom(
                signing_tool=args.tool,
                sbl_bin=args.sbl_bin,
                sysfw_bin=args.sysfw_bin,
                sysfw_inner_cert=args.sysfw_inner_cert,
                boardcfg_blob=args.boardcfg_blob,
                sbl_loadaddr=args.sbl_loadaddr,
                sysfw_loadaddr=args.sysfw_loadaddr,
                bcfg_loadaddr=args.bcfg_loadaddr,
                swrv=args.swrv,
                signing_key=args.key,
                sbl_encryption_key=args.sbl_enckey,
                debug=args.debug,
                output=args.output,
                python_executable=args.python_executable,
                working_directory=args.working_dir,
                build_record=args.build_record,
                log=args.log,
                dry_run=args.dry_run,
                post_verify=args.post_verify,
            )
            _emit(out, pretty=not args.compact)
            if args.dry_run:
                return 0
            return 0 if out.get("overall_result") == "PASS" else (3 if out.get("overall_result") == "PARTIAL" else 2)
    except FileNotFoundError as exc:
        print(f"HATA: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"HATA: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
