from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class GuidanceRecommendation:
    workflow: str
    title: str
    rationale: str
    safety_note: str


def recommend_workflow(*, has_image: bool, goal: str, wants_confidentiality: bool = False, provisioning_interest: bool = False) -> dict[str, str]:
    if provisioning_interest:
        row = GuidanceRecommendation(
            "provisioning",
            "Provisioning Hazırlığı",
            "Customer key hierarchy / HS-FS→HS-SE konusunu araştırmak veya offline preflight yapmak istiyorsunuz.",
            "Studio OTP/eFuse write veya HS-FS→HS-SE execution sunmaz.",
        )
    elif has_image and goal in {"understand", "verify", "what-is-this"}:
        row = GuidanceRecommendation(
            "inspector",
            "Image Doğrula / İncele",
            "Elinizde hazır artifact var; önce türünü, certificate boundary'sini ve host-side verification sonuçlarını görün.",
            "Host-side PASS hardware/customer enforcement kanıtı değildir.",
        )
    elif goal == "certificate":
        row = GuidanceRecommendation("certificate", "Certificate Explorer", "X.509 extension/OID ve certificate yapısını anlamak istiyorsunuz.", "Certificate signature ve payload integrity ayrı kontrollerdir.")
    elif goal == "negative":
        row = GuidanceRecommendation("negative", "Negatif Testler", "Bir değişikliğin hangi doğrulama katmanında yakalandığını görmek istiyorsunuz.", "Testler source dosyayı değiştirmeyen copy üzerinde yapılır.")
    elif goal == "rom":
        row = GuidanceRecommendation("rom", "ROM Combined Image", "RBL tarafından tüketilen combined boot image katmanında çalışmak istiyorsunuz.", "Exact load address/debug option değerleri source/build context'ten doğrulanmadan tahmin edilmez.")
    elif goal == "keys":
        row = GuidanceRecommendation("keys", "Key Center", "Synthetic development/test key üretmek veya mevcut key'i doğrulamak istiyorsunuz.", "Production customer key custody local test-key workflow'u ile eş tutulmaz.")
    else:
        suffix = " Şifreleme seçeneğini açın." if wants_confidentiality else " Signed-only akışla başlayabilirsiniz."
        row = GuidanceRecommendation("application", "Secure Application", "Application image üretmek istiyorsunuz." + suffix, "Build success tek başına security verification değildir.")
    return asdict(row)
