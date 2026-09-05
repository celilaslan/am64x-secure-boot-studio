# AM64x Secure Boot Studio v2.0.0-alpha7

Alpha7 yeni bir AM64x security execution milestone'u değildir; toolkit GUI/UX ürünleştirme scope'udur.

Bu sürümde dört ana alan iyileştirildi:

1. ROM Combined Image, Application ekranıyla aynı disipline sahip adım-adım wizard oldu. Exact load address veya debug option source olmadan tahmin edilmez.
2. Certificate Explorer, raw JSON ağırlıklı görünümden tree/detail modeline geçti. ROM, application/generalized-auth, Keywriter ve Secure Debug certificate context'leri ayrı gösterilir.
3. Key Center, key'lerin yalnız algoritmasını değil rollerini de anlatır. Application signing/MEK ile SMPK/BMPK/SMEK/BMEK provisioning rolleri UI'da ayrıdır.
4. Home ekranı Environment, Project ve son workflow durumunu gösteren dashboard + açıklamalı task card yapısına taşındı.

Safety boundary değişmedi: OTP/eFuse write, HS-FS→HS-SE execution, permanent debug/security change veya hardware enforcement claim yoktur.
