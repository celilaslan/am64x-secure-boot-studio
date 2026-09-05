# AM64x Secure Boot Studio v2.0.0-alpha8

Alpha8 yeni bir AM64x hardware security execution milestone'u değildir; Studio GUI semantic/UX geliştirme scope'udur.

Bu sürümde advanced ekranların görsel anlatımı ve semantic contract'ı güçlendirildi:

1. **SDK Inspector** artık `ENC_ENABLED → Application Makefile → appimage_x509_cert_gen.py` ve `ENC_SBL_ENABLED → SBL Makefile → rom_image_gen.py` zincirlerini ayrı diagram lane'lerinde gösterir. İki configuration switch aynı artifact katmanı gibi sunulmaz.
2. **Provisioning Preparation** primary/backup customer key setlerini, `KEYCNT` / `KEYREV` active context'ini ve offline execution sınırını secret-safe diagram üzerinde gösterir. Private/symmetric key değeri, secret path veya secret hash diagram modeline girmez.
3. **KEYREV / SWREV** ve **Security BoardCfg** ekranları raw JSON yerine semantic flow + insan-okunur result view kullanır. Target write, eFuse programming veya runtime BoardCfg gönderimi yapılmaz.
4. **Certificate Explorer ↔ Image Anatomy** bağlantısı eklendi. Certificate field/extension seçimi parsed artifact içindeki ilgili certificate, payload/ciphertext veya ROM component bölümünü vurgular; missing offset/address tahmin edilmez.
5. Her `HumanResultView` check satırında **Neden?** aksiyonu vardır. Known checks source-backed açıklama gösterir; unknown/future checks de PASS/FAIL/NOT_CHECKED durumuna uygun conservative açıklama alır ve sessizce boş bırakılmaz.
6. GUI/backend enum drift audit'i sırasında iki hata düzeltildi: SDK production intent artık canonical `production`, SWREV context'leri de backend'in kabul ettiği `tiboot3 / boardcfg / debug / application / generic` değerleriyle ortak contract'tan gelir.

Safety boundary değişmedi: OTP/eFuse write, HS-FS→HS-SE execution, permanent debug/security change, secret extraction veya hardware/customer enforcement claim yoktur.
