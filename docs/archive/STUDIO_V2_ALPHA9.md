# AM64x Secure Boot Studio v2.0.0-alpha9

Alpha9 yeni AM64x hardware/provisioning execution işi değildir; Studio UX, semantic presentation ve Project Workspace history geliştirmesidir.

Bu sürümün ana değişiklikleri:

1. **Secure Debug Assistant** raw JSON ekranından çıkarıldı. Secure Debug X.509 → Security BoardCfg runtime policy → delivery context → target prerequisites → offline policy decision akışı `FlowDiagramWidget` ile gösterilir. Sonuç `HumanResultView` içinde check/`Neden?`/claim-boundary biçimindedir. `POLICY_ALLOWS_REQUEST` target acceptance veya JTAG unlock anlamına gelmez.
2. Secure Debug GUI/backend transport drift'i giderildi. GUI yalnız backend contract'ındaki canonical `tisci` ve `sec-ap` context'lerini sunar; eski geçersiz standalone `jtag` enum'u kaldırıldı. TISCI requester Host ID alanı yalnız `tisci` seçiliyken aktif olur.
3. **Generic Data Assistant** profile/build/verify sonuçlarını generalized-authentication diagramıyla gösterir. Signed ve encrypted+signed yollar ayrılır; processor Boot Extension'ın kullanılmadığı ve `TISCI_MSG_PROC_AUTH_BOOT` target çağrısının `NOT_CHECKED / NOT EXECUTED` olduğu görünür tutulur.
4. Generic-data build sonucu host verification check'lerini ve share-safe output referanslarını doğrudan workflow result'a bağlar; raw JSON ana kullanıcı görünümü değildir.
5. **SDK Compare** old/new source'u raw JSON olarak dökmek yerine role-based side-by-side semantic diff gösterir: classification, review seviyesi, SHA değişimi ve mapped field before/after. Private/encryption key için literal configured host path gösterilmez. Mapped fark bulunmaması değişikliğin güvenli olduğu iddiasına dönüştürülmez.
6. **Project Workspace** gerçek persistent activity history aldı. Project aktifken her workflow sonucu `sessions/activity.jsonl` içine compact/share-safe event olarak yazılır. Secret value, secret path, full host path ve arbitrary technical JSON activity log'a yazılmaz; output yalnız basename olarak tutulur.
7. **Results / Reports** ekranına `Project History` sekmesi eklendi. In-memory Session History uygulama kapanınca silinirken Project History project dizininden yeniden açılabilir.
8. `NOT_APPLICABLE` result state'i insan-okunur `Uygulanmaz` durumuna bağlandı.

Safety boundary değişmedi: OTP/eFuse/customer-key provisioning, HS-FS→HS-SE transition, target `TISCI_MSG_PROC_AUTH_BOOT`, JTAG unlock, permanent debug/security change ve hardware/customer Root of Trust enforcement execution yoktur.
