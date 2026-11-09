# Release Notes — eGuard NAC Agent 0.2.0 (TEST-UNSIGNED)

**Label: TEST-UNSIGNED, LAB.** Tidak ditandatangani; kunci bootstrap tertanam = kunci lab uji. **Bukan installer siap produksi.**

## Artefak
- `eGuard-NAC-Setup-0.2.0-x64-TEST-UNSIGNED.exe` — installer NSIS berisi `eguard-nac-service.exe` dan `nac-setup.exe` nyata.
- `SHA256SUMS`, `eguard-nac-agent-0.2.0.cdx.json` (CycloneDX 1.5 dari build info biner: bbolt 1.4.3, x/sys 0.47.0, go-ole 1.3.0, StackExchange/wmi 1.2.1, go1.26.1).

## Isi
- Agent khusus NAC terpisah dari EDR: collector posture native (adapter MAC/IP, identitas, Domain Joined, AV, firewall), Unknown tetap Unknown, freshness tidak diperpanjang.
- Transport mTLS dengan kunci mesin CNG non-exportable.
- Lifecycle bertanda tangan Ed25519 + journal anti-replay; mode Temporary/Permanent; Anti-Tamper ON/OFF dari konfigurasi bertanda tangan.
- Installer transaksional dengan rollback; cleanup resmi pada expiry Temporary (berjalan dan boot berikutnya); uninstall ON (izin server) / OFF (admin).

## Terverifikasi di Windows 10 Pro 19045 (VM tester)
- Collector nyata (domain, firewall 3 profil, AV Defender yes/yes/yes).
- SCM create/rollback, fail-fast saat service exit.
- Kunci CNG ECDSA/RSA, penolakan kunci exportable.
- Provisioning ACL.
- Enroll Permanent + service Running + posture mTLS + stop bersih.
- **Temporary expiry → berhenti tepat deadline → cleanup resmi otomatis** (service, provisioning, cert+kunci terhapus; binary dijadwalkan hapus saat reboot).

## Belum terverifikasi (wajib sebelum produksi)
- Installer EXE 0.2.0 end-to-end di Windows (dibangun setelah VM offline).
- Penghapusan binary saat reboot; cleanup expiry saat boot berikutnya.
- DACL Anti-Tamper ON; uninstall ON/OFF; restore setelah penolakan.
- Perubahan jam lintas reboot; upgrade/rollback versi.
- Windows 11; code signing; endpoint enrollment backend produksi; mockup UI disetujui; kebijakan outage server.
