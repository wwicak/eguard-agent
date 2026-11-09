# eGuard NAC Agent — kandidat lokal TEST-UNSIGNED

Implementasi parsial NAC-only untuk review; **bukan produk siap instalasi**. Dokumentasi Bahasa Indonesia, pesan installer English. Target Windows 11 x64. Core Go menguji Ed25519 lifecycle dan posture tri-state; service Windows memakai subprocess fixed self-collector dengan deadline/output terbatas (Windows Job Object belum diuji di VM) untuk mengumpulkan evidence read-only native dan menulis ringkasan non-identitas ke event log bila sumber tersedia, tanpa pengiriman evidence, enrollment, atau enforcement. Binary `nac-inspect` menampilkan evidence lokal sensitif hanya untuk VM yang diizinkan. Installer NSIS inspection-only **bukan deliverable installer**: hanya menyalin payload ke TEMP; tidak memasang service atau ACL. Jangan jalankan pada host production.

## Port Linux/macOS (kandidat, belum production-ready)

Enrollment paket netral dengan fingerprint operator, collector read-only,
inventory opt-in, cleanup Unix, packaging deb/rpm/pkg dan release workflow tersedia.
**Runtime systemd/launchd, signing dan acceptance VM belum diverifikasi.** Lihat
[docs/linux-macos.md](docs/linux-macos.md) untuk perintah, trust, batas evidence,
prosedur publikasi paket ke server dan pekerjaan tersisa.

## Uji/build terisolasi

`GOPROXY=off GOSUMDB=off go test -count=1 ./...`

`GOPROXY=off GOSUMDB=off go vet ./...`

`GOPROXY=off GOSUMDB=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/eguard-nac-service-TEST-UNSIGNED.exe ./cmd/nac-service`

`GOPROXY=off GOSUMDB=off go test -race -count=1 ./...`

`./scripts/build-local.sh` membangun binary service/inspector/test Windows serta NSIS inspection-only. Tidak ada runtime Windows/Job Object terverifikasi. `cd installer/windows && makensis eguard-nac.nsi` bukan build installer fungsional.

Diperlukan Windows VM/runner untuk test SCM, ACL, UAC, installer dan lifecycle; sertifikat Authenticode serta server enrollment/CA terverifikasi untuk release. Tidak ada pengujian runtime Windows dalam slice ini. Lihat `docs/audit.md` untuk batas keamanan dan `docs/windows-validation.md` untuk uji VM yang belum dijalankan.
