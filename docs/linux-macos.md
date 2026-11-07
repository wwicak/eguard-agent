# Linux dan macOS — fondasi port, BELUM siap deployment

Slice ini **belum menyelesaikan port**. Jangan distribusikan paket untuk produksi.
Tidak ada service yang dipasang/dijalankan pada shared work host. Cross-build
bukan validasi runtime Linux/macOS. Pipeline release belum dibuat karena collector,
cleanup launchd, dan acceptance paket belum lengkap.

## Kontrak identitas dan enrollment

Paket Unix netral tidak membawa URL, CA, atau pin bootstrap tertanam. Operator
harus memperoleh fingerprint dari kanal admin server yang terautentikasi,
bukan dari koneksi identity yang akan dipercaya.

Perintah target (hanya pada VM disposable yang berizin):

```sh
sudo eguard-nac enroll --server gateway.example:8443 --fingerprint <64-hex-lowercase> <CODE>
eguard-nac status
sudo eguard-nac uninstall
sudo eguard-nac uninstall --token <TOKEN>
sudo eguard-nac uninstall --authorization /path/authorization.json
```

`GET https://HOST:PORT/v1/nac/identity` adalah **satu-satunya** request yang
menonaktifkan verifikasi TLS. Request ini tidak membawa kode, CSR, cookie,
proxy atau redirect. Respons v1 memuat `ca_der_b64` dan `bootstrap_pin`.
Fingerprint = lowercase hex SHA256 atas gabungan byte:

```
eguard-nac-identity/v1\x00 || CA_DER || raw_ed25519_public_key_32_bytes
```

Mismatch menghentikan proses sebelum redeem kode. Setelah cocok, POST
`/v1/nac/enroll` memakai CA itu dengan verifikasi hostname/SAN normal dan
mengirim `code`, `csr_pem`, `hostname`, serta `platform=linux|darwin`.
Windows tetap menggunakan konfigurasi compiled-in dan menghilangkan platform.

`enrollment-identity.json` menyimpan server, CA, pin, dan fingerprint bersama.
Service membaca ulang dan menghitung fingerprint pada setiap startup. Bootstrap
bertanda tangan juga wajib menunjuk origin dan CA yang sama, sehingga server
tidak dapat diam-diam mengganti trust runtime lewat respons enroll. Pin tersebut
dipakai admission/bootstrap.Verify dan service factory. Mengganti pin/CA saja
terdeteksi, tetapi **root dapat mengganti CA, pin dan fingerprint sekaligus**.
Tidak ada janji keamanan terhadap root/admin atau akses disk offline.

## Lokasi dan kredensial

| OS | Root provisioning/journal | Binary / CLI target |
|---|---|---|
| Linux | `/var/lib/eguard-nac` / `journal.db` | `/usr/lib/eguard-nac/eguard-nac-service`, symlink `/usr/bin/eguard-nac` |
| macOS | `/Library/Application Support/eGuard NAC` / `journal.db` | `/Library/eGuard NAC/eguard-nac-service`, symlink `/usr/local/bin/eguard-nac` |

Root baru 0700, file 0600, key ECDSA P-256 PEM di root. Key ini
**file-protected, bukan hardware-bound**. TPM2 Linux dan Keychain/Secure Enclave
macOS adalah pekerjaan lanjutan, bukan implementasi saat ini. Pemeriksaan path
Unix belum handle-pinned terhadap TOCTOU/ancestor symlink; jangan mengklaim
ketahanan root/offline atau rollback disk.

Enrollment memakai mkdir eksklusif sebagai bukti ownership transaksi; existing
root tidak ditimpa. Kegagalan menghapus root yang dibuat transaksi. Start service
hanya dilakukan setelah admission signed bootstrap + activation. Penolakan
provisioning tidak memulai collection/transport. Runtime memakai fixed child verb
dan process-group boundary, tanpa shell atau executable yang ditentukan server.

## Build dan instalasi

```sh
GOPROXY=off GOSUMDB=off scripts/build-unix-packages.sh 0.0.0-dev
```

Script menghasilkan empat binary CGO-disabled Linux/macOS amd64/arm64 dan dua
konfigurasi nfpm. Jika nfpm tersedia, dibuat deb/rpm; jika tidak, hanya binary +
YAML (tidak mengunduh tool otomatis). Artefak bukan code-signed. Signing/GPG,
pkg macOS universal, launchd plist/scripts, dan GitHub release workflow **belum
tersedia**. Tidak ada prosedur instalasi macOS yang aman/terverifikasi dalam slice
ini. Jangan menjalankan installer pada shared host.

Kandidat deb/rpm memasang unit systemd dengan hardening dan postinstall hanya
`daemon-reload` + `enable`, tidak start. Service tanpa state mencetak
`Not enrolled.` dan keluar bersih. Preremove menolak semua enrolled roots dan
mengarahkan operator ke uninstall CLI terlebih dahulu (lebih ketat daripada
hanya Anti-Tamper ON). Upgrade in-place belum didukung. Setelah uninstall CLI
berhasil dan root terhapus, removal paket dapat dilanjutkan oleh admin pada VM.
Root tetap bisa memakai force purge; prerm bukan proteksi terhadap root.

Uninstall CLI memakai mode anti-tamper dari bootstrap terverifikasi: ON perlu
token/authorization signed, device-bound dan handoff ke service untuk journal
replay checks; OFF dapat memakai root lokal. Expiry Temporary memakai callback
cleanup resmi setelah journal ditutup, tanpa melewati gate anti-tamper. Adapter
cleanup Unix saat ini hanya disable service dan menghapus root/key, **belum
menghapus binary/registrasi launchd**; expiry macOS KeepAlive belum aman untuk
rilis dan memerlukan completion + VM acceptance. Jangan klaim uninstall lengkap.

## Collection dan batas lingkup

Unix collector saat ini hanya hostname, OS GOOS/GOARCH dan adapter dari
`net.Interfaces`. Domain, AV, firewall, secure boot, disk encryption, reboot,
route provenance, inventory software dan signed-in user **belum diintegrasikan**:
Unknown/uncollected, bukan bukti No/Yes. Parser fixture Linux/macOS dan akuisisi
provider yang diminta masih pekerjaan lanjutan. Timestamp/TTL boundary tetap
berlaku; error/cancel tidak memperpanjang freshness.

Produk hanya NAC posture/inventory/status. Tidak ada EDR, kernel driver, remote
shell, arbitrary command execution atau monitoring aktivitas pengguna. Perintah
service lokal memakai path dan argv tetap, deadline, tanpa shell.

## Validasi lokal

- RED: test identity gagal compile karena Identity/FetchIdentity/ValidateServer
  belum tersedia; test persistence gagal compile karena WriteIdentity/LoadIdentity
  belum tersedia. Kemudian GREEN.
- `go test -race -count=1 ./...` Linux lulus setelah perbaikan.
- `go vet ./...` Linux/darwin/windows lulus.
- CGO-disabled `go build ./...`: linux amd64/arm64, darwin amd64/arm64,
  windows amd64 lulus.
- Baseline HEAD pada detached temporary worktree: race suite lulus. Satu run
  awal working tree mengalami timeout fixture process-group boundary; rerun
  penuh lulus. Tidak diklaim sebagai baseline failure yang reproducible.
- nfpm tidak tersedia lokal; deb/rpm belum dibuat/diinspeksi. macOS pkg,
  codesign/notarytool serta runtime service/enroll/uninstall nyata NOT RUN.
