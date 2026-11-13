# Linux dan macOS — kandidat port NAC, belum production-ready

Tidak ada instalasi/service dijalankan pada shared work host. Cross-build dan
fixture bukan validasi runtime. Acceptance enrollment, expiry, uninstall,
upgrade, systemd hardening, launchd serta signing nyata wajib pada VM disposable
berizin sebelum deployment. Windows memakai jalur install dan upgrade terpisah.

## Instalasi dan enrollment (hanya VM berizin)

Linux Debian/Ubuntu:

```sh
sudo dpkg -i eguard-nac-agent_1.2.3_amd64.deb
# arm64: eguard-nac-agent_1.2.3_arm64.deb
sudo eguard-nac enroll --server gateway.example:8443 --fingerprint <64-hex-lowercase> <CODE>
eguard-nac status
```

RHEL/Rocky/Fedora:

```sh
sudo rpm -i eguard-nac-agent-1.2.3-1.x86_64.rpm
# arm64: eguard-nac-agent-1.2.3-1.aarch64.rpm
sudo eguard-nac enroll --server gateway.example:8443 --fingerprint <64-hex-lowercase> <CODE>
```

macOS:

```sh
sudo installer -pkg eGuard-NAC-1.2.3.pkg -target /
sudo eguard-nac enroll --server gateway.example:8443 --fingerprint <64-hex-lowercase> <CODE>
eguard-nac status
```

Paket tidak start daemon: Linux hanya daemon-reload + enable; macOS memasang
symlink CLI tanpa load. Enrollment terverifikasi baru memanggil systemctl
start atau `launchctl bootstrap system /Library/LaunchDaemons/id.eguard.nac.plist`.
Status tidak mencetak secret dan bukan bukti service sehat/akses diizinkan.
Existing root tidak ditimpa. Enrollment gagal menghapus root transaksi sendiri.
Upgrade enrolled in-place memakai hook paket dengan state dipertahankan (lihat bagian upgrade).

## Trust fingerprint

Paket netral tidak membawa URL/CA/pin compiled-in. Dapatkan fingerprint lewat
kanal admin server terautentikasi, bukan endpoint identity yang belum dipercaya.
`GET https://HOST:PORT/v1/nac/identity` adalah satu-satunya request dengan verifikasi
TLS dinonaktifkan, tanpa code/CSR/proxy/redirect. Respons v1 memuat `ca_der_b64`
dan `bootstrap_pin`. Fingerprint lowercase SHA256:

```
eguard-nac-identity/v1\x00 || CA_DER || raw_ed25519_public_key_32_bytes
```

Mismatch menolak sebelum code dikirim. Selanjutnya CA dipin, hostname/SAN normal,
POST `/v1/nac/enroll` membawa platform linux/darwin. Windows menghilangkan platform.
`enrollment-identity.json` menyimpan server/CA/pin/fingerprint; startup menghitung
ulang fingerprint dan memverifikasi signed bootstrap menunjuk CA/origin yang sama.
Root dapat mengganti seluruh trust sekaligus; bukan proteksi terhadap root/offline.

## Lokasi dan keamanan

| OS | Root 0700 (journal.db, key, config) | Binary dan CLI |
|---|---|---|
| Linux | `/var/lib/eguard-nac` | `/usr/lib/eguard-nac/eguard-nac-service`, `/usr/bin/eguard-nac` |
| macOS | `/Library/Application Support/eGuard NAC` | `/Library/eGuard NAC/eguard-nac-service`, `/usr/local/bin/eguard-nac` |

Key ECDSA P-256 PEM 0600 **file-protected, bukan hardware-bound**. TPM2 serta
Keychain/Secure Enclave belum tersedia. Path/permission checks belum handle-pinned
terhadap ancestor symlink/TOCTOU. Root/offline disk dapat mengubah state dan jam.
Service memakai child self executable fixed verbs dengan stdin gate, process-group
boundary dan deadline; command provider fixed argv, timeout 5 detik, output terbatas.
Unknown/error tidak berubah menjadi bukti compliant; cancel tidak memperpanjang TTL.

## Evidence per OS

| Field | Linux | macOS |
|---|---|---|
| Host/OS | hostname, os-release | scutil ComputerName, sw_vers |
| Adapter | net.Interfaces, default IPv4 /proc/net/route | net.Interfaces, route default interface |
| VPN opt-in (`vpn`) | raw net.Interfaces, UP + non-link-local IP; wg/tun/tailscale/zt/IPsec/PPP | raw net.Interfaces, UP + IPv4 non-link-local atau IPv6 global unicast; utun/IPsec/PPP |
| Domain | sssd domains, krb5 default_realm, realm list | dsconfigad -show |
| Firewall | nft ruleset, ufw status, firewalld state | socketfilterfw global state |
| Disk encryption | root dm UUID CRYPT- (field wire bitlocker_os, source luks) | FileVault fdesetup |
| Secure Boot | efivar SecureBoot byte | Unknown |
| Reboot | reboot-required, No bila parent dapat dibaca dan marker tidak ada | Unknown |
| AV | ClamAV unit + signature mtime <7 hari; mdatp health; unit CrowdStrike/SentinelOne/Sophos/ESET/Trellix | XProtect plist versi/mtime <30 hari; Defender health; app bundle CrowdStrike/SentinelOne/Sophos/ESET |
| Software opt-in | dpkg-query atau rpm query | XML Info.plist /Applications/*.app |
| User opt-in | loginctl list-sessions, satu user snapshot | belum tersedia |

Inventory hanya bila signed config mengaktifkan; 800 entri, teks 128 byte,
deduplikasi name/version. Binary plist dilewati. Tidak ada system_profiler berat.
Domain konfigurasi bukan bukti live join. nft ruleset nonempty bukan audit kebijakan
packet filtering. Tidak ada route IPv6 Linux. LUKS berlapis/LVM dapat Unknown.
Tidak ada fallback mokutil/needs-restarting/iptables. Tidak semua distro/product
unit/path didukung. Third-party presence bukan bukti running/updated. Status unit
command error tetap Unknown (termasuk exit nonzero inactive). XProtect mtime bukan
jaminan signature vendor terbaru dan running tetap Unknown. App launchd-only belum
dideteksi. Gatekeeper dikirim sebagai evidence tambahan, bukan firewall jaringan.

VPN evidence terpisah dari `adapters` (tunnel tetap bukan aset). Hanya dikirim
bila payload signed bootstrap config v1 memuat `"report_vpn":"on"`; absent atau
`"off"` menghilangkan seluruh field `vpn` agar kompatibel dengan validator server
lama. Server/operator hanya boleh menandatangani ON setelah validator posture
server mendukung field ini. Nilai lain ditolak saat verifikasi config. Tidak ada
flag lokal/env atau pemeriksaan proses/aktivitas pengguna.

`vpn.connected` = `yes` bila interface VPN/tunnel UP dengan IP usable, `no` bila
snapshot berhasil tanpa koneksi, `unknown` bila enumerasi gagal (atau alamat VPN
UP tidak dapat dibaca tanpa bukti koneksi lain). `products` berisi heuristik nama/
deskripsi interface aktif, dedup maksimal 8 nama tetap (masing-masing <=64 byte),
bukan bukti produk/proses berjalan. `tun*` dilabeli `OpenVPN/TUN`, Wintun generik
`Wintun-based VPN`. Pada Windows sumbernya `GetAdaptersAddresses` yang sudah
tersedia; Unix `net.Interfaces`. Tidak ada command tambahan.

macOS `utun0..utun3` sering milik sistem/iCloud Private Relay: tanpa IP atau hanya
`fe80::` tidak dihitung. utun UP dengan IPv4 non-link-local atau IPv6 global
unicast dihitung, tetapi tetap tidak dapat membedakan Private Relay dari VPN
pengguna. Tidak mendeteksi VPN tanpa tunnel yang dikenali (mis. browser proxy).
Contoh bagian JSON opt-in:

```json
{"vpn":{"connected":"yes","products":["macOS VPN (utun)"],"source":"net.Interfaces"}}
```

Produk NAC-only posture/inventory/status: tidak ada EDR, kernel driver, remote shell,
arbitrary command execution atau monitoring aktivitas pengguna.

## Uninstall dan expiry

```sh
sudo eguard-nac uninstall
sudo eguard-nac uninstall --token <TOKEN>
sudo eguard-nac uninstall --authorization /path/authorization.json
# Linux setelah cleanup sukses:
sudo dpkg -r eguard-nac-agent
# atau sudo rpm -e eguard-nac-agent
```

Signed Anti-Tamper ON memerlukan authorization signed device-bound, singkat,
handoff ke service untuk replay/sequence checks. OFF mengizinkan root lokal.
Temporary expiry cleanup langsung dari verified lifecycle setelah journal/key
handle ditutup, tidak melewati gate anti-tamper. Linux disable, hapus root/key,
kemudian stop; binary tetap package-owned, hapus melalui package manager.
macOS hapus plist/root/key/CLI/install dir lalu bootout system/id.eguard.nac.
Urutan menghapus state sebelum stop sendiri menghindari proses mati sebelum cleanup;
namun kegagalan stop/bootout/permission tetap memerlukan recovery operator.
Prerm Linux menolak **semua enrolled roots**, lebih ketat daripada hanya ON;
uninstall dahulu. Force purge oleh root tidak dapat dicegah.

## Build, signing, release

```sh
GOFLAGS= GOPROXY=https://proxy.golang.org go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.1
scripts/build-unix-packages.sh 1.2.3
```

Binary linux/darwin amd64/arm64 CGO-disabled; nfpm menghasilkan empat paket Linux
ke dist/unix (gitignored). Export GPG_KEY_FILE untuk signing serta
NFPM_DEB_PASSPHRASE / NFPM_RPM_PASSPHRASE bila key terenkripsi. Tanpa key unsigned.
Universal lipo hanya CI macOS. build-pkg.sh memakai codesign identifier id.eguard.nac,
hardened runtime, productsign, notarytool --wait (ASC key preferred, Apple ID fallback),
stapler. Env kosong melewati signing; unsigned bukan klaim publisher terpercaya.
Workflow release-nac-agent.yml: tag nac-v* / dispatch version, test/linux/macos/
windows-binaries/release; Windows hanya binary, bukan installer netral.
Manifest eguard-nac-agent-release.json, SHA256SUMS dan CycloneDX SBOM disertakan.
SBOM generator masih berlabel TEST-UNSIGNED secara konservatif walau signing aktif.

## Publikasi paket ke server eGuard

Pada mesin operator (bukan agent host), verifikasi checksum dan signature dahulu.
Ganti 1.2.3 dengan versi release yang sama di manifest. Salin lima file berikut:

```sh
scp eguard-nac-agent_1.2.3_amd64.deb eguard-nac-agent_1.2.3_arm64.deb \
 eguard-nac-agent-1.2.3-1.x86_64.rpm eguard-nac-agent-1.2.3-1.aarch64.rpm \
 eGuard-NAC-1.2.3.pkg admin@gateway:/tmp/nac-packages/
# Pada server, setelah memverifikasi ulang checksum/signature:
sudo install -d -m 0755 /usr/local/eg/share/nac-agent/
sudo install -m 0644 /tmp/nac-packages/eguard-nac-agent_1.2.3_amd64.deb \
 /tmp/nac-packages/eguard-nac-agent_1.2.3_arm64.deb \
 /tmp/nac-packages/eguard-nac-agent-1.2.3-1.x86_64.rpm \
 /tmp/nac-packages/eguard-nac-agent-1.2.3-1.aarch64.rpm \
 /tmp/nac-packages/eGuard-NAC-1.2.3.pkg /usr/local/eg/share/nac-agent/
```

Buat staging /tmp/nac-packages di server sebelum scp. Publikasi/static download
routing, permission dan fingerprint admin server tetap tanggung jawab operator;
agent tidak mengubah server. Jangan mengganti pola nama file di atas.

## Validasi lokal

Parser Linux/macOS RED (fungsi belum ada) lalu GREEN. Fixture provider memakai
t.TempDir + runner palsu; tidak membaca provider nyata. Cleanup exact-command tests
untuk kedua OS; uninstall signed gate diuji paket uninstall/servicefactory.
Race suite seluruh modul, vet linux/darwin/windows dan CGO-disabled build
linux amd64/arm64, darwin amd64/arm64, windows amd64 lulus. YAML parse dan actionlint
v1.7.7 lulus. nfpm v2.41.1 berhasil didapat; empat paket 0.0.0-dev dibangun;
kedua DEB diinspeksi dpkg-deb -c/-I. rpm tool tidak tersedia untuk -qlp.
macOS pkg build/sign/notarize/install, runtime systemd/launchd dan release CI NOT RUN.

## Upgrade in-place (admin lokal)

Gunakan installer/paket versi baru dari publisher yang sama, dengan elevasi/root.
Tidak perlu izin server atau kode enrollment baru. Upgrade hanya mengganti biner;
konfigurasi, identitas, kredensial (termasuk CNG), journal, mode Temporary/Permanent,
expiry dan pilihan Anti-Tamper dipertahankan: tidak reset dan tidak diperpanjang.
Uninstall tetap mengikuti aturan lama: Anti-Tamper ON memerlukan authorization signed.

- Cek versi: `eguard-nac version` (Unix), `nac-setup version` (Windows).
- Versi baru wajib semver valid dan lebih tinggi. Downgrade ditolak. Versi sama
  hanya dengan opsi eksplisit reinstall, bukan enrollment ulang. Biner legacy tanpa
  stamp/perintah version (termasuk paket lama 0.6.1), atau `0.0.0-dev`, dianggap
  versi tidak diketahui dan lebih lama dari versi baru valid apa pun.
- Windows: jalankan installer baru sebagai Administrator; service eGuardNAC dan
  root provisioning existing mengarahkan wizard ke upgrade tanpa halaman kode.
  Alternatif: `nac-setup upgrade <service.exe-baru> [--reinstall]`. Preflight
  memverifikasi provisioning signed dan konfigurasi service persis; stop, backup
  `.prev`, copy, start dan readiness stabil 10 detik. Kegagalan replacement/start/
  readiness mencoba mengembalikan biner lama dan start lagi. Error rollback/DACL
  dilaporkan: jangan menganggap rollback berhasil hanya karena helper selesai.
  Anti-Tamper ON: DACL dilonggarkan sementara untuk stop dan wajib dipulihkan;
  pilihan bootstrap tidak diubah. `.prev` terakhir disimpan untuk recovery.
- Linux: `sudo dpkg -i <paket-baru.deb>` atau `sudo rpm -U <paket-baru.rpm>`.
  Hook upgrade stop tanpa menghapus state/disable service, kemudian daemon-reload
  dan start hanya bila enrolled. Install fresh tidak start. Untuk versi sama,
  `sudo env EGUARD_NAC_REINSTALL=1 dpkg -i ...` (atau `rpm -U --replacepkgs ...`).
  Remove/purge tetap menolak selama enrolled. **Batas migrasi legacy:** prerm dari
  paket lama yang sudah terpasang dan menolak argumen upgrade tidak dapat diperbaiki
  secara retroaktif oleh paket baru; jalur migrasi paket tersebut perlu diuji dan
  dikelola admin sebelum rollout, tanpa menghapus state atau bypass uninstall.
- macOS: `sudo installer -pkg <paket-baru.pkg> -target /`. Preinstall bootout
  daemon enrolled (error not-loaded diabaikan), postinstall memperbaiki symlink CLI
  dan bootstrap kembali. Fresh install tidak load. Reinstall versi sama memakai
  `sudo env EGUARD_NAC_REINSTALL=1 installer -pkg ... -target /`.
- Paket Unix memeriksa versi sebelum unpack; gunakan package manager standar,
  jangan copy biner manual atau menjalankan hook terpisah. OS package trust/signing
  adalah batas publisher; helper bukan pengganti verifikasi signature distribusi.
  Build evaluasi unsigned tetap bukan bukti publisher identity.

**Verifikasi upgrade saat ini hanya unit/fake/sandbox dan cross-build. Runtime
upgrade pada Windows, Linux dan macOS nyata belum diverifikasi.** Validasi paket
signed, service protection, readiness, failure recovery, dan preservation pada VM
berizin wajib sebelum produksi. Unix package manager tidak menyediakan rollback
biner otomatis seperti helper Windows; kegagalan start harus dipulihkan admin
menggunakan backup/paket yang telah diverifikasi tanpa mengubah provisioning.
