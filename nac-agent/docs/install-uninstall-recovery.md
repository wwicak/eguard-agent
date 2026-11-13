# Panduan Install, Uninstall, dan Recovery — eGuard NAC Agent 0.2.0 (TEST-UNSIGNED)

> Status: **build evaluasi, bukan produksi.** Belum ditandatangani (Authenticode), kunci bootstrap yang tertanam pada build lab adalah kunci uji. Gunakan hanya pada perangkat tester yang disetujui. Lihat `release-notes-0.2.0.md` untuk apa yang sudah dan belum diverifikasi.

## 1. Apa yang dipasang

| Komponen | Lokasi | Keterangan |
|---|---|---|
| Service `eGuardNAC` | `C:\Program Files\eGuard NAC\eguard-nac-service.exe` | LocalSystem, start Automatic |
| Konfigurasi bertanda tangan + journal | `C:\ProgramData\eGuard NAC\` | DACL terproteksi: SYSTEM + Administrators saja |
| Sertifikat mesin | `LocalMachine\My` | Kunci CNG non-exportable, dibuat di perangkat |
| Event source | Application log, sumber `eGuardNAC` | Catatan start/stop/cleanup |

Agent hanya mengumpulkan posture untuk NAC: adapter jaringan (MAC/IP), identitas perangkat, Domain Joined, AV installed/running/updated, firewall, waktu observasi. **Tidak** ada EDR, driver kernel, remote shell, eksekusi perintah, atau monitoring aktivitas pengguna. Keputusan akses dibuat server/perangkat jaringan.

## 2. Persiapan (admin eGuard)

1. Daftarkan perangkat di server eGuard, pilih **mode** (Temporary dengan masa berlaku, atau Permanent) dan **Anti-Tamper** (ON/OFF). Keduanya ditandatangani server di dalam bootstrap; tidak bisa diubah di perangkat.
2. Buat CSR mesin di perangkat (kunci tetap di perangkat), tandatangani di CA eGuard, terima sertifikat (`certreq -accept`). Rantai CA harus trusted di LocalMachine.
3. Unduh dua file: `bootstrap.json` dan `activation.json`. Activation berumur pendek; pasang segera.

## 3. Install

Jalankan sebagai Administrator:

```
eGuard-NAC-Setup-0.2.0-x64-TEST-UNSIGNED.exe /BOOTSTRAP=C:\path\bootstrap.json /ACTIVATION=C:\path\activation.json
```

Tambahkan `/S` untuk silent. Installer:
1. Menolak jika belum elevated, file tidak ada, atau eGuard NAC sudah terpasang (tidak menimpa diam-diam).
2. Memverifikasi tanda tangan, binding perangkat, dan masa berlaku activation.
3. Menulis konfigurasi, menyalin binary, mendaftarkan event source, membuat service.
4. Service harus tetap Running 10 detik (bukti factory terverifikasi berhasil). Jika ada langkah gagal, **semua langkah yang sudah dilakukan dibatalkan** dan exit code ≠ 0.
5. Jika Anti-Tamper ON: memasang DACL service terproteksi.

Verifikasi: `sc.exe query eGuardNAC` → RUNNING; server menerima posture (≈ tiap 30 detik pada konfigurasi lab).

Exit code: `0` sukses; `1` gagal & di-rollback; `2` parameter/file salah; `5` bukan Administrator.

## 4. Uninstall

### Anti-Tamper OFF
Administrator elevated:
```
"C:\path\nac-setup.exe" uninstall
```

### Anti-Tamper ON
1. Admin eGuard menerbitkan **izin uninstall** untuk perangkat ini (berlaku ≤ 10 menit, sekali pakai, terikat perangkat/tenant/site/enrollment).
2. Di perangkat, Administrator:
```
"C:\path\nac-setup.exe" uninstall C:\path\authorization.json
```
Izin palsu, untuk perangkat lain, kedaluwarsa, atau sudah dipakai → ditolak tanpa perubahan. Jika ditolak setelah service dihentikan, service dinyalakan kembali dan proteksi dipasang ulang.

`nac-setup.exe` diambil dari paket installer yang sama (ekstrak dengan 7-Zip) atau dari media rilis.

### Yang dihapus
Service → sertifikat + kunci CNG (fingerprint persis) → `C:\ProgramData\eGuard NAC` → binary. Binary yang sedang dipakai dijadwalkan dihapus saat **restart berikutnya**. Sumber daya lain (CA Root, aplikasi lain) tidak disentuh.

## 5. Mode Temporary

- Saat masa berlaku dari server habis dan perangkat **menyala**, agent berhenti mengirim posture dan menjalankan cleanup resmi sendiri (tanpa perlu izin uninstall; tidak dihalangi Anti-Tamper).
- Jika perangkat **mati** saat masa berlaku habis, cleanup dilakukan saat **boot berikutnya**, sebelum mengakses jaringan.
- Akses jaringan berakhir di server tepat pada deadline, terlepas dari kapan cleanup lokal berjalan.

## 6. Recovery admin (transparan)

Anti-Tamper meningkatkan usaha, **bukan kekebalan**. Administrator lokal/SYSTEM atau akses disk offline tetap dapat menghapus agent. Prosedur recovery resmi bila izin server tidak bisa didapat (mis. server tidak tersedia, perangkat rusak):

1. Catat alasan; recovery ini terlihat di server sebagai perangkat berhenti melapor.
2. Administrator elevated, PowerShell:
   ```
   # pulihkan DACL default service agar bisa dihentikan/dihapus
   sc.exe sdset eGuardNAC "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
   ```
   Jika `sdset` ditolak (DACL terproteksi tidak memberi WRITE_DAC ke Administrators), jalankan sebagai SYSTEM (mis. tugas terjadwal sekali-jalan sebagai SYSTEM) — ini perilaku Windows yang terdokumentasi, bukan backdoor.
3. `sc.exe stop eGuardNAC` lalu `sc.exe delete eGuardNAC`.
4. Hapus `C:\ProgramData\eGuard NAC` dan `C:\Program Files\eGuard NAC`.
5. Hapus sertifikat mesin eGuard NAC dari `LocalMachine\My` (certlm.msc) beserta kuncinya.
6. Di server: revoke enrollment perangkat tersebut.

## 7. Batas yang diketahui

- Build ini TEST-UNSIGNED; SmartScreen/AV dapat memberi peringatan.
- Uji runtime dilakukan pada Windows 10 Pro 19045 (VM tester). Windows 11 belum diverifikasi.
- INSTALL baru tetap menolak existing; gunakan jalur upgrade terpisah di bawah.
- Perubahan jam: rollback jam terdeteksi in-process; latch jam tahan reboot belum ada.

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
