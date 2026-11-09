# Harness acceptance Windows (VM disposable)

**Status: preflight saja. Runtime acceptance NOT RUN.** Installer NSIS saat ini hanya menyalin payload TEST-UNSIGNED ke TEMP untuk inspeksi; tidak memasang service atau enrollment. Harness ini tidak membuat installer menjadi fungsional. Jangan gunakan paket sebagai release/deployment. Produk NAC-only: posture/inventory perangkat/status untuk Access Policy, tanpa EDR atau enforcement lokal. Pilihan Anti-Tamper ON/OFF independen dari Temporary/Permanent masih memerlukan integrasi installer dan acceptance nyata. ON bukan proteksi terhadap administrator/SYSTEM; OFF tetap tidak memberi user biasa akses ke key/config; expiry/signature/TLS tetap wajib.

## Lingkup dan artefak

`acceptance-manifest.json` (schema_version 1) berisi path relatif `dist/`, checksum SHA256 hex kecil 64 karakter dan `signature_class` TEST-UNSIGNED atau SIGNED. Digest harus diperbarui secara terkontrol setiap build; mismatch adalah FAIL, bukan alasan menonaktifkan verifikasi. TEST-UNSIGNED hanya cocok bila Authenticode `NotSigned`; SIGNED hanya cocok bila `Valid`. Status tanda tangan **bukan** bukti publisher dipercaya untuk deployment. `acceptance-cases.json` (schema_version 1) adalah daftar ID wajib. `acceptance_validator.py` memeriksa schema/report dan melarang PASS tanpa evidence berstruktur (`kind`, `reference` tidak kosong). Validator offline tidak menguji keaslian evidence, tidak membuktikan eksekusi Windows dan tidak menilai hasil installer. Report JSON memisahkan `preflight.status` (PASS/FAIL) dari `runtime_acceptance` (selalu NOT RUN dalam harness ini). `os_acceptance` mencatat `WINDOWS11_CANDIDATE`, `WINDOWS10_OBSERVED_NOT_MVP`, atau `UNSUPPORTED_OR_UNKNOWN`; hanya kandidat Windows 11 workstation x64 dapat PASS pemeriksaan platform. Windows 10 Pro 19045 x64 yang teramati lewat akses read-only adalah Windows 10, **bukan** verifikasi MVP Windows 11; status dukungan/ESU belum ditentukan. Bahkan Windows 11 CANDIDATE bukan acceptance runtime. Semua pemeriksaan preflight wajib PASS agar preflight PASS; kegagalan satu item tetap FAIL. Operator opt-in adalah pencatatan intent untuk pengujian mutating **di masa depan**, bukan izin menjalankan mutasi sekarang.

## Operator VM

Gunakan Windows 11 x64 VM snapshot disposable dengan izin eksplisit, terminal Windows PowerShell 5.1 elevated dan salinan artefak dari build yang diaudit. VM Windows 10 yang teramati belum terkonfirmasi snapshot-nya: jangan jalankan harness atau menyalin artefak ke sana tanpa persetujuan tambahan. Siapkan file manifest sesuai SHA256 paket yang benar; jangan ambil file dari network melalui harness. Dari root repo di VM:

```powershell
powershell.exe -NoProfile -File .\scripts\windows\invoke-acceptance-preflight.ps1 -ReportPath .\preflight-vm.json -ManifestPath .\scripts\windows\acceptance-manifest.json -CasesPath .\scripts\windows\acceptance-cases.json -DisposableVmOperatorOptIn
python .\scripts\windows\acceptance_validator.py .\scripts\windows\acceptance-manifest.json .\scripts\windows\acceptance-cases.json .\preflight-vm.json
```

Hilangkan switch opt-in jika VM/izin belum siap; hasil gate FAIL. Gunakan nama report baru tiap run; output tidak menulis username, token, sertifikat, atau evidence sensitif. Script hanya membaca versi OS/arsitektur, membership admin (boolean), file hash dan status Authenticode, lalu menulis satu report ke path baru. Tidak menjalankan installer/payload, uninstall, layanan, ACL, key, policy, atau network. Snapshot VM dan backup tetap tanggung jawab operator. Tinjau report sebelum membagikannya. Jika PowerShell tidak tersedia, parser/runtime PowerShell **NOT RUN**; jangan laporkan PASS. Jika Python tidak ada di VM, validator dapat dijalankan secara offline pada report yang dipindahkan secara aman; tetap bukan bukti runtime Windows.

## Matriks runtime yang belum diuji

Semua ID berikut wajib ada di report tetapi tetap NOT RUN: `clean_install`, `upgrade_rollback`, `temporary_on`, `temporary_off`, `permanent_on`, `permanent_off`, `expiry_offline_reboot_clock`, `standard_user_tamper`, `authorized_uninstall`, `cleanup`, `coexist_edr`. Empat kombinasi mode/proteksi harus diuji terpisah pada installer fungsional dan VM berizin kelak. Termasuk negative tests user biasa vs elevated admin, perubahan pilihan lokal, repair/downgrade, deadline offline/reboot/jam, cleanup milik NAC saja dan EDR coexist. Jangan mengubah `NOT RUN` menjadi `PASS` hanya karena preflight berhasil. Pengujian mutating memerlukan desain/script dan izin baru, snapshot/rollback, signed provisioning dan produk yang benar-benar fungsional; bukan bagian harness ini.

## Uji validator di Linux

```sh
python3 -m unittest discover -s scripts/windows -p 'test_acceptance_validator.py' -v
```

Uji ini hanya menolak report/schema buruk dan menjaga kontrak lokal, termasuk pemeriksaan teks sumber atas grammar PowerShell (bukan eksekusi PowerShell). Parser/runtime Windows PowerShell 5.1 masih NOT RUN. Guard path komponen tidak membuktikan keamanan reparse point/ACL; manifest saat ini menunjuk installer lama inspection-only TEST-UNSIGNED. Jangan mengubah `signature_class` untuk mengesahkannya.
