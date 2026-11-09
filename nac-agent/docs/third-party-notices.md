# Dependency dan atribusi

Tidak ada sumber EDR disalin. Sumber `eguard-agent-v15-av` read-only digunakan sebagai referensi arsitektur saja (workspace menyatakan GPL-2.0-or-later); jangan mengambil file tanpa peninjauan kompatibilitas lisensi. Modul Go binary ini:

| Modul | Versi | Lisensi upstream | Kegunaan |
| --- | --- | --- | --- |
| `go.etcd.io/bbolt` | v1.4.3 | MIT | Journal transaksi lokal (lisensi upstream: `go.etcd.io/bbolt@v1.4.3/LICENSE`) |
| `golang.org/x/sys` | v0.47.0 | BSD-3-Clause | Windows IP Helper, NetAPI, SCM/eventlog |
| `github.com/go-ole/go-ole` | v1.3.0 | MIT | COM firewall, transitive WMI |
| `github.com/StackExchange/wmi` | v1.2.1 | MIT | Query WMI lokal read-only |

Lisensi upstream asli berada di direktori masing-masing modul Go dalam module cache; pemeriksaan lisensi dan SBOM release perlu diulang saat dependency di-update. Tidak ada EDR/WFP/eBPF/remote shell/command-execution module dalam `go list -m all`. Go standard library mengikuti lisensi Go BSD-style. Cross-build tidak membuktikan runtime/keamanan Windows.
