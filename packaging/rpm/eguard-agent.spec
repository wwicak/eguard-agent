Name: eguard-agent
Version: 0.1.0
Release: 1
Summary: eGuard endpoint agent scaffold
License: GPLv2+
BuildArch: x86_64

%description
eGuard endpoint agent scaffold package.

%package rules
Summary: Optional initial rule bundle for eGuard endpoint agent
Requires: eguard-agent = %{version}-%{release}

%description rules
Optional initial SIGMA/YARA/IOC bundle package for eGuard endpoint agent.

%post
# Ensure nf_tables kernel module loads at boot (needed for nftables-based
# network isolation on Fedora/RHEL 9+ where iptables-legacy is blocked by SELinux).
install -d -m 0755 /etc/modules-load.d
echo "nf_tables" > /etc/modules-load.d/eguard-agent.conf 2>/dev/null || true
modprobe nf_tables 2>/dev/null || true

# Protect config from deletion via immutable flag.
chattr +i /etc/eguard-agent/agent.conf 2>/dev/null || true

# Enable and start service.
systemctl daemon-reload 2>/dev/null || true
systemctl enable eguard-agent 2>/dev/null || true
systemctl restart eguard-agent 2>/dev/null || true

%preun
# Remove immutable flag before uninstall so rpm can clean up.
chattr -i /etc/eguard-agent/agent.conf 2>/dev/null || true

%files
/usr/bin/eguard-agent
/usr/lib/eguard-agent/ebpf/process_exec_bpf.o
/usr/lib/eguard-agent/ebpf/file_open_bpf.o
/usr/lib/eguard-agent/ebpf/file_write_bpf.o
/usr/lib/eguard-agent/ebpf/file_rename_bpf.o
/usr/lib/eguard-agent/ebpf/file_unlink_bpf.o
/usr/lib/eguard-agent/ebpf/tcp_connect_bpf.o
/usr/lib/eguard-agent/ebpf/dns_query_bpf.o
/usr/lib/eguard-agent/ebpf/module_load_bpf.o
/usr/lib/eguard-agent/ebpf/lsm_block_bpf.o
/usr/lib/eguard-agent/ebpf-perf/process_exec_bpf.o
/usr/lib/eguard-agent/ebpf-perf/file_open_bpf.o
/usr/lib/eguard-agent/ebpf-perf/file_write_bpf.o
/usr/lib/eguard-agent/ebpf-perf/file_rename_bpf.o
/usr/lib/eguard-agent/ebpf-perf/file_unlink_bpf.o
/usr/lib/eguard-agent/ebpf-perf/tcp_connect_bpf.o
/usr/lib/eguard-agent/ebpf-perf/dns_query_bpf.o
/usr/lib/eguard-agent/ebpf-perf/module_load_bpf.o
/usr/lib/eguard-agent/ebpf-perf/lsm_block_bpf.o
/usr/lib/eguard-agent/lib/libeguard_asm.a
/var/lib/eguard-agent/baselines/seed.bin
/usr/lib/systemd/system/eguard-agent.service
/etc/eguard-agent/agent.conf
/var/lib/eguard-agent/rules/sigma/credential_access.yml
/var/lib/eguard-agent/rules/sigma/default_webshell.yml
/var/lib/eguard-agent/rules/sigma/windows_lateral_movement_service_exec.yml
/var/lib/eguard-agent/rules/sigma/windows_lsass_access_dump.yml
/var/lib/eguard-agent/rules/sigma/windows_powershell_download_cradle.yml
/var/lib/eguard-agent/rules/sigma/windows_registry_runkey_persistence.yml
/var/lib/eguard-agent/rules/sigma/windows_uac_bypass_signals.yml
/var/lib/eguard-agent/rules/yara/default.yar
/var/lib/eguard-agent/rules/ioc/default_ioc.txt

%files rules
/var/lib/eguard-agent/rules/sigma/credential_access.yml
/var/lib/eguard-agent/rules/sigma/default_webshell.yml
/var/lib/eguard-agent/rules/sigma/linux_data_staging_archive.yml
/var/lib/eguard-agent/rules/sigma/linux_download_exec.yml
/var/lib/eguard-agent/rules/sigma/linux_ld_preload_defense_evasion.yml
/var/lib/eguard-agent/rules/sigma/linux_persistence_cron_systemd.yml
/var/lib/eguard-agent/rules/sigma/linux_reverse_shell_devtcp.yml
/var/lib/eguard-agent/rules/sigma/linux_ssh_lateral_movement.yml
/var/lib/eguard-agent/rules/sigma/windows_amsi_bypass_reflection.yml
/var/lib/eguard-agent/rules/sigma/windows_bits_notifycmdline_persistence.yml
/var/lib/eguard-agent/rules/sigma/windows_certutil_download.yml
/var/lib/eguard-agent/rules/sigma/windows_certutil_encode.yml
/var/lib/eguard-agent/rules/sigma/windows_com_hijack_registry.yml
/var/lib/eguard-agent/rules/sigma/windows_csc_lolbin.yml
/var/lib/eguard-agent/rules/sigma/windows_defender_disable.yml
/var/lib/eguard-agent/rules/sigma/windows_ifeo_debugger_persistence.yml
/var/lib/eguard-agent/rules/sigma/windows_installutil_lolbin.yml
/var/lib/eguard-agent/rules/sigma/windows_lateral_movement_service_exec.yml
/var/lib/eguard-agent/rules/sigma/windows_lsass_access_dump.yml
/var/lib/eguard-agent/rules/sigma/windows_msbuild_lolbin.yml
/var/lib/eguard-agent/rules/sigma/windows_mshta_lolbin_download.yml
/var/lib/eguard-agent/rules/sigma/windows_powershell_download_cradle.yml
/var/lib/eguard-agent/rules/sigma/windows_registry_runkey_persistence.yml
/var/lib/eguard-agent/rules/sigma/windows_taskkill_eguard_tamper.yml
/var/lib/eguard-agent/rules/sigma/windows_uac_bypass_signals.yml
/var/lib/eguard-agent/rules/sigma/windows_wmi_event_subscription_persistence.yml
/var/lib/eguard-agent/rules/yara/default.yar
/var/lib/eguard-agent/rules/ioc/default_ioc.txt
