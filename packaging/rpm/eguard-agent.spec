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

# Clear legacy immutability before ownership changes or enrollment's atomic rename.
if [ -f /etc/eguard-agent/agent.conf ]; then
    chattr -i /etc/eguard-agent/agent.conf 2>/dev/null || true
    chown root:root /etc/eguard-agent/agent.conf
    chmod 0600 /etc/eguard-agent/agent.conf
fi

# Enable and cycle the MainPID; RefuseManualStop rejects systemctl restart.
systemctl daemon-reload 2>/dev/null || echo "eguard-agent: daemon-reload failed" >&2
systemctl enable eguard-agent 2>/dev/null || echo "eguard-agent: enable failed" >&2
old_pid=$(systemctl show -p MainPID --value eguard-agent 2>/dev/null || true)
target_version=$( (unset EGUARD_AGENT_VERSION; timeout 10 /usr/bin/eguard-agent --version 2>/dev/null | head -n 1) || true)
if systemctl is-active --quiet eguard-agent; then
    systemctl kill --kill-who=main -s TERM eguard-agent 2>/dev/null || echo "eguard-agent: TERM signal failed" >&2
else
    systemctl start eguard-agent 2>/dev/null || echo "eguard-agent: start failed" >&2
fi
verified=false
i=0
while [ "$i" -lt 30 ]; do
    pid=$(systemctl show -p MainPID --value eguard-agent 2>/dev/null || true)
    if [ -n "$pid" ] && [ "$pid" != 0 ] && [ "$pid" != "$old_pid" ] \
        && systemctl is-active --quiet eguard-agent \
        && [ "/proc/$pid/exe" -ef /usr/bin/eguard-agent ]; then
        live_version=$( (unset EGUARD_AGENT_VERSION; timeout 10 "/proc/$pid/exe" --version 2>/dev/null | head -n 1) || true)
        if [ -z "$target_version" ] || [ -z "$live_version" ] || [ "$live_version" = "$target_version" ]; then
            verified=true
            break
        fi
    fi
    i=$((i + 1))
    sleep 1
done
[ "$verified" = true ] || echo "eguard-agent: restart could not be verified on the installed binary" >&2
exit 0

%preun
# Immutable config protection was removed because it breaks replacement and enrollment rename.
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    dropin_dir=/run/systemd/system/eguard-agent.service.d
    dropin="$dropin_dir/zz-package-uninstall.conf"
    stopped_service=0
    preremove_ok=0
    cleanup() {
        rm -f "$dropin"
        rmdir "$dropin_dir" 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        # If we took the agent down but removal did NOT complete (interrupted or
        # fail-closed abort), the package stays installed while the explicit stop
        # suppressed Restart=. Bring the agent back so the host is never left
        # installed-but-unprotected. start is a no-op if it is already running.
        if [ "$stopped_service" = 1 ] && [ "$preremove_ok" != 1 ]; then
            systemctl start eguard-agent.service 2>/dev/null || true
        fi
    }
    # Arm cleanup traps BEFORE the weakening drop-in exists on disk so a signal in the
    # setup window cannot leave the RefuseManualStop=no override without a handler that
    # removes it. IGNORE further signals during teardown so a storm cannot terminate the
    # shell before cleanup completes.
    trap 'cleanup' EXIT
    trap 'trap "" HUP INT TERM EXIT; cleanup; exit 1' HUP INT TERM
    mkdir -p "$dropin_dir"
    printf '[Unit]\nRefuseManualStop=no\n\n[Service]\nRestart=no\n' > "$dropin"
    systemctl daemon-reload
    stopped_service=1
    systemctl stop eguard-agent.service || { echo "refusing to remove while agent is still running: systemd stop failed" >&2; exit 1; }
    stopped=false
    i=0
    while [ "$i" -lt 10 ]; do
        if ! pid=$(systemctl show -p MainPID --value eguard-agent.service 2>/dev/null); then
            echo "refusing to remove while agent state is unknown" >&2
            exit 1
        fi
        if [ "$pid" = 0 ]; then stopped=true; break; fi
        i=$((i + 1)); sleep 1
    done
    [ "$stopped" = true ] || { echo "refusing to remove while agent is still running (MainPID=$pid)" >&2; exit 1; }
    # All pre-removal steps completed. Commit to a NON-INTERRUPTIBLE success boundary:
    # ignore signals before the success flag so an interrupt during the final EXIT
    # cleanup cannot flip this authorized removal into a nonzero (aborted) exit while
    # the restart-on-abort restore is suppressed. EXIT cleanup still runs; the agent
    # stays down for erasure and %preun exits 0 so removal proceeds.
    trap '' HUP INT TERM
    preremove_ok=1
fi

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
