#!/bin/sh
set -e

action="${1:-}"
case "$action" in
    upgrade|failed-upgrade|1)
        exit 0
        ;;
esac

# Backward compatibility for packages that previously made the config immutable.
chattr -i /etc/eguard-agent/agent.conf 2>/dev/null || true

if [ -d /run/systemd/system ]; then
    dropin_dir=/run/systemd/system/eguard-agent.service.d
    dropin="$dropin_dir/zz-package-uninstall.conf"
    stopped_service=0
    preremove_ok=0
    cleanup() {
        rm -f "$dropin"
        rmdir "$dropin_dir" 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        # If we took the agent down but removal did NOT complete (interrupted, or a
        # fail-closed abort), the package stays installed while an explicit stop has
        # suppressed Restart=. Bring the agent back so the host is never left
        # installed-but-unprotected. `start` is a no-op if it is already running.
        if [ "$stopped_service" = 1 ] && [ "$preremove_ok" != 1 ]; then
            systemctl start eguard-agent.service 2>/dev/null || true
        fi
    }
    # Arm cleanup traps BEFORE the weakening drop-in exists on disk so there is no
    # window in which the RefuseManualStop=no override is present without a handler
    # that removes it. On a signal, IGNORE further HUP/INT/TERM/EXIT for the rest of
    # teardown so a signal storm cannot terminate the shell (default disposition)
    # before cleanup completes; cleanup runs once, then we exit nonzero so the
    # package manager treats removal as not authorized.
    trap 'cleanup' EXIT
    trap 'trap "" HUP INT TERM EXIT; cleanup; exit 1' HUP INT TERM
    mkdir -p "$dropin_dir"
    printf '[Unit]\nRefuseManualStop=no\n\n[Service]\nRestart=no\n' > "$dropin"
    systemctl daemon-reload

    stopped_service=1
    if ! systemctl stop eguard-agent.service; then
        echo "refusing to remove while agent is still running: systemd stop failed" >&2
        exit 1
    fi

    stopped=false
    i=0
    while [ "$i" -lt 10 ]; do
        if ! pid=$(systemctl show -p MainPID --value eguard-agent.service 2>/dev/null); then
            echo "refusing to remove while agent state is unknown" >&2
            exit 1
        fi
        if [ "$pid" = 0 ]; then
            stopped=true
            break
        fi
        i=$((i + 1))
        sleep 1
    done
    if [ "$stopped" != true ]; then
        echo "refusing to remove while agent is still running (MainPID=$pid)" >&2
        exit 1
    fi

    systemctl disable eguard-agent.service || true
    # All pre-removal steps completed. Commit to a NON-INTERRUPTIBLE success boundary:
    # ignore signals before setting the success flag so an interrupt during the final
    # EXIT cleanup cannot flip this authorized removal into a nonzero (aborted) exit
    # while the restart-on-abort restore is suppressed. The EXIT trap still runs
    # cleanup (drop-in removal + daemon-reload) uninterrupted; the agent stays down
    # for erasure and the script exits 0 so removal proceeds.
    trap '' HUP INT TERM
    preremove_ok=1
fi
