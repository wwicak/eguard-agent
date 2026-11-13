# In-place upgrade progress

Scope: local elevated/root publisher installer only, no server authorization or enrollment for upgrade. INSTALL rejection and signed uninstall authorization remain unchanged. No real service/package operations have been executed; all runtime evidence here is unit/sandbox only. Real Windows/Linux/macOS runtime upgrades are NOT verified.

## TDD evidence
- Version policy RED: `go test ./upgrade` failed `undefined: CheckVersion`. GREEN: valid strict semver, precedence (including numeric prerelease), downgrade/same-version denial, explicit reinstall, unknown legacy version tests pass.
- Sequence RED: `undefined: Run`. GREEN: fake steps verify preflight, relaxation, stop, backup, replacement, readiness, restoration and mandatory DACL re-protection on failures.
- Package scripts RED: sandbox tests showed upgrade disabled Linux service, enrolled removals ignored test state, no enrolled restart and no launchd bootout/bootstrap. All host-facing tools were faked even for RED. GREEN: all script fixtures pass and state bytes are unchanged.

## Boundaries
- Existing posture wire schema has no agent_version field; no wire field added.
- ProtectedSDDL permits admin start but not stop/configuration/WRITE_DAC. Upgrade must temporarily relax it and restore the signed selection even after failure.

- Unix version gate RED: missing `packaging/version-policy.sh`; GREEN: sandbox installed binaries cover higher/equal/reinstall/downgrade/legacy/prerelease/invalid versions. Policy is inlined into generated Linux/macOS preinstall scripts before unpack. No additional runtime dependency beyond POSIX shell/awk.
- Strengthened GREEN coverage checks real sandbox CLI symlink and plist mode, plus rollback stop/restore/restart failure reporting with final protection attempt. Old tests were not removed or weakened.

## Verification and limitations
- `/usr/local/go/bin/go test -race -count=1 ./...`: initial parallel run failed existing servicefactory delivery deadlines (host load average ~28/64/72); focused run also hit a delivery deadline. No tests changed. `GOMAXPROCS=2 go test -race -count=1 -p 1 ./...` then passed all packages, uncached. Initial cold-cache commands timed out before output and were rerun with longer limits.
- `gofmt -l .`: empty. `go vet ./...`, `GOOS=windows go vet ./...`, `GOOS=darwin go vet ./...`: passed.
- CGO_ENABLED=0 builds `./cmd/...`: linux amd64/arm64, darwin amd64/arm64, windows amd64 passed into a temporary /tmp directory, removed afterward. Native stamped binary `version` printed `1.2.3`.
- `bash -n`: all touched shell scripts passed (including extensionless pkg scripts). `actionlint` unavailable; not installed.
- No real dpkg/rpm/systemctl/launchctl or installer execution. No signed publisher artifacts, NSIS compilation, macOS pkgbuild/lipo, service ACL runtime or real OS upgrade verified here.
- Legacy Linux package caveat: the *already installed* old prerm may still reject upgrade before the new hook can help. This cannot be repaired retroactively by replacing the new package hook; it needs a separately validated admin migration/rollout procedure. State must never be deleted to bypass it.
- Package publisher verification belongs to the trusted signed distribution/OS installer path; current unsigned evaluation artifacts cannot establish same-publisher cryptographic identity. Windows helper only executes fixed `version` on the local admin-selected binary, not arbitrary commands or server instructions.

### Final rerun
- Exact requested `/usr/local/go/bin/go test -race ./...` subsequently passed every package (including servicefactory); serial uncached pass above is retained as additional evidence. No timeout/test thresholds were changed.
- Final format, all three vet targets, five CGO-free cmd cross-build targets and shell syntax checks rerun successfully after readiness polling fix.
- Available `makensis` compiled the final NSIS source with dummy payload files and output under /tmp, then all fixtures/output removed. Only warning was the fixture output basename `setup.exe` (compatibility shim warning); no installer executed. NSIS all-users `$APPDATA` resolves the fixed ProgramData provisioning path.
