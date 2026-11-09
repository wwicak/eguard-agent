#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts dist
run() { local name="$1"; shift; local rc=0; "$@" >"artifacts/${name}.log" 2>&1 || rc=$?; printf '%s exit=%s\n' "$name" "$rc" | tee "artifacts/${name}.exit"; ((rc==0)) || exit "$rc"; }
run tests env GOPROXY=off GOSUMDB=off go test -count=1 ./...
run vet env GOPROXY=off GOSUMDB=off go vet ./...
run build env GOPROXY=off GOSUMDB=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/eguard-nac-service-TEST-UNSIGNED.exe ./cmd/nac-service
run inspect-build env GOPROXY=off GOSUMDB=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/eguard-nac-inspect-TEST-UNSIGNED.exe ./cmd/nac-inspect
run windows-test-compile env GOPROXY=off GOSUMDB=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -o dist/collector-TEST-UNSIGNED.test.exe ./collector
run windows-boundary-test-compile env GOPROXY=off GOSUMDB=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -o dist/boundary-TEST-UNSIGNED.test.exe ./boundary
run windows-journal-test-compile env GOPROXY=off GOSUMDB=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -o dist/journal-TEST-UNSIGNED.test.exe ./journal
run nsis bash -c 'cd installer/windows && makensis eguard-nac.nsi'
sha256sum dist/* > artifacts/SHA256SUMS
