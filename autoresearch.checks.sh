#!/usr/bin/env bash
# Windows autoresearch checks — runs Go tests for the server-side IOC rules
set -euo pipefail
cd /home/dimas/fe_eguard/go
go test ./agent/server -run 'TestMatchServerSideIOCRulesDetectsWindows|TestAgentInstallWindows|TestHaproxyAdmin|TestServerSideIOCRuleFromThreatIntelRuleJSON' -count=1
