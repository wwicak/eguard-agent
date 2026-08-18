# Scenario 02–03 synthetic acceptance test (Windows)

Use only on the isolated Windows VM. The fixture generator uses synthetic values;
do not substitute customer data, production documents, or a production tenant key.

## Preconditions

1. Install a **fresh MSI built from the current `feat/dlp` source**. The older
   `0.2.94` installer does not contain fingerprint classification.
2. Confirm the service is the newly-built Agent:

```powershell
Get-CimInstance Win32_Service -Filter "Name='eGuardAgent'" |
  Select-Object Name, State, PathName
```

3. Work in a disposable VM directory:

```powershell
$Root = 'C:\DlpAcceptance'
New-Item -ItemType Directory -Force -Path $Root | Out-Null
```

## Create the synthetic pack and fixtures

From the repository checkout containing the current source:

```powershell
cd $env:USERPROFILE\eguard-agent-test
python scripts\build_dlp_fingerprint_fixture.py --output C:\DlpAcceptance
```

Expected files:

```text
C:\DlpAcceptance\fingerprint.key
C:\DlpAcceptance\fingerprint-pack.json
C:\DlpAcceptance\structured-positive.json
C:\DlpAcceptance\unstructured-positive.txt
C:\DlpAcceptance\negative.txt
```

Keep `fingerprint.key` endpoint-local. Do not upload it or paste it into logs.

## Configure the Agent

Add or update the `[detection]` section of the Agent's active config
(`C:\ProgramData\eGuard\agent.conf` by default):

```toml
[detection]
dlp_enabled = true
dlp_rules_path = "C:\\ProgramData\\eGuard\\dlp\\indonesia.json"
dlp_fingerprint_pack_path = "C:\\DlpAcceptance\\fingerprint-pack.json"
dlp_fingerprint_key_path = "C:\\DlpAcceptance\\fingerprint.key"
dlp_max_file_scan_size_mb = 10
```

The normal Indonesia DLP rule pack remains required because the Agent keeps
its existing scanner active while adding fingerprint classification.

Restart only the Agent service:

```powershell
Restart-Service eGuardAgent
Get-Service eGuardAgent
```

Expected: `Status` is `Running`.

## Test Scenario 02: structured record

Trigger a new write of the synthetic JSON record:

```powershell
Copy-Item C:\DlpAcceptance\structured-positive.json C:\DlpAcceptance\structured-trigger.json -Force
```

Expected redacted DLP rule ID:

```text
classification.structured_fingerprint
```

## Test Scenario 03: unstructured document

Trigger a new write of the synthetic text:

```powershell
Copy-Item C:\DlpAcceptance\unstructured-positive.txt C:\DlpAcceptance\unstructured-trigger.txt -Force
```

Expected redacted DLP rule ID:

```text
classification.unstructured_fingerprint
```

## Negative control

Write the unrelated synthetic fixture:

```powershell
Copy-Item C:\DlpAcceptance\negative.txt C:\DlpAcceptance\negative-trigger.txt -Force
```

Expected: no classification fingerprint detection.

## Verify only redacted events

In the Admin UI, use **DLP only** filtering. Or query the existing event API:

```text
GET /api/v1/endpoint/events?event_type=dlp_detection
```

Pass criteria:

- Structured positive emits `classification.structured_fingerprint`.
- Unstructured positive emits `classification.unstructured_fingerprint`.
- Negative control emits neither classification rule ID.
- Each event remains `audit` or `alert`; never `block` or `isolate`.
- Event metadata does not contain the JSON values, document text, or key.

## Cleanup

Disable the temporary fingerprint inputs, restart the service, and remove the
synthetic test folder:

```powershell
# Remove the two fingerprint path lines from [detection], then:
Restart-Service eGuardAgent
Remove-Item C:\DlpAcceptance -Recurse -Force
```

Do not delete the normal Agent rule pack or change firewall, proxy,
certificate, host-isolation, or Internet settings.

## If no event appears

1. Verify the fresh installer contains the current source; do not test with
   the stale MSI.
2. Confirm `eGuardAgent` is running after the config change.
3. Confirm the normal DLP rules path, pack path, and key path all exist and
   are readable by `LocalSystem`.
4. Create a new trigger file name; do not overwrite a stale event.
5. Check Agent logs for `DLP fingerprint pack reloaded` or a rejected-pack
   warning. A malformed/empty key or invalid pack keeps the prior policy.

This test is audit/alert-only. It does not authorize blocking, interception,
firewall changes, TLS inspection, or host isolation.
