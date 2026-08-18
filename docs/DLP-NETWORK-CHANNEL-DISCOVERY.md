# DLP network, email, and chat channel discovery

## Decision

Current Windows Agent telemetry is suitable for **connection and DNS observation only**:

- ETW `TcpConnect` provides destination IP and port.
- ETW DNS Client events provide the queried domain.
- Process identity is available through the existing enriched event flow.

It is **not** a content-inspection channel. The Agent does not parse HTTP,
HTTPS, SMTP, FTP, chat, browser upload, or cloud-upload payloads.

## Current safe capability

| Signal | Available | DLP use allowed now |
| --- | --- | --- |
| TCP connect | Yes | Audit connection metadata only. |
| DNS query | Yes | Audit domain metadata only. |
| Process identity | Yes | Correlate to existing endpoint telemetry only. |
| HTTP/HTTPS body | No | Not implemented. |
| SMTP/FTP body | No | Not implemented. |
| Chat/browser/cloud content | No | Not implemented. |
| TLS decryption / SSL inspection | No | Prohibited without separate approval. |
| Network enforcement | No | Out of scope. |

## Privacy boundary

- Do not capture request/response bodies, credentials, cookies, message text,
  attachments, or TLS plaintext.
- Do not add a root certificate, proxy, packet filter, firewall rule, host
  isolation, or network block path.
- Existing DLP events remain `audit` or `alert` only and retain redacted
  evidence.

## Future implementation gate

A future protocol channel needs all of the following before code is added:

1. An approved platform API/hook for that application or protocol.
2. Privacy/legal review covering scope, retention, consent, and redaction.
3. A bounded synthetic corpus and false-positive test plan.
4. A per-channel performance budget and rollback/kill switch.
5. Separate explicit authorization for any decryption, interception, or
   enforcement work.

## Test plan for current metadata observation

1. Generate a synthetic TCP connection and DNS lookup from a disposable Windows
   VM process.
2. Confirm the existing telemetry contains only process identity, destination
   IP/port, and DNS domain metadata.
3. Confirm no request body, credentials, message content, or attachment data
   appears in telemetry.
4. Confirm no firewall, proxy, certificate, or host-isolation configuration
   changed during the test.

This document does not authorize protocol-content DLP or network blocking.
