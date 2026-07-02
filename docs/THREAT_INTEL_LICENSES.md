# Threat-Intel & Detection-Rule License Audit — eGuard Bundle

**Context:** eGuard is a *commercial* EDR that aggregates public threat-intel feeds and
detection rules into a signed bundle redistributed to paying customers' endpoints.
This is **commercial redistribution**, the most restrictive use case. "Internal use OK"
does NOT imply "bundle-and-resell OK".

**Audit date:** 2026-07-02.
**Method note:** This audit was produced without live web verification in this run.
Every row cites the authoritative license/ToS URL that must be checked before the
verdict is treated as final. Items where the terms are known to be ambiguous or where
the license could not be confirmed from memory are marked **UNRESOLVED** — they are
listed again in the legal-review section. Do not treat UNRESOLVED items as permissive.

Legend for **action**: `OK` / `OK-attr` (OK with attribution) / `segregate` (keep out
of the redistributed bundle; server-side lookup only) / `remove` / `needs-permission`
(written permission or commercial license required) / `UNRESOLVED`.

---

## 1. IOC feeds

| Source | License / Terms | Redistribution in commercial bundle? | Attribution required? | Commercial-use restrictions | Action | Evidence URL |
|---|---|---|---|---|---|---|
| Spamhaus DROP/EDROP | Spamhaus Terms of Use (proprietary). DROP is "free" for *use*, but Spamhaus ToU prohibit redistribution/resale of Spamhaus data; commercial/professional use requires a paid Spamhaus (DQS/data feed) license. | **No** — redistribution to third parties without a commercial agreement is prohibited by ToU. | N/A (redistribution not permitted) | Explicit: commercial use of free datafeeds beyond the free-use threshold requires a paid license. | **needs-permission** (or remove; replace with paid Spamhaus feed license covering redistribution) | https://www.spamhaus.org/legal/terms-of-use/ ; https://www.spamhaus.org/blocklists/do-not-route-or-peer/ |
| FireHOL Level 1 (firehol/blocklist-ipsets) | Aggregator repo; the *scripts* are GPL, but the **data has no unified license** — README states each list is distributed under the terms of its own maintainer. Level 1 includes Spamhaus DROP, DShield, and others with non-redistribution/non-commercial terms. | **No** — inherits the most restrictive upstream terms (includes Spamhaus + DShield, both problematic, see their rows). | Per-upstream | Per-upstream; several upstreams are non-commercial. | **remove** (consume permissively-licensed upstreams directly instead of the aggregate) | https://github.com/firehol/blocklist-ipsets (README license section) ; https://iplists.firehol.org/ |
| abuse.ch — MalwareBazaar, ThreatFox, Feodo Tracker, URLhaus, SSLBL, JA3 | Historically datasets were stated as CC0. Since the 2023/2024 platform change (auth-key requirement, updated ToS; abuse.ch now operated with Spamhaus Technology involvement), the Terms of Service govern dataset use and the commercial-redistribution position is **not clearly CC0 anymore**. | **Ambiguous.** CC0 statements suggest yes; current ToS may restrict commercial redistribution/resale of the datasets. Do not assume. | Requested (abuse.ch asks for credit) | Ambiguous under 2023+ ToS. | **UNRESOLVED — needs-permission** until legal confirms current ToS; safest is written confirmation from abuse.ch | https://abuse.ch/terms/ ; https://bazaar.abuse.ch/faq/ ; https://urlhaus.abuse.ch/api/ |
| SANS ISC DShield block.txt | DShield/ISC data is licensed **CC BY-NC-SA 4.0** (Attribution-NonCommercial-ShareAlike). | **No** — NC clause prohibits use in a commercial product; SA clause additionally conflicts with a proprietary bundle. | Yes (BY) — moot given NC | Explicitly non-commercial. | **remove** | https://isc.sans.edu/api/ (license statement) ; https://creativecommons.org/licenses/by-nc-sa/4.0/ |
| DigitalSide Threat-Intel (osint.digitalside.it, davidonzo/Threat-Intel) | **MIT License** (repo LICENSE file). | Yes. | Yes — include copyright + MIT license text. | None. | **OK-attr** (verify LICENSE file unchanged at ingest) | https://github.com/davidonzo/Threat-Intel/blob/master/LICENSE ; https://osint.digitalside.it/ |
| Botvrij.eu | **No explicit license published.** Free OSINT feed; site describes it as free to use but publishes no license or redistribution grant. | **Ambiguous** — no license = no redistribution grant by default. | Unspecified | Unspecified | **UNRESOLVED — needs-permission** (email operator; low effort, they are MISP-community friendly) | https://www.botvrij.eu/ |
| CINSscore ci-badguys (CINS Army) | Site says the list is "free for anyone to use"; **no formal license text**, no explicit redistribution grant. | **Ambiguous** — "free to use" ≠ "free to redistribute in a paid product". | Courtesy attribution expected | Unspecified | **UNRESOLVED — needs-permission** (request written OK from Sentinel/CINS) | https://cinsscore.com/#list |
| Blocklist.de | FAQ states lists are provided **free of charge** for server operators/firewalls; **no formal license**, no explicit grant to rebundle into a commercial product. | **Ambiguous.** | Courtesy attribution | Unspecified | **UNRESOLVED — needs-permission** | https://www.blocklist.de/en/index.html ; https://www.blocklist.de/en/api.html |
| AlienVault OTX (subscribed pulses via API) | OTX Terms of Use (AT&T Cybersecurity / LevelBlue). ToS restrict resale/commercial redistribution of OTX content; pulses are community-contributed (contributors retain rights — OTX cannot sublicense them to you for resale). | **No** — redistributing pulse indicators to paying customers is effectively resale of OTX data, prohibited by ToS; also unresolvable third-party (contributor) rights. | N/A | Explicit ToS restrictions on commercial exploitation. | **remove** from bundle (**segregate**: server-side enrichment/lookup only, if ToS permit internal use) | https://otx.alienvault.com/tos ; https://otx.alienvault.com/faq |
| OpenPhish feed.txt (free/community tier) | OpenPhish Terms: the free community feed is licensed for **non-commercial use only**; commercial use requires an OpenPhish commercial subscription. | **No.** | N/A | Explicit non-commercial restriction on the free tier. | **remove** (or purchase OpenPhish commercial feed with redistribution rights) | https://openphish.com/terms.html ; https://openphish.com/phishing_feeds.html |
| mitchellkrogza/Phishing.Database | Repo carries a **MIT license** (verify — repo licensing has changed over time). **Caution:** it aggregates upstream sources (e.g., PhishTank-derived data) whose own terms prohibit redistribution; the repo's MIT grant cannot launder those. | Repo license: yes; **effective answer ambiguous** due to upstream provenance. | Yes (MIT text) if kept | Upstream provenance risk. | **UNRESOLVED — segregate or remove** unless provenance of each entry is verified | https://github.com/mitchellkrogza/Phishing.Database (LICENSE file) ; https://www.phishtank.com/terms.php (upstream example) |
| Tor Project bulk exit list | No explicit license on the exit-list data itself (check.torproject.org/torbulkexitlist). Tor website content is CC BY 3.0 US; the exit list is factual, machine-generated relay data that Tor publishes for exactly this purpose (blocking/identification). | **Likely yes** (Tor publishes it for operational reuse; data is factual), but no explicit grant. Low practical risk. | Courtesy attribution to Tor Project | None known | **OK-attr** (flag as low-risk-ambiguous in manifest) | https://check.torproject.org/torbulkexitlist ; https://www.torproject.org/about/trademark/ (site license: https://www.torproject.org — footer CC BY 3.0 US) |
| montysecurity/C2-Tracker | Repo is **MIT** (verify LICENSE file). **Caution:** data is generated from Shodan/Censys queries; Shodan ToS restrict redistribution of Shodan-derived data, and the repo author cannot grant rights Shodan withholds. | Repo license: yes; **effective answer ambiguous** (Shodan-derived provenance). | Yes (MIT text) if kept | Shodan ToS: no resale/redistribution of results without license. | **UNRESOLVED — segregate or remove** pending legal view on derived-data risk | https://github.com/montysecurity/C2-Tracker (LICENSE) ; https://www.shodan.io/legal/tos (upstream) |

## 2. CVE / vulnerability data

| Source | License / Terms | Redistribution in commercial bundle? | Attribution required? | Commercial-use restrictions | Action | Evidence URL |
|---|---|---|---|---|---|---|
| NVD API (NIST) | US Government work — public domain in the US; NVD ToU: free to use/redistribute, but you must display the NVD attribution/citation statement and must not imply NIST endorsement. | **Yes.** | Yes — required NVD citation ("This product uses the NVD API but is not endorsed or certified by the NVD"). | None (no-endorsement clause only). | **OK-attr** | https://nvd.nist.gov/developers/terms-of-use |
| CISA KEV catalog | KEV is US Government information released for broad use; CISA publishes an explicit KEV license permitting free use, adaptation and redistribution (with conditions: no implication of CISA endorsement, no CISA logo/seal use). | **Yes.** | Yes — retain source notice per KEV license conditions. | No-endorsement / no-logo conditions only. | **OK-attr** | https://www.cisa.gov/known-exploited-vulnerabilities ; KEV license: https://www.cisa.gov/sites/default/files/licenses/kev/license.txt |
| FIRST.org EPSS scores | FIRST EPSS usage terms: scores are freely provided; FIRST permits use including commercial, **with attribution** ("cite EPSS as the source"); FIRST general data usage terms apply. | **Yes** (with attribution; verify current FIRST usage agreement wording re: bulk redistribution). | Yes — cite FIRST EPSS. | None known beyond attribution; bulk-redistribution wording should be verified. | **OK-attr** (verify usage agreement) | https://www.first.org/epss/user-guide ; https://www.first.org/epss/faq |

## 3. Detection rules

| Source | License / Terms | Redistribution in commercial bundle? | Attribution required? | Commercial-use restrictions | Action | Evidence URL |
|---|---|---|---|---|---|---|
| SigmaHQ/sigma | **Detection Rule License (DRL) 1.1.** Grants use, modification, redistribution incl. commercial, provided license text + rule author/reference metadata are retained. | **Yes.** | Yes — keep DRL text and each rule's `author`/`references` fields intact. | None. | **OK-attr** | https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md ; https://github.com/SigmaHQ/sigma/blob/master/LICENSE |
| joesecurity/sigma-rules | License not confirmed from memory; Joe Security is a commercial vendor and repo terms may be bespoke. | **Unknown.** | Unknown | Unknown | **UNRESOLVED** — check repo LICENSE; if absent, needs-permission | https://github.com/joesecurity/sigma-rules |
| mdecrevoisier/SIGMA-detection-rules | License not confirmed from memory (repo may use DRL or GPL). | **Unknown.** | Unknown | Unknown (GPL would force copyleft on the rule set portion) | **UNRESOLVED** — check repo LICENSE | https://github.com/mdecrevoisier/SIGMA-detection-rules |
| tsale/Sigma_rules | License not confirmed from memory. | **Unknown.** | Unknown | Unknown | **UNRESOLVED** — check repo LICENSE; if absent, needs-permission | https://github.com/tsale/Sigma_rules |
| splunk/security_content | **Apache License 2.0.** | **Yes.** | Yes — include Apache-2.0 text + NOTICE if present. | None. | **OK-attr** | https://github.com/splunk/security_content/blob/develop/LICENSE |
| elastic/detection-rules | **Elastic License 2.0 (ELv2).** ELv2 grants rights to use, copy, distribute, make available, and prepare derivative works, **except**: (a) may not provide the software to third parties as a hosted/managed service exposing substantial features; (b) may not circumvent license-key functionality; (c) must not remove licensing/copyright notices. Bundling rule *files* into a distributed on-prem product is arguably permitted distribution under ELv2 (limitation (a) targets SaaS), **but** shipping Elastic's rules inside a *competing commercial EDR* sits close to the line ELv2 was written to defend, and "make available … as a hosted or managed service" could be argued for cloud-managed EDR deployments. **Genuinely ambiguous — do not guess.** | **Ambiguous** (distribution literally granted; competitive/hosted-service reading is legal-risk). | Yes — retain ELv2 text and copyright notices on every rule. | The hosted/managed-service limitation; competitive-use optics. | **segregate + UNRESOLVED** (exclude from bundle pending legal opinion; if included, ship verbatim with ELv2 text and never behind eGuard's own license enforcement) | https://www.elastic.co/licensing/elastic-license ; https://github.com/elastic/detection-rules/blob/main/LICENSE.txt |
| elastic/protections-artifacts | **ELv2** (same analysis as above; these are Elastic Defend's own protection artifacts — the competitive-use concern is *stronger* here). | **Ambiguous / high risk.** | Yes (ELv2 notices) | Same as above; these artifacts exist specifically to power Elastic's EDR. | **remove or needs-permission** (highest-risk detection source; get Elastic's written position) | https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt ; https://www.elastic.co/licensing/elastic-license |
| Emerging Threats Open (ET Open Suricata rules) | Mixed: legacy (pre-Proofpoint/pre-2008 "original") rules under BSD; the current ET Open ruleset is distributed under the **Proofpoint ET Open license**, which permits free use but **restricts commercial redistribution/resale of the ruleset without Proofpoint's permission** (Proofpoint sells ET Pro precisely for commercial embedding). Exact current license text must be pulled from the download page. | **No** for the modern ruleset without Proofpoint agreement; BSD-portion only in theory (impractical to separate). | Yes (retain rule headers/license) | Explicit restriction on commercial redistribution of ET Open as part of a paid product. | **needs-permission** (or license ET Pro with redistribution rights) | https://rules.emergingthreats.net/ (license/FAQ) ; https://community.emergingthreats.net/ ; https://www.proofpoint.com/us/products/et-intelligence |
| YARAHQ/yara-forge — **full** package | yara-forge tooling is licensed openly, but the packages bundle rules from many repos, each retaining its own license; yara-forge embeds per-rule license/author metadata. The **core** package is curated/most-permissive; the **full** package includes *everything that passed QA*, i.e. rules under GPL, CC BY(-SA/-NC?), DRL, and repos with unclear licenses. Which license tiers "full" includes must be verified against the current yara-forge README/output. | **Mixed per rule** — cannot answer for the package as a whole. GPL rules in a proprietary bundle create copyleft questions; any NC-licensed rule is a hard no. | Per rule (headers embedded by yara-forge — must be preserved). | Per rule. | **segregate**: do not ship "full" wholesale; filter to an allow-list of licenses (MIT/BSD/Apache/DRL/CC0/CC-BY) using yara-forge's per-rule metadata; mark license-tier composition **UNRESOLVED** until verified | https://github.com/YARAHQ/yara-forge (README, license handling) ; https://yarahq.github.io/ |
| bartblaze/Yara-rules | Believed **MIT** (verify LICENSE file — not confirmed in this run). | Yes if MIT. | Yes (MIT text + copyright). | None if MIT. | **OK-attr (pending LICENSE verification)** | https://github.com/bartblaze/Yara-rules/blob/master/LICENSE |
| chronicle/GCTI (Google) | **Apache License 2.0.** | **Yes.** | Yes — Apache-2.0 text + NOTICE. | None. | **OK-attr** | https://github.com/chronicle/GCTI/blob/main/LICENSE |
| InQuest/yara-rules | License not confirmed from memory (InQuest repos vary; some Apache-2.0, some GPL). | **Unknown.** | Unknown | Unknown (GPL possible) | **UNRESOLVED** — check repo LICENSE | https://github.com/InQuest/yara-rules |
| reversinglabs/reversinglabs-yara-rules | **MIT License.** | **Yes.** | Yes — MIT text + ReversingLabs copyright. | None. | **OK-attr** | https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/LICENSE |
| Malpedia auto-YARA zip (malpedia.caad.fkie.fraunhofer.de) | Malpedia is a Fraunhofer FKIE community service with its own Terms of Service; the public zip contains only TLP:CLEAR rules, but individual rules carry their original authors' licenses, and Malpedia's ToS address redistribution of Malpedia content (historically: free service, restricted accounts, redistribution of corpus/content restricted). Exact current redistribution terms **not confirmed** in this run. | **Ambiguous** — two layers: Malpedia ToS + per-rule author licenses. | Per rule + Malpedia credit | Unconfirmed | **UNRESOLVED — needs-permission** (contact Malpedia team; they respond to such requests) | https://malpedia.caad.fkie.fraunhofer.de/usage/tos ; https://malpedia.caad.fkie.fraunhofer.de/ |

---

## 4. Top legal risks (ranked)

1. **Spamhaus DROP/EDROP** — Spamhaus actively enforces commercial licensing of its data
   and sells exactly this use case (data feeds for security vendors). Redistributing DROP
   inside a paid EDR bundle without a Spamhaus agreement is the single most likely source
   of a demand letter. *Fix: remove now; negotiate a Spamhaus datafeed license if the data
   is wanted.*
2. **elastic/protections-artifacts (and detection-rules) under ELv2** — shipping a direct
   competitor's protection content inside a commercial EDR. Even where ELv2's text
   arguably permits distribution, Elastic has both motive and resources to litigate the
   hosted-service/derivative reading. *Fix: exclude from bundle pending legal opinion /
   Elastic's written position.*
3. **ET Open rules** — Proofpoint monetizes ET Pro for exactly "embed in a commercial
   product"; bundling ET Open into a paid product without permission undercuts their
   business and their license restricts it. *Fix: remove or license ET Pro with
   redistribution rights.*
4. **AlienVault OTX pulses** — double problem: platform ToS restricting resale, plus
   community contributors' rights that AT&T/LevelBlue never sublicensed for your resale.
   *Fix: server-side enrichment only, never in the bundle.*
5. **OpenPhish free tier & SANS DShield** — both explicitly non-commercial. Clear-cut
   violations if shipped. *Fix: remove (OpenPhish sells a commercial feed).*
6. **abuse.ch post-2023 terms** — previously assumed CC0 across the industry; the ToS
   changed with the auth-key rollout. If eGuard's ingestion predates the change, the
   assumption is stale. *Fix: written confirmation.*
7. **Provenance laundering** (FireHOL aggregate, Phishing.Database, C2-Tracker) — a
   permissive repo license does not grant rights the upstream (Spamhaus, PhishTank,
   Shodan) withheld. Aggregators are not license firewalls.
8. **yara-forge "full" package** — GPL or NC rules inside a proprietary signed bundle;
   fix is mechanical (license allow-list filter on per-rule metadata) but must be done.

## 5. Compliance checklist — LICENSES manifest inside the signed bundle

The bundle MUST ship a machine-readable + human-readable `LICENSES/` manifest containing,
**per source**:

- [ ] Source name, upstream URL, and exact retrieval URL.
- [ ] SPDX identifier where one exists (MIT, Apache-2.0, CC0-1.0, CC-BY-4.0…) or the
      verbatim license/ToS text where none exists (DRL 1.1, ELv2, ET Open, KEV license).
- [ ] Full license text for every license present in the bundle (MIT/Apache/DRL/etc.),
      including Apache NOTICE files where upstream provides them.
- [ ] Required attribution strings, verbatim:
  - NVD: "This product uses data from the NVD API but is not endorsed or certified by
    the NVD." (per NVD ToU)
  - CISA KEV source notice (per KEV license conditions).
  - FIRST EPSS citation (per EPSS user guide).
  - Copyright lines for each MIT/Apache source (DigitalSide, ReversingLabs, Splunk,
    Chronicle GCTI, bartblaze…).
- [ ] Per-rule metadata preservation: Sigma DRL requires author/reference fields intact;
      yara-forge per-rule license headers must not be stripped by any
      minification/repackaging step.
- [ ] Retrieval date + upstream content hash per source (proves what version of the
      terms applied at ingest).
- [ ] An exclusion list: sources consumed server-side only (OTX, anything segregated)
      with a build-time assertion that none of their indicators leak into the bundle.
- [ ] License allow-list enforced at ingest (CI gate): bundle build fails if a rule/feed
      carries a license outside {MIT, BSD-2/3, Apache-2.0, CC0-1.0, CC-BY-4.0, DRL-1.1,
      US-Gov/PD} or has no license metadata.
- [ ] No-endorsement compliance: no NIST/CISA/vendor logos or wording implying
      endorsement anywhere in product/marketing.
- [ ] Record of written permissions obtained (who, when, scope) for needs-permission
      sources actually shipped.

## 6. UNRESOLVED — requires legal review / upstream contact

| # | Item | Why unresolved | Next step |
|---|---|---|---|
| 1 | abuse.ch datasets (all six) under 2023+ ToS | CC0 claim vs. current platform ToS not reconciled; terms changed with auth-key rollout | Read https://abuse.ch/terms/ current text; email abuse.ch for written redistribution confirmation |
| 2 | ELv2 rules (elastic/detection-rules, protections-artifacts) in a competing EDR | ELv2 distribution grant vs. hosted-service limitation vs. competitive-use risk — genuinely ambiguous | Formal legal opinion; optionally ask Elastic directly |
| 3 | ET Open exact current license text | BSD-legacy vs. Proofpoint ET Open license split not verified this run | Pull license from https://rules.emergingthreats.net/ and confirm commercial-redistribution clause |
| 4 | Botvrij.eu, CINSscore, Blocklist.de | No formal license published — no default redistribution right | Email operators for written permission (template letter) |
| 5 | Malpedia ToS redistribution clause | Current ToS text not verified; two-layer licensing (ToS + per-rule) | Read https://malpedia.caad.fkie.fraunhofer.de/usage/tos ; contact Malpedia team |
| 6 | joesecurity/sigma-rules, mdecrevoisier/SIGMA-detection-rules, tsale/Sigma_rules, InQuest/yara-rules, bartblaze/Yara-rules | LICENSE files not verified in this run | Check each repo's LICENSE; treat license-less repos as all-rights-reserved |
| 7 | yara-forge "full" package license-tier composition | Which tiers/licenses "full" includes must be read from current yara-forge docs/output | Inspect per-rule license metadata in the actual package; build allow-list filter |
| 8 | Phishing.Database & C2-Tracker upstream provenance | MIT repo license cannot launder PhishTank/Shodan-derived data | Legal view on derived-data risk; or drop |
| 9 | Tor bulk exit list | No explicit data license (low practical risk) | One-line legal sign-off; keep flagged in manifest |
| 10 | EPSS bulk-redistribution wording | Attribution-based use is clear; wholesale score redistribution wording unverified | Verify https://www.first.org/epss/user-guide usage agreement |

**Immediate safe subset (can ship today with attribution):** NVD, CISA KEV, EPSS
(pending #10), SigmaHQ (DRL 1.1), splunk/security_content, chronicle/GCTI,
reversinglabs-yara-rules, DigitalSide Threat-Intel, Tor exit list (flagged).
**Everything else: hold, segregate, or obtain permission first.**

---

## Live verification log

| Date | Claim | Result | Evidence |
|---|---|---|---|
| 2026-07-02 | SANS ISC/DShield data is CC BY-NC-SA 4.0 (non-commercial) | **CONFIRMED** — isc.sans.edu carries the CC BY-NC-SA 4.0 license badge/link | https://isc.sans.edu/aboutus.html (live fetch) |
| 2026-07-02 | OpenPhish free/Community feed excludes commercial use | **CONFIRMED** — openphish.com feed table gates "Commercial Use" behind paid Premium/Platinum tiers; Community tier is "Limited" under ToU | https://openphish.com/phishing_feeds.html (live fetch) |

Remaining rows marked UNRESOLVED have **not** been live-verified — treat as open legal items.
