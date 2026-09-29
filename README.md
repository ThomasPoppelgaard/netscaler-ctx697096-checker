# netscaler-ctx697096-checker

Read-only precondition and exposure checker for the Citrix NetScaler ADC / NetScaler Gateway security bulletin **[CTX697096](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscale.html)**, covering **CVE-2026-88771 through CVE-2026-88778**.

> ⚠️ **CVE-2026-88771 and CVE-2026-88772 are exploited in the wild** and are listed in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Upgrade now, and assume breach on internet-facing appliances.

It answers three questions for each NetScaler:

1. **Is this build vulnerable?** It checks the build against the fixed versions and flags end-of-life releases.
2. **Which of the eight CVE preconditions does this configuration meet?** It checks the default partition and every admin partition.
3. **What could go wrong during the upgrade?** It flags known upgrade issues from the Citrix guidance.

For background, a timeline and step-by-step remediation, see the accompanying blog post: **[CVE-2026-88771 through CVE-2026-88778 – what you should know and how to fix your NetScaler](https://www.poppelgaard.com/cve-2026-88771-through-cve-2026-88778-what-you-should-know-and-how-to-fix-your-netscaler-adc-netscaler-gateway)**.

It is a single POSIX shell script with no dependencies. It runs on the appliance itself or against an exported `ns.conf` on any Linux, macOS or WSL machine.

---

## ⚠️ This is not an IoC scanner

This script checks **exposure**, not **compromise**.

- To check for compromise, use the official Citrix IoC scan, either through **NetScaler Console** (Security Advisory, then Indicators of Compromise) or by requesting the IoC script from **Citrix Support**.
- Run the official IoC scan **before** you upgrade or reboot. Some traces may only exist in memory.
- The optional `--ioc` switch in this script only runs a few **informal community checks**. A clean result does **not** mean the appliance was not compromised.

### What `--ioc` checks (appliance only)

**Context first:**
- **Firmware install date.** On a vulnerable build this is when the exposure window started. On a fixed build it's when the window ended.
- **Last boot.** It shows whether in-memory traces can still be found. It warns if a vulnerable box rebooted recently.
- **Log retention** for `ns.log`, `notice.log` and `httpaccess-vpn.log`. It warns when less than 7 days are kept, because log-based checks can't see further back.

**Files:**
- Hidden files under `LogonPoint/custom`.
- Web files changed in the last 14 days, **grouped by timestamp**. Twenty or more files written in one burst (each within 30 seconds of the previous one, e.g. a theme or system rewrite) are reported as expected. Files changed **on their own** are flagged for review, with their timestamp, how many similar files in the same folder changed with them, and a content check: files written during the firmware upgrade or reboot are reported as expected, `strings.*.js` language loaders identical to the unchanged ones in their folder are recognised as the standard Citrix template, other language/EULA files (`strings.*.js`, `.xml`) must not contain code that sends data or loads scripts, `.php` files are checked for webshell calls, and other `.js`/`.html` for obfuscated loaders. Suspicious content is marked `[SUSPECT]`.
- `httpd.conf` changes. A change at boot time is expected after a reboot or upgrade. Any other change is flagged.
- `/bin/sh` permissions, and recent crash dumps (FreeBSD `bounds` and `minfree` files are ignored).

**Persistence and processes:** crontab entries and processes for user `nobody`.

**Logs:**
- `b64decode` strings in the HTTP logs.
- `.php` references in `httperror` logs.
- Successful VPN requests from non-Receiver/Workspace clients, **summarised**: paths other than the standard Gateway pages, the top source IPs, and a NAT warning when 95% or more come from one IP.
- **Public CVE-2026-88771 indicators** ([GreyNoise](https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation), Marius Sandbu, [Lupovis](https://x.com/LupovisDefence)), split into two levels:
  - **Compromise (a command ran on the box):** the `.ctxs.receiver` webshell by name and SHA-256; PHP or webshell code (`<?php`, `passthru(`, `NSC_TASS`) anywhere in `LogonPoint/custom` or `/var/vpn`, which catches renamed copies; the httpd `receiver.min(.<hex>).css` alias; files written by exploit payloads (`nx_verify.html` canary, `/var/tmp/wtw*`, `watchTowr*`, `boom*`, and any small recent file in `/var/tmp` or the web roots that contains `id` output); setuid `/bin/sh`.
  - **Targeted (attacker traffic in the logs):** six known attacker IPs, requests to the webshell alias, the `httpworkbench` DNS-exfil domain, the `NX-CVE-OK` canary, the `ns-88771-poc` / `PoCbit` scanner user agents, and base64 commands parked in the User-Agent as `INDEX:<base64>` (CERT-EU two-stage variant), shown decoded.
- **`ns.log` entries with shell injection patterns**: backticks, `$(`, `;` or `|` followed by a command (including FreeBSD `fetch`), `${IFS}` used instead of spaces (also URL-encoded), and fake `pitboss` messages injected as the login name (`...unexpectedly died NSPPE;<cmd>` from Lupovis and the watchTowr PoC, `...missed too many heartbeatsNSPPE;<cmd>` from [CERT-EU](https://cert.europa.eu/blog/taking-execute-logging-a-bit-too-literally-cve-2026-88771)). `/var/log/messages` is searched too, because the vulnerable `ns_monuploadd_err.pl` reads it. This is the publicly described CVE-2026-88771 technique ([watchTowr analysis](https://labs.watchtowr.com/oh-look-the-foot-gun-went-off-again-citrix-netscaler-preauth-command-injection-cve-2026-88771/)).

Several of these checks are adapted from Manuel Winkel's [NetScaler CVE checklist](https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/) (deyda.net). Thanks, Manuel! On an HA pair, run it on **both** nodes: a clean node does not clear its peer.

---

## What it checks

### Build

| Release | Fixed in | Note |
|---|---|---|
| 14.1 | 14.1-73.37 and later | |
| 13.1 | 13.1-64.24 and later | The bulletin lists 64.23. 64.24 is the released build and avoids the 64.23 cyclic-reboot issue with NS variables |
| 14.1-FIPS | 14.1-73.37 FIPS and later | |
| 13.1-FIPS / NDcPP | 13.1-37.279 and later | |
| 13.0, 12.1 and older | No fix (end of life) | Flagged as vulnerable. Upgrade to 14.1 |

The August 2026 builds, 14.1-73.32 and 13.1-63.21, are **not** fixed.

### CVE preconditions (per partition)

| CVE | CVSS v4 | Issue | Precondition checked |
|---|---|---|---|
| CVE-2026-88771 | 9.5 | Unauthenticated RCE (**exploited**) | All deployments, no workaround |
| CVE-2026-88772 | 9.5 | Memory overflow leading to RCE (**exploited**) | DTLS enabled: VPN vservers without `-dtls OFF`, or DTLS vservers |
| CVE-2026-88773 | 9.3 | HTTP request smuggling | HTTP/SSL LB, CS, VPN or AAA vservers |
| CVE-2026-88774 | 7.0 | Policy bypass (URL normalisation) | `HTTP.REQ.URL` policy expressions |
| CVE-2026-88775 | 8.8 | Memory overflow / DoS | Gateway or AAA vservers |
| CVE-2026-88776 | 8.8 | Memory overflow / DoS | LB vservers of type ORACLE |
| CVE-2026-88777 | 8.8 | Memory overflow / DoS | FTP LB/CS/service/monitor, LSN FTP ALG (on unless disabled), RTSP ALG, DNS64, NAT64 |
| CVE-2026-88778 | 8.8 | TCP ISN prediction | TCP-based vservers with **Enhanced ISN Generation** not enabled. This needs a config change, not just the upgrade |

### Upgrade risks

- **NS variables on 13.1.** 13.1-64.23 may go into a cyclic reboot during the upgrade when NS variables are configured, so upgrade straight to 13.1-64.24.
- **SAML.** `samlRejectUnsignedAssertion OFF` is no longer supported and is forced ON by the upgrade. If your IdP does not sign assertions, SAML logons will break.

### Admin partitions

When partition configs exist (`/nsconfig/partitions/*/ns.conf`, or `partitions/*/ns.conf` next to an exported `ns.conf`), each partition gets its own precondition report.

According to the NetScaler documentation, TCP parameters are partition-specific. **Enable Enhanced ISN Generation in the default partition and in every admin partition.**

---

## Usage

### On the appliance

```sh
# copy the script (use binary mode in WinSCP, see Troubleshooting)
scp ctx697096_check.sh nsroot@<NSIP>:/var/tmp/

ssh nsroot@<NSIP>
> shell
cd /var/tmp
sh ctx697096_check.sh            # build + preconditions + partitions + upgrade risks
sh ctx697096_check.sh --ioc      # also runs the informal community IoC checks
```

Save the output for your change record:

```sh
sh ctx697096_check.sh --ioc --out /var/tmp/ctx697096_$(hostname)_$(date +%Y%m%d).txt
```

Notes:

- The script reads the **saved** config (`/nsconfig/ns.conf`). Run `save ns config` first if there are unsaved changes.
- On HA pairs, run it on **both** nodes, especially with `--ioc`.
- It needs shell access (nsroot, or a superuser account).

### Offline, against an exported config

```sh
sh ctx697096_check.sh fw01-ns.conf

# many appliances
for f in *.conf; do echo "=== $f"; sh ctx697096_check.sh "$f"; done > report.txt
```

The build number is read from the first line of `ns.conf` (`#NS14.1 Build 73.37`). `--ioc` only works on the appliance.

### Options

| Option | Description |
|---|---|
| `<path>` | Config file to check (default `/nsconfig/ns.conf`) |
| `--ioc` | Run the informal community IoC checks (appliance only) |
| `--partition <ns.conf>` | Check a single admin partition config |
| `--out <file>` | Also save the report as plain text (no colours), e.g. for the change record |
| `--version` | Show the script version |
| `-h`, `--help` | Show help |

### Output labels

| Label | Meaning |
|---|---|
| `[AFFECTED]` | Precondition met on a **vulnerable** build: act now |
| `[met/fixed]` | Precondition met, but the build is **fixed**. It shows what was exposed before the upgrade. No action needed |
| `[fixed]` | The running build includes the CTX697096 fixes |
| `[not met]` | CVE precondition not met |
| `[OK]` | Check clean or expected (upgrade risks, `--ioc`) |
| `[SUSPECT]` | A web file modified on its own contains code-like content (e.g. `eval(atob`, injected `<script>`, PHP webshell calls): treat as possible compromise |
| `[CHECK]` | Review manually |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Fixed build, no follow-up flagged |
| `1` | Fixed build, but follow-up needed (e.g. Enhanced ISN, NS variables, SAML, IoC hits) |
| `2` | **Vulnerable**: upgrade now |
| `3` | Could not read the config or determine the build |

---

## Example output

```text
CTX697096 precondition check  (config: fw01-ns.conf, host: ns01, 2026-09-28 13:21)
============================================================================
Build
  [AFFECTED] Running 13.1-58.21 - VULNERABLE. Fixed in 13.1-64.24 or later.

Preconditions (CTX697096)
  [AFFECTED] CVE-2026-88771 (RCE, 9.5, EXPLOITED) - applies to ALL deployments, no workaround
  [AFFECTED] CVE-2026-88772 (RCE, 9.5, EXPLOITED) - DTLS enabled:
             | add vpn vserver gw1 SSL 10.0.0.1 443 -Listenpolicy NONE
  [AFFECTED] CVE-2026-88773 (HTTP request smuggling, 9.3) - 4 HTTP/SSL vserver(s)
  ...
  [AFFECTED] CVE-2026-88778 (TCP ISN prediction, 8.8) - TCP vservers present, Enhanced ISN not enabled in config

Upgrade risk
  [CHECK]    NS variables configured - upgrade straight to 13.1-64.24, do NOT use a 64.23 build:
  [CHECK]    SAML action(s) accept UNSIGNED assertions. After upgrade this is forced ON -

============================================================================
VERDICT: VULNERABLE - upgrade now. CVE-2026-88771 and -88772 are exploited in the wild.
```

With `--ioc` on a patched appliance (shortened, names and IPs changed):

```text
Build
  [fixed]    Running 14.1-73.37 - includes the CTX697096 fixes (recommended: 14.1-73.37 or later).

Preconditions (CTX697096)
  [met/fixed] CVE-2026-88771 (RCE, 9.5, EXPLOITED) - applies to ALL deployments, no workaround - mitigated by fixed build
  [met/fixed] CVE-2026-88772 (RCE, 9.5, EXPLOITED) - DTLS enabled - mitigated by fixed build:
  ...
  [not met]  CVE-2026-88778 - TCP vservers present, Enhanced ISN Generation ENABLED

Informal IoC sweep (community guidance, not Citrix IoCs)
  [OK]       Fixed build installed 2026-09-28 15:20 (newest /var/nsinstall entry) - exposure window ended here
  [OK]       Last boot 2026-09-28 15:18 (after the fixed-build install)
  [CHECK]    ns.log keeps only ~24 hours of history (oldest file 2026-09-27 17:00)
             | Log-based checks cannot see further back. Forward logs to a SIEM / syslog server.
  [OK]       432 web files rewritten together on 2026-09-24 16:03 - whole theme/system rewrite (expected)
  [OK]       Web files written during the firmware upgrade / reboot (expected):
             | 2026-09-28 15:17  /var/netscaler/logon/themes/EULA/resources/en.xml
             | ... and 11 more
  [OK]       Language loader files identical to the unchanged ones in their folder (standard Citrix template):
             | 2026-09-22 22:00  /var/netscaler/logon/LogonPoint/custom/strings.ko.js
  [OK]       No crontab for user 'nobody'
  [OK]       8524 successful VPN requests from non-Receiver clients - all normal logon-page paths
             | NOTE: >=95% from one IP - client IPs are probably hidden by NAT; use firewall logs
  [OK]       No shell metacharacters in logon-related ns.log entries

============================================================================
VERDICT: fixed build, no follow-up flagged.
```

---

## Enabling Enhanced ISN Generation (CVE-2026-88778)

```text
switch ns partition <partition>        # repeat for each admin partition
set ns tcpparam -enhancedISNgeneration ENABLED
switch ns partition default
set ns tcpparam -enhancedISNgeneration ENABLED
save ns config -all
show ns tcpparam | grep "Enhanced ISN Generation"
```

GUI: **Configuration > System > Settings > Change TCP Parameters**, tick **Enhanced ISN Generation**, click **OK** and save the config.

---

## Recommended order of work

1. **Preserve evidence.** Collect a support bundle and copy the logs off the appliance. Take a RAM capture if possible.
2. **Run the official Citrix IoC scan** (NetScaler Console or Citrix Support) **before** any reboot.
3. **Run this script** to see which preconditions apply and to plan the upgrade.
4. **Upgrade** to the fixed build, and enable Enhanced ISN Generation.
5. If anything suspicious was found, **treat the appliance as compromised** and follow [CTX694799 – Steps to take if NetScaler ADC is suspected to be compromised](https://support.citrix.com/external/article/ctx694799/steps-to-take-if-netscaler-adc-issuspec.html).

---

## Changelog

- **v1.4** (2026-09-29): catches CVE-2026-88771 as exploited in the wild, based on public reporting by GreyNoise, Marius Sandbu, Lupovis, watchTowr and CERT-EU. Results are split into "compromised" (a command ran: the `.ctxs.receiver` webshell by name, SHA-256 or content, PHP where no PHP belongs, the `receiver.min.css` httpd alias, files written by exploit payloads including any file containing `id` output, setuid `/bin/sh`) and "targeted" (six known attacker IPs, exploit strings and scanner user agents, base64 `INDEX:` payloads in the User-Agent shown decoded). Exploitation log lines are tagged `[BEFORE fix]` / `[after fix]` relative to the fixed-build install; when all attempts came after the fix, the result is `[CHECK]` instead of `[SUSPECT]` (tested on a production appliance attacked hours after patching). Files written between the firmware install and the next boot count as part of the upgrade, which also covers files that HA file sync copies from the peer while it is being upgraded (tested on a production HA pair). PHP notices from the management GUI and the `/vpns/j_services.html` portal page are no longer flagged. The `ns.log` injection check now also searches `/var/log/messages` and catches the fake `pitboss` markers (`unexpectedly died NSPPE;` and `missed too many heartbeatsNSPPE;`), `${IFS}` instead of spaces, URL-encoded payloads and commands without a following space (`;id>`); v1.3 missed several of these.
- **v1.3** (2026-09-28): `--ioc` gives context and far fewer false positives; tested on a production appliance.
  - **Context:** firmware install date (start or end of the exposure window), last boot (are in-memory traces still there?), log retention for `ns.log`, `notice.log` and `httpaccess-vpn.log` (warning below 7 days).
  - **Web files:** changes in the last 14 days are clustered into bursts (20+ files within 30 s = theme/system rewrite). Files changed on their own get a timestamp, how many similar files in the folder changed with them, and a content check. Files written during the upgrade/reboot and the standard Citrix `strings.<lang>.js` loader template are recognised. Code that sends data or loads scripts, obfuscated loaders and PHP webshell calls are marked with the new red `[SUSPECT]` label.
  - **Fewer false positives:** `httpd.conf` changed at boot, FreeBSD `bounds`/`minfree` in `/var/core`, and more standard Gateway paths (including `OPTIONS *`) are treated as expected.
  - **Output:** new labels `[fixed]`, `[OK]` and `[SUSPECT]`; new `--out <file>` and `--version` options; lists show "... and N more" instead of being cut silently.
  - **Portability:** timestamps via perl (NetScaler may not ship `stat`); correct FreeBSD `kern.boottime` parsing.
- **v1.2** (2026-09-28): on fixed builds, met preconditions are shown as `[met/fixed]` instead of red `[AFFECTED]`; `--ioc` VPN check now summarises paths and source IPs (with NAT warning) instead of listing every request; new `--ioc` check for shell metacharacters in logon-related `ns.log` entries (CVE-2026-88771 technique, per watchTowr's public analysis).
- **v1.1** (2026-09-28): `--ioc` adds last firmware install / exposure window, `nobody` cron and processes, `.php` in httperror logs, and non-Receiver VPN access (adapted from the deyda.net checklist).
- **v1.0** (2026-09-28): initial release covering the build, all 8 CTX697096 preconditions, admin partitions, Enhanced ISN, and the 13.1-64.24 / SAML upgrade risks.

---

## Troubleshooting

**`: not found` or `Syntax error: word unexpected` on the NetScaler.** The file has Windows (CRLF) line endings, usually from a text-mode transfer or from saving the file on Windows. Fix it on the appliance:

```sh
tr -d '\r' < ctx697096_check.sh > ctx697096_fixed.sh && sh ctx697096_fixed.sh
```

To prevent it, upload in **binary** mode in WinSCP, or clone and download from GitHub, where `.gitattributes` enforces LF line endings.

---

## References

- [CTX697096 – Citrix security bulletin](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscale.html)
- [Citrix Tech Zone – Guidance for CVE-2026-88771 through CVE-2026-88778](https://community.citrix.com/techzone-blogs/110_security-updates/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve-2026-88771-through-cve-2026-88778/)
- [CISA – Critical Zero-Day Vulnerabilities Exploited in Citrix NetScaler ADC, Gateway](https://www.cisa.gov/news-events/alerts/2026/09/27/critical-zero-day-vulnerabilities-exploited-citrix-netscaler-adc-gateway)
- [NetScaler docs – Enhanced ISN generation](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/tcp-configurations.html#enhanced-isn-generation)
- [Deyda – NetScaler CVE checklist: updates, security assessment and incident response](https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/)
- [NetScaler docs – Configurations support in admin partition](https://docs.netscaler.com/en-us/citrix-adc/current-release/admin-partition/admin-partition-config-types.html)
- Blog post: [CVE-2026-88771 through CVE-2026-88778, what you should know and how to fix your NetScaler ADC, NetScaler Gateway](https://www.poppelgaard.com/cve-2026-88771-through-cve-2026-88778-what-you-should-know-and-how-to-fix-your-netscaler-adc-netscaler-gateway) (Thomas Poppelgaard)

---

## Disclaimer

This is an independent community tool. It is **not** affiliated with, endorsed by or supported by Cloud Software Group / Citrix. It is provided as is, without warranty. It is read-only and makes no changes to the appliance. The Citrix security bulletin is the authoritative source. Always verify the results against it, and involve experienced forensic investigators if you suspect a compromise.

Author: **Thomas Poppelgaard**, [Poppelgaard.com ApS](https://www.poppelgaard.com)
