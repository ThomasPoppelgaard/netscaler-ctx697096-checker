# netscaler-ctx697096-checker

Read-only precondition and exposure checker for the Citrix NetScaler ADC / NetScaler Gateway security bulletin **[CTX697096](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscale.html)**, covering **CVE-2026-88771 through CVE-2026-88778**.

> ⚠️ **CVE-2026-88771 and CVE-2026-88772 are exploited in the wild** and are listed in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Upgrade now, and assume breach on internet-facing appliances.

It answers three questions for each NetScaler:

1. **Is this build vulnerable?** It checks the build against the fixed versions and flags end-of-life releases.
2. **Which of the eight CVE preconditions does this configuration meet?** It checks the default partition and every admin partition.
3. **What could go wrong during the upgrade?** It flags known upgrade issues from the Citrix guidance.
4. **Was I hacked?** With `--ioc`, it checks every public indicator of compromise for CVE-2026-88771 published so far, and tells you whether attack traffic came before or after your fix.

For background, a timeline and step-by-step remediation, see the accompanying blog post: **[CVE-2026-88771 through CVE-2026-88778 – what you should know and how to fix your NetScaler](https://www.poppelgaard.com/cve-2026-88771-through-cve-2026-88778-what-you-should-know-and-how-to-fix-your-netscaler-adc-netscaler-gateway)**.

It is a single POSIX shell script with no dependencies. It runs on the appliance itself or against an exported `ns.conf` on any Linux, macOS or WSL machine.

---

## Fix check and IoC sweep

Without switches, the script checks **exposure and fix status**. With `--ioc`, it also checks for **compromise**: every public indicator of compromise for CVE-2026-88771 published so far, from GreyNoise, watchTowr, Lupovis, CERT-EU and Marius Sandbu.

> **Use it together with the official Citrix IoC scan, not instead of it.**
> - The official IoCs are only available through **NetScaler Console** (Security Advisory, then Indicators of Compromise) or from **Citrix Support**. Run that scan first, **before** you upgrade or reboot, because some traces may only exist in memory.
> - This script only knows the indicators that have been published. A clean result means none of those were found in the files and logs that are still on the box. It does **not** prove the appliance was never compromised. Check the log-retention lines to see how far back that goes.
> - On an HA pair, run it on **both** nodes. HA file sync copies webshells to the peer.

### What `--ioc` checks (appliance only)

**Context: how much is a clean result worth?**
- **When the fixed build started running.** Taken from the kernel that `installns` copies to `/flash` (`ns-<build>.gz`) and the first boot after the install (`/var/nsinstall/installns_state_post_reboot`). Every attack line is tagged before or after this time, and the output says where the date comes from. On a vulnerable build it shows when the exposure started, or that a newer build is installed but not running yet. Override with `--fixdate` if needed.
- **Last boot.** It shows whether in-memory traces can still be found, and warns if a vulnerable box rebooted recently.
- **Log retention** for `ns.log`, `notice.log` and `httpaccess-vpn.log`. It warns when less than 7 days are kept, because log-based checks can't see further back.

**Compromise: a command ran on this box** (`[SUSPECT]`)
- The `.ctxs.receiver` webshell by name and SHA-256, and PHP or webshell code (`<?php`, `passthru(`, `NSC_TASS`) anywhere in `LogonPoint/custom` or `/var/vpn`, which catches renamed copies.
- The httpd `Alias`/`AliasMatch` for `receiver.min(.<hex>).css` in `/etc/httpd.conf` or `/nsconfig/httpd.conf`.
- Files written by exploit payloads: the `nx_verify.html` canary, `/var/tmp/wtw*`, `watchTowr*`, `boom*`, and any small recent file in `/tmp`, `/var/tmp` or the web roots that contains `id` output.
- A setuid `/bin/sh`.
- `httpd.conf` changes that make a **non-`.php` extension run as PHP** (e.g. `.deb`, `.sig`), or `AliasMatch` rules pointing into Gateway folders such as `vpn/media` or `vpn/scripts` ([Mandiant/GTIG](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances/)).
- PHP or webshell code in the Gateway plugin and media folders (`vpn/scripts/linux`, `vista`, `mac`, `vpn/media`), which should only hold packages and images.
- Tunnel artefacts: `/tmp/.uxdport`, `/tmp/.uxdlock`, a Python process started from base64, or the SLAPSHOT marker `UXD_IDLE_EXIT` in a running process or a file in `/tmp` / `/var/tmp`.
- **WHIPSHOT-style webshell code** (Mandiant): commands read from `HTTP_X_UX*`, or `eval`/`base64_decode` on `HTTP_NSC_CLIENTTYPE` / `HTTP_NSC_LDAP`, in `LogonPoint/custom`, `/var/vpn` and the Gateway plugin and media folders. Known webshell SHA-256 hashes (GreyNoise, IFIN, eSentire, Unit 42 via Deyda) are checked in the same folders. Real client packages such as `nsgclient*.deb` are only flagged by content, never by name.
- `php_flag engine on` or a `SetHandler` for PHP in `httpd.conf` (Beazley, CERT-EU).
- PHP or shell scripts under `/netscaler/ns_gui` written after boot. Webshells differ per appliance, so this does not depend on a name or hash.
- `c88771.json` / `xua.html`, and any archive disguised as a web file (`.html`, `.json`, `.css`, `.js`, `.txt` with gzip, tar or zip content), which is how a stolen `/flash/nsconfig` is staged for download.
- Marker files from exploit tools in `/tmp` and `/var/tmp`, including `/tmp/watchTowr` from the public watchTowr CVE-2026-88772 (DTLS) tool. `/tmp` is emptied at reboot.
- Files dropped by the known payloads: `/.x`, `/s`, `lula`, `/var/1.py`, `update_c*.pl`, `themes/wt88771*` (Gotham Technology Group), and `/var/tmp/.s` (Arctic Wolf).
- The **`nsmon.pl` Perl implant** ([Arctic Wolf](https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771)): its hidden folder `/var/tmp/.nsmon` (`.cfg`, `.state`, `nsmon.pl`), its cron persistence in `/etc/crontab`, `/nsconfig/crontab` or any user crontab (Perl as root every 5 minutes), a running `nsmon.pl` process, or Perl listening on a TCP port between 41000 and 41999.
- Five payload SHA-256 hashes from Arctic Wolf (`/xd7h/x`, `nsmon.pl`, `update_c08937.pl`, the Platypus agent script), checked in `/tmp`, `/var/tmp`, the top of `/` and `/var`, and the web folders.
- Files payloads write stolen data or loaders into: `logon/insight-new.js`, `admin_ui/e.txt`, `admin_ui/log.txt`. Only path, size and date are shown, never the contents (Gotham, Deyda).
- A setuid shell copy in `/var/tmp/sh`, and persistence in startup files (`rc.netscaler`, `ns.conf`, `/etc/rc`): Python one-liners, `zlib`/`base64` decoders and reversed path strings used in earlier NetScaler campaigns (Deyda).
- Any text or script file in the Gateway client-package folders, not only PHP (Gotham).
- A payload process running now (`lula`, `update_c`, `nsmon`, `xd7h`, `/.x`), or an open connection to campaign infrastructure (Gotham).
- On a vulnerable build: **ARMED**, injected payload text still waiting in `ns.log`, `ns.log.0` or `messages`, which the vulnerable daily check reads next (Gotham).
- Web files changed in the last 14 days. Theme rewrites (20 or more files in one burst), files written during the upgrade (including HA sync from the peer) and the standard Citrix `strings.<lang>.js` loaders are recognised as expected. Any other changed file gets a content check for data-sending code, obfuscated loaders and webshell calls.

**Targeted: attack traffic in the logs**
- Injected commands in `ns.log` and `/var/log/messages`: fake `pitboss` messages as the login name (`...unexpectedly died NSPPE;<cmd>` and `...missed too many heartbeatsNSPPE;<cmd>`), `${IFS}` instead of spaces (also URL-encoded), backticks, `$(`, and commands straight after `;` or `|` (including FreeBSD `fetch`). Following [Elastic](https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_netscaler_log_poisoning_command_injection.toml)'s detection rule, any `pitboss` packet-engine message with a shell character (`;`, backtick, `$(`, `&&`, `||`, or URL-encoded `%3b` `%60` `%7c` `%24%28` `%26%26` `%3e` `%3c`) is also reported, which catches hand-written variants. This is the CVE-2026-88771 technique described by [watchTowr](https://labs.watchtowr.com/oh-look-the-foot-gun-went-off-again-citrix-netscaler-preauth-command-injection-cve-2026-88771/) and [CERT-EU](https://cert.europa.eu/blog/taking-execute-logging-a-bit-too-literally-cve-2026-88771).
- Base64 commands in the User-Agent, either as `INDEX:<base64>` (CERT-EU two-stage variant) or as the whole User-Agent (Kevin Beaumont), **shown decoded**.
- Post-exploitation in the shell history (`/var/log/sh.log*`, `bash.log*`): `ldapsearch`, `openssl s_client` and `ns_gui/vpn`, which attackers use to pull AD credentials through the LDAP bind account (Kevin Beaumont).
- Possible CVE-2026-88772 (DTLS) attempts: DTLSv1.0 handshake failures with "Internal Error", and packet-engine crashes (`exit with orphan rings`, `NOT restarting NSPPE`). When both are present, the output flags it as a likely CVE-2026-88772 attempt (Deyda).
- Attack payloads in requests to the login pages (`/nf/auth/doAuthentication.do`, `/cgi/login`, `/p/u/doLogon.do`, `tmindex.html`, `GetUserName`) as recorded in the HTTP logs: `pitboss`, `NSPPE`, `%3B`, `%60`, `${IFS}`, `curl`, `wget` or `fetch`. These are still visible after `ns.log` has rotated. Normal requests to these pages are not flagged (Deyda).
- 37 known attacker IPs and the domains `echvista.com` and `entretiensol.com`, shown as dated log lines (Truesec, eSentire, IFIN, Corelight, Lupovis via PitScaler.com, Gotham Technology Group, Mandiant, Arctic Wolf, [GreyNoise](https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation), [Lupovis](https://x.com/LupovisDefence)), requests to the webshell alias, the `httpworkbench` DNS-exfil domain, the `NX-CVE-OK` canary, the `ns-88771-poc` / `PoCbit` scanner user agents, and payload strings from Arctic Wolf (`xd7h/`, `nsmon`, `update_c08937`, `/dev/tcp/`, `nc -e`, `base64 -w0`, `exec-ok`), and the webshell header names `HTTP_X_UX` / `HTTP_NSC_LDAP` / `HTTP_NSC_CLIENTTYPE` in the HTTP logs.
- About 60 opportunistic scanner IPs tagged by GreyNoise, in a separate group marked as a hunting lead only (Cloudflare WARP addresses are left out: they are shared by ordinary users).
- Base64 PHP (`PD9…`) in the User-Agent, e.g. on `/vpn/media/*.ico`: webshell staging through the access log (eSentire), **shown decoded**.
- Probes: 1-byte `nsepa.deb` pre-checks (HTTP 206), the `vp_probe_nonexist` recon marker, `scanner-probe` logins, and requests for `.ctxs.receiver` per source IP (Gotham).
- Key and config theft in the shell history: `/flash/nsconfig/keys`, `F1.key`/`F2.key`, `database.php`, `LDAPTLS_REQCERT` (Deyda).
- **Before or after your fix:** every dated attack line is tagged `[BEFORE fix]` or `[after fix]`. Attempts that only came after the fixed build was installed cannot run commands, so they are reported as `[CHECK]` instead of `[SUSPECT]`. The decision uses every matching line, and `[BEFORE fix]` lines are always shown first.

**Other community checks**
- `httpd.conf` changes outside a reboot or upgrade, and recent crash dumps (FreeBSD `bounds` and `minfree` files are ignored).
- Crontab entries and processes for user `nobody`, root crontab lines that download something, and crontabs for any other user.
- **Cron jobs that delete or empty logs or files** (trace wiping, Beazley Security) are reported as compromise.
- `/nsconfig/nsafter.sh` (runs after every boot): Python, decoders, downloads, `nc`, setuid changes or writes into web folders are reported as compromise; any change in the last 30 days as `[CHECK]`.
- Hidden files in all web-served folders, and `.dot` files under `LogonPoint/custom`.
- Files changed in the last 3 days at the top of `/` and `/var` and in `/tmp` and `/var/tmp` (NetScaler's own files and anything written at boot or upgrade are filtered out).
- Processes running download tools or one-liners, connections from the management plane to public addresses, and packet engines that restarted after boot (possible CVE-2026-88772, visible even when the logs have rotated).
- `HeadlessChrome` in the VPN access logs.
- `b64decode` strings in the HTTP logs, and `.php`, `.sh`, `.pl`, `.rpm` or `.tgz` references in the `httperror` logs (notices from the management GUI are ignored).
- PHP or XHTML files under `/var/netscaler` outside the management GUI (`admin_ui`) and `websocketd`, with the files that contain webshell-like code (`eval`, `system`, `passthru`, `base64_decode`) listed separately (Deyda).
- Successful VPN requests from non-Receiver/Workspace clients, **summarised**: paths other than the standard Gateway pages, the top source IPs, and a NAT warning when 95% or more come from one IP.

Several of these checks are adapted from Manuel Winkel's [NetScaler CVE checklist](https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/) and triage scripts v9.17 and [triage script v9.28](https://github.com/Deyda/Security/blob/main/deyda-netscaler-ioc-check.sh) (Deyda Consulting). Additional indicators come from Gotham Technology Group's IoC check, shared with permission, and from the [PitScaler.com](https://pitscaler.com) IoC collection (30 September snapshot) with its original sources, and from [Arctic Wolf's alert pack](https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771) (30 September). Attacker IPs and webshell names differ per victim (Kevin Beaumont), so a clean result is never proof of a clean box. Thanks to all of them, and to Michael Shuster (Ferroque Systems) for his review and feedback on v1.7!

Log lines that contain binary or terminal-control bytes (common in `ns.log`, and attackers can inject escape codes) are shown with those bytes as `.` and labelled "(line contains binary data)", so a matched line is never blank.

With `--out`, attacker text in the saved report is **defanged** (`;` `|` `&` `` ` `` `$` `<` `>` become `_`, `http:` becomes `hxxp:`) so it is safe to paste into email or chat. The screen shows the raw text.

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
sh ctx697096_check.sh --ioc      # also checks for compromise (all public IoCs)
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
| `--ioc` | Also check for compromise: all public IoCs, attack traffic before/after the fix, log retention (appliance only) |
| `--partition <ns.conf>` | Check a single admin partition config |
| `--out <file>` | Also save the report as plain text (no colours, attacker text defanged), e.g. for the change record |
| `--fixdate "YYYY-MM-DD HH:MM"` | Optional: set when the fixed build started running, if the automatic date is wrong. Normally not needed |
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

IoC sweep (public indicators - use together with the official Citrix IoC scan)
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

- **v1.9** (2026-10-01): all public indicators published since v1.8, in one release.
  - **PitScaler.com:** Indicators from the [PitScaler.com](https://pitscaler.com) IoC collection. 15 more attacker IPs (C2, payload hosts, exfiltration, reverse shell; Truesec, eSentire, IFIN, Corelight, Lupovis) and the domain `echvista.com`, 32 in total; about 60 opportunistic scanner IPs from GreyNoise in a separate hunting-lead group (Cloudflare WARP left out); 3 more webshell hashes, also checked in the Gateway plugin and media folders; WHIPSHOT header code and the SLAPSHOT `UXD_IDLE_EXIT` marker (Mandiant); base64 PHP (`PD9…`) in the User-Agent, shown decoded (eSentire); `php_flag engine on` / `SetHandler` PHP in `httpd.conf` (Beazley).
  - **Beazley Security:** two persistence and anti-forensics checks from Beazley Security's advisory (BSL-A1216): cron jobs in `/var/cron/tabs` that delete or empty logs or files (red), crontabs for users other than root (`[CHECK]`), and suspicious commands in `/nsconfig/nsafter.sh` (red) or recent changes to it (`[CHECK]`).
  - **watchTowr:** marker files from exploit tools are now also looked for in `/tmp` (`watchTowr*`, `wtw*`, `boom*`). The public watchTowr detection tool for CVE-2026-88772 (DTLS) writes a 7-byte marker to `/tmp/watchTowr`, which earlier versions did not check. `/tmp` is emptied at reboot, so after a reboot the packet-engine crash/restart checks are the main trace of CVE-2026-88772.
  - **Arctic Wolf and Elastic:** indicators from [Arctic Wolf's alert pack](https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771) (30 September). Compromise: the `nsmon.pl` Perl implant (`/var/tmp/.nsmon` with `.cfg`, `.state`, `nsmon.pl`), its cron persistence in any crontab, a running `nsmon` process or a Perl listener on port 41000–41999, `/var/tmp/.s`, and 5 payload SHA-256 hashes (also checked in `/tmp`, `/var/tmp`, `/` and `/var`). Targeted: 5 more attacker IPs (37 in total), the domain `entretiensol.com`, and payload strings `xd7h/`, `nsmon`, `update_c08937`, `/dev/tcp/`, `nc -e`, `base64 -w0`, `exec-ok`, now also searched in `/var/log/messages`. Following [Elastic](https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_netscaler_log_poisoning_command_injection.toml)'s log-poisoning rule, any `pitboss` packet-engine message with a shell character (`;`, backtick, `$(`, `&&`, `||`, also URL-encoded) is now reported as an injection attempt, which catches hand-written variants without a known command name.
  - **Deyda triage script v9.28:** 3 more webshell/payload hashes (Unit 42), attack payloads in login-page requests in the HTTP logs, webshell header names in the HTTP logs, `.pl`/`.rpm`/`.tgz` in the `httperror` check, a combined warning when DTLS failures and packet-engine crashes both appear, and a `[CHECK]` for PHP/XHTML files in unexpected places under `/var/netscaler`.
  - **Fix:** a matched log line could show as empty (reported on 64.94.85.67). All log searches now read logs as text even when they contain binary bytes, and non-printable bytes, including terminal escape codes, are shown as `.` with the label "(line contains binary data)". Counts and the red/yellow decision are unchanged.
- **v1.8** (2026-09-30): the fix date for the `[BEFORE fix]` / `[after fix]` tags is now taken from the running build's kernel in `/flash` (`ns-<build>.gz`, written once by `installns`) and the first boot after the install (`installns_state_post_reboot`), capped by the last boot. Up to v1.7 it was the newest entry of any kind in `/var/nsinstall`, and `adc.version` in that folder is rewritten when someone logs on to the GUI, so attacks after the patch could be tagged `[BEFORE fix]` (a false red). The output now says where the date comes from, and there is an optional `--fixdate` override. Staged firmware (installed, not yet booted) is also detected from `/flash`. Thanks to the World of EUC Slack community for reporting this.
- **v1.7** (2026-09-30): indicators from Gotham Technology Group's IoC check (shared with permission) and Manuel Winkel's (Deyda Consulting) triage script v9.17, with review and feedback from Michael Shuster (Ferroque Systems).
  - **Compromise:** files dropped by known payloads (`/.x`, `/s`, `lula`, `/var/1.py`, `update_c*.pl`, `themes/wt88771*`); payload-targeted files (`insight-new.js`, `admin_ui/e.txt`, `admin_ui/log.txt`, contents not shown); setuid `/var/tmp/sh`; persistence strings in startup files; text/script files in client-package folders; payload processes and open connections to campaign infrastructure; **ARMED** payload text waiting on a vulnerable build.
  - **Targeted:** nine more attacker IPs (17 in total, also searched in `messages`); `nsepa.deb` 1-byte probes, `vp_probe_nonexist`, `scanner-probe` logins and `.ctxs.receiver` probing per source IP; key and config theft in the shell history. Apache error-log dates are now tagged before/after the fix too.
  - **Context:** hidden files in all web folders, `.dot` files, files changed in the last 3 days in `/`, `/var`, `/tmp` and `/var/tmp`, download/one-liner processes, public connections, packet engines restarted after boot, root crontab downloads, `HeadlessChrome`.
  - Admin CLI commands logged in `ns.log` (`shell_command=`) are no longer counted as attacks. `--out` reports are defanged. A compromise now says: don't reboot yet, copy the evidence first.
  - **Fewer false alarms (tested on a production HA pair):** the NetScaler Console Security Advisory scan files in `/var/tmp` (`*-detection.py`, and its `log.txt` / `results.txt` when written within 5 minutes of them), NetScaler's own `ns_system_backup.pl`, `install_pre_check.json`, `.monit.id` and `_callhome_tmp_file`, and root crontab calls to `localhost` are recognised as normal.
  - **Fix: attempts before the patch could be hidden.** The yellow/red decision for exploitation traffic used only the first few lines of each indicator, so an attempt before the fix in an older, rotated log could be missed and the result shown as yellow. It now decides on **all** lines, shows `[BEFORE fix]` lines first in every group, and says how many came before the fix. Found on a production appliance that was targeted 1.5 hours before it was patched.
  - **Compromise:** `c88771.json` and `xua.html` (payload files seen in the wild on 29 Sep: an `expr` test and a `tar` of `/flash/nsconfig` disguised as a web page), and **any archive disguised as a web file** (`.html`, `.json`, `.css`, `.js`, `.txt` with gzip, tar or zip content), whatever it is called.
  - **Verdict:** a vulnerable box now reads "the fixed build covers all eight CVEs in CTX697096". A fixed box with Enhanced ISN still off (in the default partition or any admin partition) now says "CVE-2026-88778 is still open" instead of only "follow-up items above".
- **v1.6** (2026-09-29): attempts after the patch are no longer shown as red, plus fixes found during a live HA upgrade.
  - `ns.log` injection attempts that are all `[after fix]` now give a yellow `[CHECK]` instead of a red `[SUSPECT]`. Known attacker IPs are shown as dated log lines tagged `[BEFORE fix]` / `[after fix]` (before, only the file names), and base64 User-Agent payloads and Gateway staging errors are tagged too. Compromise indicators stay red whatever the date.
  - On the appliance, the build is now read from the **running** kernel instead of the `ns.conf` header. Before, the checker reported the old (vulnerable) build after an upgrade until `save ns config` was run. If the two differ, it now warns that the config has not been saved since the upgrade.
  - `--ioc`: when the newest `/var/nsinstall` entry is newer than the last boot, the new build is reported as staged but **not running yet** (reboot pending), and the exposure is shown as running since at least the last boot. Before, the copy date of the staged build was wrongly shown as the start of the exposure window.
- **v1.5** (2026-09-29): new public indicators from Mandiant/GTIG and Kevin Beaumont, including CVE-2026-88772.
  - **Compromise:** `httpd.conf` handlers that run non-`.php` extensions as PHP and `AliasMatch` rules into Gateway folders; webshell code in the Gateway plugin and media folders; tunnel artefacts in `/tmp` and Python processes started from base64; PHP or shell scripts under `/netscaler/ns_gui` written after boot (webshells differ per appliance).
  - **Targeted / post-exploitation:** CVE-2026-88772 (DTLS) handshake failures and packet-engine crashes; `ldapsearch` / `openssl s_client` / `ns_gui/vpn` in the shell history (LDAP credential theft); a User-Agent that is only base64 (shown decoded); `pitboss` with `b64decode`; `.sh` and `.php` in the httperror logs; two more attacker IPs (eight in total).
  - Headings now say CVE-2026-88771/88772.
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
- [Arctic Wolf – Citrix NetScaler active exploitation via CVE-2026-88771 (alert pack)](https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771)
- [Elastic – Potential NetScaler Log Poisoning Command Injection Attempt (detection rule)](https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_netscaler_log_poisoning_command_injection.toml)
- [Deyda – NetScaler IoC triage script (GitHub)](https://github.com/Deyda/Security/blob/main/deyda-netscaler-ioc-check.sh)
- [Deyda – NetScaler CVE checklist: updates, security assessment and incident response](https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/)
- [NetScaler docs – Configurations support in admin partition](https://docs.netscaler.com/en-us/citrix-adc/current-release/admin-partition/admin-partition-config-types.html)
- Blog post: [CVE-2026-88771 through CVE-2026-88778, what you should know and how to fix your NetScaler ADC, NetScaler Gateway](https://www.poppelgaard.com/cve-2026-88771-through-cve-2026-88778-what-you-should-know-and-how-to-fix-your-netscaler-adc-netscaler-gateway) (Thomas Poppelgaard)

---

## Disclaimer

This is an independent community tool. It is **not** affiliated with, endorsed by or supported by Cloud Software Group / Citrix. It is provided as is, without warranty. It is read-only and makes no changes to the appliance. The Citrix security bulletin is the authoritative source. Always verify the results against it, and involve experienced forensic investigators if you suspect a compromise.

Author: **Thomas Poppelgaard**, [Poppelgaard.com ApS](https://www.poppelgaard.com)
