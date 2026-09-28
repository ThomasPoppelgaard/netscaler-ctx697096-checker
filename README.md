# netscaler-ctx697096-checker

Read-only precondition and exposure checker for the Citrix NetScaler ADC / NetScaler Gateway security bulletin **[CTX697096](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscale.html)**, covering **CVE-2026-88771 through CVE-2026-88778**.

> ⚠️ **CVE-2026-88771 and CVE-2026-88772 are exploited in the wild** and are listed in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Upgrade now, and assume breach on internet-facing appliances.

It answers three questions for each NetScaler:

1. **Is this build vulnerable?** It checks the build against the fixed versions and flags end-of-life releases.
2. **Which of the eight CVE preconditions does this configuration meet?** It checks the default partition and every admin partition.
3. **What could go wrong during the upgrade?** It flags known upgrade issues from the Citrix guidance.

It is a single POSIX shell script with no dependencies. It runs on the appliance itself or against an exported `ns.conf` on any Linux, macOS or WSL machine.

---

## ⚠️ This is not an IoC scanner

This script checks **exposure**, not **compromise**.

- To check for compromise, use the official Citrix IoC scan, either through **NetScaler Console** (Security Advisory, then Indicators of Compromise) or by requesting the IoC script from **Citrix Support**.
- Run the official IoC scan **before** you upgrade or reboot. Some traces may only exist in memory.
- The optional `--ioc` switch in this script only runs a few **informal community checks**. A clean result does **not** mean the appliance was not compromised.

### What `--ioc` checks (appliance only)

- Hidden files under `LogonPoint/custom`, and web files changed in the last 14 days. Timestamps also change on reboot or upgrade, so review them in context.
- `httpd.conf` changes, `/bin/sh` permissions, `b64decode` strings in the HTTP logs, and recent crash dumps.
- **Last firmware install** (`/var/nsinstall`), which marks the start of the possible exposure window.
- Crontab entries for user `nobody`, and processes running as `nobody` other than httpd.
- `.php` references in `httperror` logs.
- Successful VPN requests from non-Receiver/Workspace clients. Browser-based users can be normal, so review the list.

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
sh ctx697096_check.sh --ioc > /var/tmp/ctx697096_$(hostname)_$(date +%Y%m%d).txt 2>&1
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
| `-h`, `--help` | Show help |

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
- Blog post: [poppelgaard.com](https://www.poppelgaard.com)

---

## Disclaimer

This is an independent community tool. It is **not** affiliated with, endorsed by or supported by Cloud Software Group / Citrix. It is provided as is, without warranty. It is read-only and makes no changes to the appliance. The Citrix security bulletin is the authoritative source. Always verify the results against it, and involve experienced forensic investigators if you suspect a compromise.

Author: **Thomas Poppelgaard**, [Poppelgaard.com ApS](https://www.poppelgaard.com)
