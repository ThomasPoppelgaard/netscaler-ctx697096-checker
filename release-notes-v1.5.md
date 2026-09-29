## v1.5: Mandiant/GTIG and Kevin Beaumont indicators, CVE-2026-88772 included

Mandiant and Google Threat Intelligence published [Defending Against Active Exploitation of Citrix NetScaler ADC and Gateway Appliances](https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances/). Exploitation of **CVE-2026-88771 and CVE-2026-88772** started in **early September 2026**. The attackers hide webshells as client packages, signatures or icons in the Gateway folders, and use a tunnel to reach the internal network. v1.5 adds these defensive checks to `--ioc`:

### Compromise: a command ran on this box
- `httpd.conf` rules that make a **non-`.php` extension run as PHP** (e.g. `.deb`, `.sig`), and `AliasMatch` rules pointing into Gateway folders (`vpn/media`, `vpn/scripts`, …)
- **PHP or webshell code in the Gateway plugin and media folders** (`vpn/scripts/linux`, `vista`, `mac`, `vpn/media`), which should only hold packages and images
- **Tunnel artefacts:** `/tmp/.uxdport`, `/tmp/.uxdlock`, or a Python process started from base64

### Targeted
- **Possible CVE-2026-88772 (DTLS) attempts:** DTLSv1.0 handshake failures with "Internal Error", and packet-engine crashes (`exit with orphan rings`, `NOT restarting NSPPE`), tagged before/after your fix
- **Errors for package, signature or icon files** in Gateway folders (possible webshell staging)
- **Two more attacker IPs:** `143.198.7.94`, `157.254.167.12` (eight in total)

### Also new: post-exploitation and per-appliance webshells (Kevin Beaumont)
Kevin Beaumont reports that **"every appliance got a different shell"** ([summary by Prophet Security](https://www.prophetsecurity.ai/blog/citrix-netscaler-zero-day)), and that attackers go on to steal AD credentials through the LDAP bind account. So v1.5 also checks:
- **PHP or shell scripts under `/netscaler/ns_gui` written after boot** (compromise), whatever they're called
- **Shell history** (`/var/log/sh.log*`, `bash.log*`) with `ldapsearch`, `openssl s_client` or `ns_gui/vpn`, tagged before/after your fix. If found before the fix, rotate the LDAP bind password and review LDAP/LDAPS and SMB traffic from the NetScaler to your domain controllers
- **A User-Agent that is only a base64 string**, shown decoded
- **`pitboss` with `b64decode`** in `ns.log`
- **`.sh` as well as `.php`** requests in the httperror logs

Headings now say CVE-2026-88771/88772. Everything from v1.4 is unchanged.

**If you can't patch today:** block inbound UDP/443 where DTLS isn't needed, restrict management access, and forward `ns.log`, `/var/log/messages` and the HTTP logs off the box. **If you find anything:** isolate the appliance, disable HA sync, and rotate every secret on it (TLS keys, LDAP bind, RADIUS, API credentials).

Use it **together with** the official Citrix IoC scan (NetScaler Console or Citrix Support), not instead of it, and run it on **both** HA nodes.
