## v1.18 (27 October 2026): php2shell is fixed – one build for everything

### 🚨 Fixed builds for php2shell

Citrix updated security advisory **[CTX697263](https://support.citrix.com/external/article/CTX697263)** on 27 October: PHP **CVE-2026-109618 and CVE-2026-109619** ("php2shell", pre-auth remote code execution, exploited in the wild) are fixed in

- **14.1-73.49** and later
- **13.1-64.32** and later
- **14.1-73.49 FIPS** and later
- **13.1-37.286 FIPS/NDcPP** and later

These builds also contain the CTX697096, CVE-2026-88779 and CVE-2026-107406 fixes, so they are the one build to install.

**Do now:** upgrade. Until then, restrict GUI and API access to admin hosts and NetScaler Console with ACLs ([CTX228148](https://support.citrix.com/external/article/CTX228148)) on every management address. Citrix's upgrade notes: ICA and VPN sessions drop during the upgrade, and `samlRejectUnsignedAssertion OFF` is forced ON.

### What's new

- **php2shell status by build:** 14.1-73.49 (also FIPS), 13.1-64.32 and 13.1-37.286 or later show `[fixed]`. If a fixed build's PHP module lacks the two upstream fix functions, the checker shows a `[CHECK]` to confirm with Citrix Support instead of guessing.
- **VULNERABLE when the GUI is open:** on a build without the fix, a management GUI that is open to any source in the NetScaler ACLs, or forwarded by a load-balancing vserver, is now red `[AFFECTED]` with the verdict **VULNERABLE to php2shell** (exit code 2). A GUI restricted by ACLs is a `[CHECK]` (exit code 1): the upgrade is still needed.
- **Upgrade advice everywhere points to the new builds:** 14.1-73.49 / 13.1-64.32 / 13.1-37.286 FIPS/NDcPP; end-of-life releases to 14.1-73.49.
- **`--summary`:** `php2shell=` adds `fixed`, `vulnerable` and `verify`; new verdict `VULNERABLE_PHP2SHELL` (status stays `FIXED` for the CTX697096 build).

Exit codes in automation: a CTX697096-fixed appliance with an open management GUI that returned 1 with v1.17 now returns **2**.

### ❤️ Support this project

This tool is free and will stay free. If it saved you time, you can say thanks with a voluntary contribution — completely optional:

👉 [Support netscaler-ctx697096-checker](https://donate.stripe.com/9B6aEX4fTasY7F70AbbbG00)
