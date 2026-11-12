## v1.19 (12 November 2026): CTX697305 – 28 CVEs, every NetScaler affected

### 🚨 CTX697305: upgrade again

Citrix published security bulletin **[CTX697305](https://support.citrix.com/external/article/CTX697305)** on 12 November 2026: **28 memory-safety vulnerabilities** in NetScaler ADC and NetScaler Gateway, rated critical, up to CVSS 9.5.

- **CVE-2026-120868** (packet processing, 9.3) applies to **every deployment in the default configuration**.
- **CVE-2026-107412** (9.5), **CVE-2026-120864** (ICA proxy, 9.3), **CVE-2026-111342** and **CVE-2026-111343** apply to every **Gateway and AAA** vserver.
- The others need a specific feature: EPA, SAML, WebAuth, Email OTP, KBA, certificate authentication, DNS recursion / DNS over HTTPS, SMPP, PUSH, RTSP, DIAMETER / SIP_TCP / MQTT / RADIUS load balancing, HTTP/3, HTTP/2, B64DECODE or AppFW, GSLB / geolocation, SIP ALG, BGP, ECH or a SafeNet HSM, and the management plane.
- **No workaround.** The bulletin does not report exploitation.

**Fixed builds:** **14.1-73.57** and later (the released build is **14.1-73.58**), **13.1-64.39**, **14.1-73.58 FIPS**, **13.1-37.293 FIPS/NDcPP**. They also contain every earlier fix (CTX697096, CVE-2026-88779, CVE-2026-107406, php2shell), so they are the one build to install. Secure Private Access hybrid deployments using NetScaler are affected too.

### What's new

- **Build check for CTX697305.** On a CTX697096-fixed build below the CTX697305 fix the Build line is now red, and the run ends with **`VERDICT: VULNERABLE to CTX697305`** (exit code 2). Every build below the fix is vulnerable, whatever the configuration, because of CVE-2026-120868.
- **One line per CVE precondition**, using the configuration checks from the bulletin: `[AFFECTED]` on a build below the fix, `[met/fixed]` on a fixed build, and one `[not met]` line with everything that is not in the configuration. BGP neighbors without TCP-MD5 are read from `/nsconfig/ZebOS.conf`; the management-plane CVE reuses the php2shell ACL check.
- **One build to install:** every upgrade recommendation now points to **14.1-73.58 / 13.1-64.39 / 14.1-73.58 FIPS / 13.1-37.293**; end-of-life releases to 14.1-73.58.
- **`--summary`:** new field `ctx697305=` (`vulnerable` / `fixed` / `unknown`) and verdict `VULNERABLE_CTX697305` (status stays `FIXED` for the CTX697096 build).
- No new IoCs: CTX697305 reports no exploitation and no indicators.

Exit codes in automation: a box on 14.1-73.49 / 13.1-64.32 that returned 0 or 1 with v1.18 now returns **2**.

### ❤️ Support this project

This tool is free and will stay free. If it saved you time, you can say thanks with a voluntary contribution — completely optional:

👉 [Support netscaler-ctx697096-checker](https://donate.stripe.com/9B6aEX4fTasY7F70AbbbG00)
