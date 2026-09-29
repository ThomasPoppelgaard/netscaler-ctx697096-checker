#!/bin/sh
# =============================================================================
# ctx697096_check.sh
# NetScaler ADC / Gateway precondition checker for CTX697096
# (CVE-2026-88771 .. CVE-2026-88778), published 2026-09-27
#
# Version: 1.4 (2026-09-29)
# Author : Thomas Poppelgaard - Poppelgaard.com ApS
# License: MIT (see LICENSE). Provided AS IS, no warranty. Read-only - makes no changes.
#
# Usage:
#   On the appliance (shell):   sh ctx697096_check.sh
#   Against an exported config: sh ctx697096_check.sh /path/to/ns.conf
#   Also run the IoC sweep with all public indicators (appliance only):
#                               sh ctx697096_check.sh --ioc
#   Admin partitions are checked automatically (TCP parameters incl. Enhanced
#   ISN are partition-specific per Citrix docs) when /nsconfig/partitions/*/ns.conf
#   (or partitions/*/ns.conf next to an exported ns.conf) exist. A single
#   partition config can be checked with:
#                               sh ctx697096_check.sh --partition <ns.conf>
#   Save a plain-text report (no colours) as well as showing it:
#                               sh ctx697096_check.sh --ioc --out /var/tmp/report.txt
#   Show version:               sh ctx697096_check.sh --version
#
# Exit codes:
#   0 = build is fixed and no manual follow-up flagged
#   1 = build is fixed, but follow-up needed (e.g. Enhanced ISN, IoC hits)
#   2 = build is VULNERABLE (upgrade now)
#   3 = could not read the config / determine the build
#
# The precondition patterns follow CTX697096. CVE-2026-88771 applies to every
# deployment regardless of config, so an affected build is always vulnerable.
# The IoC sweep is based on unofficial community guidance (incl. checks adapted
# from Manuel Winkel's NetScaler CVE checklist, deyda.net), NOT on Citrix IoCs -
# a clean result does not prove the appliance was not compromised.
# =============================================================================

VERSION="1.4"
CONF="/nsconfig/ns.conf"
DO_IOC=0
PART_MODE=0
OUTFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ioc) DO_IOC=1 ;;
    --partition) PART_MODE=1 ;;
    --out) shift; OUTFILE="$1" ;;
    --out=*) OUTFILE="${1#--out=}" ;;
    --version) echo "ctx697096_check.sh $VERSION"; exit 0 ;;
    -h|--help) awk 'NR>2 && /^# =====/{exit} NR>2' "$0"; exit 0 ;;
    *) CONF="$1" ;;
  esac
  shift
done

# --out: run once more with output captured to a plain-text file, then show it
if [ -n "$OUTFILE" ] && [ -z "$CTXCHK_CHILD" ]; then
  set --
  [ "$DO_IOC" -eq 1 ] && set -- --ioc
  [ "$PART_MODE" -eq 1 ] && set -- "$@" --partition
  set -- "$@" "$CONF"
  CTXCHK_CHILD=1 sh "$0" "$@" > "$OUTFILE" 2>&1; RC=$?
  cat "$OUTFILE"; echo; echo "Report saved to: $OUTFILE"
  exit $RC
fi

if [ -t 1 ]; then
  R=$(printf '\033[31m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m')
  B=$(printf '\033[1m');  N=$(printf '\033[0m'); C=$(printf '\033[36m')
else
  R=""; G=""; Y=""; B=""; N=""; C=""
fi

hit()  { printf '  %s[AFFECTED]%s %s\n' "$R" "$N" "$1"; }
susp() { printf '  %s[SUSPECT]%s  %s\n'  "$R" "$N" "$1"; }
ok()   { printf '  %s[not met]%s  %s\n'  "$G" "$N" "$1"; }
warn() { printf '  %s[CHECK]%s    %s\n'   "$Y" "$N" "$1"; }
okay() { printf '  %s[OK]%s       %s\n'   "$G" "$N" "$1"; }
fixd() { printf '  %s[fixed]%s    %s\n'   "$G" "$N" "$1"; }
# pre(): a CVE precondition is met. On a fixed build it is mitigated by the firmware,
# so show it as [met/fixed] instead of [AFFECTED].
pre()  {
  if [ "$VULN_BUILD" = "no" ]; then
    case "$1" in
      *:) printf '  %s[met/fixed]%s %s\n' "$C" "$N" "${1%:} - mitigated by fixed build:" ;;
      *)  printf '  %s[met/fixed]%s %s\n' "$C" "$N" "$1 - mitigated by fixed build" ;;
    esac
  else
    printf '  %s[AFFECTED]%s %s\n' "$R" "$N" "$1"
  fi
}
show() { awk -v n="${1:-5}" 'NR<=n{print "             | " $0} END{if(NR>n) print "             | ... and " NR-n " more"}'; }
note() { echo "             | $1"; }

# Portable time helpers. NetScaler (FreeBSD) may not ship "stat", but always has perl.
if command -v perl >/dev/null 2>&1; then
  mtime()     { perl -e '@s=stat($ARGV[0]); print $s[9] if @s' "$1" 2>/dev/null; }
  allmtimes() { find "$@" -type f 2>/dev/null | perl -ne 'chomp; @s=stat($_); print "$s[9]\n" if @s'; }
elif stat -c %Y / >/dev/null 2>&1; then
  mtime()     { stat -c %Y "$1" 2>/dev/null; }
  allmtimes() { find "$@" -type f -exec stat -c %Y {} + 2>/dev/null; }
else
  mtime()     { stat -f %m "$1" 2>/dev/null; }
  allmtimes() { find "$@" -type f -exec stat -f %m {} + 2>/dev/null; }
fi
fmtdate() {
  date -r "$1" '+%Y-%m-%d %H:%M' 2>/dev/null || date -d "@$1" '+%Y-%m-%d %H:%M' 2>/dev/null \
    || perl -MPOSIX -e 'print strftime("%Y-%m-%d %H:%M", localtime($ARGV[0]))' "$1" 2>/dev/null
}
boottime()  {
  [ -n "$CTXCHK_BOOTTIME" ] && { echo "$CTXCHK_BOOTTIME"; return; }
  b=$(sysctl -n kern.boottime 2>/dev/null | sed -nE 's/.*\{ *sec = ([0-9]+),.*/\1/p')
  [ -z "$b" ] && b=$(awk '/^btime/{print $2}' /proc/stat 2>/dev/null)
  echo "$b"
}

[ -r "$CONF" ] || { echo "ERROR: cannot read $CONF"; exit 3; }

# Case-insensitive extended grep against the config
# Tag log lines "[before fix]" / "[after fix]" relative to epoch $1 (fixed-build install).
# Understands Apache "[29/Sep/2026:00:10:12 -0300]" and syslog "Sep 29 00:10:12" timestamps.
fixtag() {
  perl -MTime::Local -ne '
    BEGIN { $f=shift @ARGV; %m=(Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11); @n=localtime; $y=$n[5]+1900 }
    $t=undef;
    if (/\[(\d+)\/(\w{3})\/(\d{4}):(\d+):(\d+):(\d+) ([+-])(\d\d)(\d\d)\]/ && exists $m{$2}) {
      $t=timegm($6,$5,$4,$1,$m{$2},$3) - ($7 eq "-" ? -1 : 1)*($8*3600+$9*60) }
    elsif (/^(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)/ && exists $m{$1}) {
      $t=timelocal($5,$4,$3,$2,$m{$1},$y) }
    $p = (!$f || !defined $t) ? "" : ($t > $f ? "[after fix] " : "[BEFORE fix] ");
    print $p.$_' "$1" 2>/dev/null
}
cg() { grep -iE -e "$1" "$CONF"; }
cgq() { grep -iqE -e "$1" "$CONF"; }

NAME='("[^"]*"|[^ ]+)'   # vserver/object name, quoted or not
FOLLOWUP=0

if [ "$PART_MODE" -eq 1 ]; then
  printf '\n%s--- Admin partition: %s ---%s\n' "$B" "$(basename "$(dirname "$CONF")")" "$N"
else
printf '%sCTX697096 precondition check%s  (config: %s, host: %s, %s)\n' \
  "$B" "$N" "$CONF" "$(hostname 2>/dev/null)" "$(date '+%Y-%m-%d %H:%M')"
echo "============================================================================"
fi

# ---------------------------------------------------------------------------
# 1. Build / version
# ---------------------------------------------------------------------------
if [ "$PART_MODE" -eq 1 ]; then VULN_BUILD="${PARENT_VULN:-partition}"; REL=""; else
echo "${B}Build${N}"
VERLINE=$(head -n 5 "$CONF" | grep -iE '^#NS[0-9]+\.[0-9]+ Build' | head -n 1)
if [ -z "$VERLINE" ] && command -v nsconmsg >/dev/null 2>&1; then
  VERLINE=$(nsconmsg -K /var/nslog/newnslog -d setime 2>/dev/null | grep -iE 'NS[0-9]+\.[0-9]+ Build' | head -n 1)
fi
REL=$(echo "$VERLINE" | sed -nE 's/.*NS([0-9]+\.[0-9]+) Build ([0-9]+)\.([0-9]+).*/\1/p')
BMAJ=$(echo "$VERLINE" | sed -nE 's/.*NS([0-9]+\.[0-9]+) Build ([0-9]+)\.([0-9]+).*/\2/p')
BMIN=$(echo "$VERLINE" | sed -nE 's/.*NS([0-9]+\.[0-9]+) Build ([0-9]+)\.([0-9]+).*/\3/p')

VULN_BUILD=""
if [ -z "$REL" ]; then
  warn "Could not read build from config header. Check with: show ns version"
  VULN_BUILD="unknown"
else
  # ge MAJ MIN  -> true if running build >= MAJ.MIN
  ge() { [ "$BMAJ" -gt "$1" ] || { [ "$BMAJ" -eq "$1" ] && [ "$BMIN" -ge "$2" ]; }; }
  case "$REL" in
    14.1)
      if [ "$BMAJ" -eq 37 ]; then
        warn "14.1 build $BMAJ.$BMIN looks like FIPS numbering - verify against 14.1-73.37 FIPS"
        VULN_BUILD="unknown"
      elif ge 73 37; then VULN_BUILD="no"; else VULN_BUILD="yes"; fi
      FIXED="14.1-73.37" ;;
    13.1)
      if [ "$BMAJ" -eq 37 ]; then
        # 13.1-FIPS / NDcPP train
        if ge 37 279; then VULN_BUILD="no"; else VULN_BUILD="yes"; fi
        FIXED="13.1-37.279 (FIPS/NDcPP)"
      else
        # Bulletin lists 64.23 as fixed; the released (GA) build is 13.1-64.24
        if ge 64 23; then VULN_BUILD="no"; else VULN_BUILD="yes"; fi
        FIXED="13.1-64.24"
      fi ;;
    *)
      VULN_BUILD="eol"; FIXED="14.1-73.37 (release $REL is end of life)" ;;
  esac
  case "$VULN_BUILD" in
    yes)     hit "Running $REL-$BMAJ.$BMIN - VULNERABLE. Fixed in $FIXED or later." ;;
    eol)     hit "Running $REL-$BMAJ.$BMIN - end-of-life release, no fix. Upgrade to $FIXED." ;;
    no)      fixd "Running $REL-$BMAJ.$BMIN - includes the CTX697096 fixes (recommended: $FIXED or later)." ;;
  esac
fi
echo

fi

# ---------------------------------------------------------------------------
# 2. Per-CVE preconditions
# ---------------------------------------------------------------------------
echo "${B}Preconditions (CTX697096)${N}"
[ "$VULN_BUILD" = "no" ] && echo "  (build is fixed - [met/fixed] lines show exposure before the upgrade; only CVE-2026-88778 needs a config change)"

# CVE-2026-88771 - all deployments
pre "CVE-2026-88771 (RCE, 9.5, EXPLOITED) - applies to ALL deployments, no workaround"

# CVE-2026-88772 - DTLS
VPN_NODTLS=$(cg "^add vpn vserver $NAME (SSL|DTLS) " | grep -viE -- '-dtls OFF')
DTLS_VS=$(cg "^add (lb|vpn|cs) vserver $NAME DTLS ")
if [ -n "$VPN_NODTLS" ] || [ -n "$DTLS_VS" ]; then
  pre "CVE-2026-88772 (RCE, 9.5, EXPLOITED) - DTLS enabled:"
  { echo "$VPN_NODTLS"; echo "$DTLS_VS"; } | grep -v '^$' | show 8
else
  ok "CVE-2026-88772 - no DTLS-enabled vservers found"
fi

# CVE-2026-88773 - HTTP/SSL vservers
HTTPVS=$(cg "^add (lb|cs|vpn|authentication) vserver $NAME (HTTP|SSL) ")
if [ -n "$HTTPVS" ]; then
  pre "CVE-2026-88773 (HTTP request smuggling, 9.3) - $(echo "$HTTPVS" | wc -l | tr -d ' ') HTTP/SSL vserver(s)"
else
  ok "CVE-2026-88773 - no HTTP/SSL LB/CS/VPN/AAA vservers"
fi

# CVE-2026-88774 - URL-based policy expressions
URLEXP=$(cg 'HTTP\.REQ\.URL')
if [ -n "$URLEXP" ]; then
  pre "CVE-2026-88774 (policy bypass, 7.0) - $(echo "$URLEXP" | wc -l | tr -d ' ') line(s) use HTTP.REQ.URL expressions"
elif [ -n "$HTTPVS" ]; then
  warn "CVE-2026-88774 - no HTTP.REQ.URL found, but HTTP/SSL vservers exist (Citrix uses the same test as 88773)"
else
  ok "CVE-2026-88774 - no URL-based policy expressions"
fi

# CVE-2026-88775 - Gateway / AAA
GWAAA=$(cg "^add (vpn|authentication) vserver ")
if [ -n "$GWAAA" ]; then
  pre "CVE-2026-88775 (memory overflow/DoS, 8.8) - Gateway or AAA vserver present"
else
  ok "CVE-2026-88775 - no Gateway/AAA vservers"
fi

# CVE-2026-88776 - Oracle LB
ORA=$(cg "^add lb vserver .* ORACLE")
if [ -n "$ORA" ]; then
  pre "CVE-2026-88776 (memory overflow/DoS, 8.8) - Oracle LB vserver:"; echo "$ORA" | show
else
  ok "CVE-2026-88776 - no Oracle LB vservers"
fi

# CVE-2026-88777 - non-HTTP L7 (FTP, LSN FTP/RTSP ALG, DNS64, NAT64)
F777=""
add777() { F777="$F777
$1"; }
cgq "^add (lb|cs) vserver $NAME FTP( |$)"      && add777 "FTP LB/CS vserver"
cgq "^add service $NAME [^ ]+ FTP( |$)"         && add777 "FTP service"
cgq "^add lb monitor $NAME FTP(-EXTENDED)?( |$)" && add777 "FTP health monitor"
cgq "^set lsn group .* -rtspalg ENABLED"        && add777 "LSN group with RTSP ALG enabled"
cgq "^add lb vserver .* DNS .*-dns64 ENABLED"   && add777 "DNS vserver with DNS64 enabled"
cgq "^add dns policy64 "                        && add777 "DNS64 policy (vulnerable if bound to a DNS vserver)"
cgq "^add nat64 "                               && add777 "NAT64 rule"
# LSN groups: FTP ALG is on unless explicitly disabled per group
for g in $(cg "^add lsn group " | awk '{print $4}'); do
  if ! grep -iE "^set lsn group $g .*-ftp DISABLED" "$CONF" >/dev/null 2>&1 \
     && ! grep -iE "^add lsn group $g .*-ftp DISABLED" "$CONF" >/dev/null 2>&1; then
    add777 "LSN group $g (FTP ALG not explicitly disabled)"
  fi
done
if [ -n "$(echo "$F777" | grep -v '^$')" ]; then
  pre "CVE-2026-88777 (memory overflow/DoS, 8.8) - non-HTTP L7 features:"
  echo "$F777" | grep -v '^$' | show 10
else
  ok "CVE-2026-88777 - no FTP / LSN ALG / DNS64 / NAT64 features found"
fi

# CVE-2026-88778 - TCP ISN prediction (config change required even after upgrade)
TCPTYPES='HTTP|SSL|SSL_BRIDGE|TCP|SSL_TCP|FTP|NNTP|RTSP|RDP|DNS_TCP|DOT|SIP_TCP|SIP_SSL|DIAMETER|SSL_DIAMETER|MYSQL|MSSQL|ORACLE|SMPP|MQTT|MQTT_TLS|MONGO|MONGO_TLS|PROXY|SSL_PROXY|USER_TCP|USER_SSL_TCP'
TCPVS=$(cg "^add (lb|cs|vpn|authentication|gslb|cr) vserver $NAME ($TCPTYPES) ")
if [ -n "$TCPVS" ]; then
  if [ "$PART_MODE" -eq 1 ]; then
    # Citrix docs: TCP feature parameters are partition-specific (admin partition "Case 2")
    if cgq "^set ns tcpParam .*-enhancedISNGeneration ENABLED"; then
      ok "CVE-2026-88778 - TCP vservers present, Enhanced ISN enabled in this partition"
    else
      hit "CVE-2026-88778 (TCP ISN prediction, 8.8) - TCP vservers present, Enhanced ISN NOT enabled in this partition"
      echo "             | TCP parameters are partition-specific - enable it inside this partition:"
      echo "             |   switch ns partition <name>; set ns tcpParam -enhancedISNGeneration ENABLED"
      FOLLOWUP=1
    fi
  elif cgq "^set ns tcpParam .*-enhancedISNGeneration ENABLED"; then
    ok "CVE-2026-88778 - TCP vservers present, Enhanced ISN Generation ENABLED"
  else
    hit "CVE-2026-88778 (TCP ISN prediction, 8.8) - TCP vservers present, Enhanced ISN not enabled in config"
    echo "             | Verify: show ns tcpparam | grep \"Enhanced ISN Generation\""
    echo "             | Fix per docs.netscaler.com > TCP configurations > Enhanced ISN generation"
    echo "             | NOTE: this needs a config change - the firmware upgrade alone is not enough"
    FOLLOWUP=1
  fi
else
  ok "CVE-2026-88778 - no TCP-based vservers"
fi
echo

# In partition mode only the per-partition preconditions are reported
if [ "$PART_MODE" -eq 1 ]; then
  [ "$FOLLOWUP" -eq 1 ] && exit 1
  exit 0
fi

# ---------------------------------------------------------------------------
# 3. Upgrade risks (from Citrix Tech Zone guidance for CTX697096)
# ---------------------------------------------------------------------------
echo "${B}Upgrade risk${N}"
# The released 13.1 fix is 13.1-64.24. 13.1-64.23 (early-access / bulletin build)
# may go into a CYCLIC REBOOT during upgrade when NS variables are configured.
NSVARS=$(cg "^add ns variable ")
if [ "$REL" = "13.1" ] && [ "$BMAJ" != "37" ] && [ "$BMAJ" -eq 64 ] && [ "$BMIN" -eq 23 ]; then
  warn "Running 13.1-64.23 (early-access build). Move to the released 13.1-64.24."
  [ -n "$NSVARS" ] && warn "NS variables configured - 64.23 has a known cyclic-reboot issue with these."
  FOLLOWUP=1
elif [ "$REL" = "13.1" ] && [ "$BMAJ" != "37" ] && [ "$VULN_BUILD" = "yes" ] && [ -n "$NSVARS" ]; then
  warn "NS variables configured - upgrade straight to 13.1-64.24, do NOT use a 64.23 build:"
  echo "$NSVARS" | show 8
  FOLLOWUP=1
else
  okay "No 13.1-64.23 upgrade risk"
fi

# SAML: samlRejectUnsignedAssertion OFF is no longer supported and is converted to
# the secure default during upgrade. Unsigned assertions from the IdP will then fail.
SAMLOFF=$(cg "-samlRejectUnsignedAssertion (OFF|NO)")
if [ -n "$SAMLOFF" ]; then
  warn "SAML action(s) accept UNSIGNED assertions. After upgrade this is forced ON -"
  warn "confirm the IdP signs assertions, or SAML logons will break:"
  echo "$SAMLOFF" | show 8
  FOLLOWUP=1
else
  okay "No SAML actions with samlRejectUnsignedAssertion OFF"
fi
echo

# ---------------------------------------------------------------------------
# 4. Optional IoC sweep with public indicators (appliance only)
# ---------------------------------------------------------------------------
if [ "$DO_IOC" -eq 1 ]; then
  echo "${B}IoC sweep${N} (public indicators - use together with the official Citrix IoC scan)"
  if [ ! -d /netscaler ]; then
    warn "Not running on a NetScaler - skipping IoC sweep"
  else
    NOW=$(date +%s)
    BOOT=$(boottime)

    # --- Context: firmware install, last boot, log retention -------------------
    NEWEST=$(ls -t /var/nsinstall 2>/dev/null | head -1)
    FWE=""; [ -n "$NEWEST" ] && FWE=$(mtime "/var/nsinstall/$NEWEST")
    if [ -n "$FWE" ]; then
      if [ "$VULN_BUILD" = "no" ]; then
        okay "Fixed build installed $(fmtdate "$FWE") (newest /var/nsinstall entry) - exposure window ended here"
        note "Look for signs of exploitation in logs from BEFORE this date."
      else
        warn "Current (vulnerable) firmware installed $(fmtdate "$FWE") - exposure window runs from here until you patch"
      fi
    else
      warn "Could not read /var/nsinstall to determine the last firmware install"
    fi
    if [ -n "$BOOT" ]; then
      UPD=$(( (NOW - BOOT) / 86400 ))
      if [ "$VULN_BUILD" = "no" ]; then
        if [ -n "$FWE" ] && [ "$BOOT" -ge "$((FWE - 300))" ]; then
          okay "Last boot $(fmtdate "$BOOT") (after the fixed-build install)"
          note "In-memory traces from before the upgrade are gone - rely on your pre-upgrade IoC scan."
        else
          okay "Last boot $(fmtdate "$BOOT") ($UPD days ago)"
        fi
      elif [ "$UPD" -lt 30 ]; then
        warn "Last boot $(fmtdate "$BOOT") ($UPD days ago) while on a vulnerable build"
        note "In-memory traces from before that boot are lost - memory checks only cover the time since boot."
      else
        okay "No reboot for $UPD days (since $(fmtdate "$BOOT")) - in-memory IoC checks are meaningful"
        note "Run the official Citrix IoC scan BEFORE upgrading or rebooting."
      fi
    fi
    for pat in ns.log notice.log httpaccess-vpn.log; do
      OLDEST=$(ls -tr /var/log/$pat* 2>/dev/null | head -1)
      [ -n "$OLDEST" ] || continue
      if [ "$(ls /var/log/$pat* 2>/dev/null | wc -l | tr -d ' ')" -eq 1 ]; then
        warn "$pat has no rotated files - history unknown; check the date of its first line"
        continue
      fi
      OM=$(mtime "$OLDEST"); [ -n "$OM" ] || continue
      DAYS=$(( (NOW - OM) / 86400 )); HRS=$(( (NOW - OM) / 3600 ))
      if [ "$HRS" -lt 48 ]; then SPAN="~$HRS hours"; else SPAN="~$DAYS days"; fi
      if [ "$DAYS" -lt 7 ]; then
        warn "$pat keeps only $SPAN of history (oldest file $(fmtdate "$OM"))"
        note "Log-based checks cannot see further back. Forward logs to a SIEM / syslog server."
      else
        okay "$pat covers $SPAN (oldest file $(fmtdate "$OM"))"
      fi
    done

    # --- File checks ---------------------------------------------------------
    # Dot-files dropped under LogonPoint/custom
    DOTS=$(find /var/netscaler/logon/LogonPoint/custom /netscaler/ns_gui/vpn 2>/dev/null \
           -name '.*' -type f 2>/dev/null)
    [ -n "$DOTS" ] && { warn "Hidden files under LogonPoint/custom or vpn:"; echo "$DOTS" | show 10; FOLLOWUP=1; } \
                   || okay "No hidden files under LogonPoint/custom"
    # Recently modified web-served files (last 14 days), grouped by modification time.
    # Many files written in one burst (>= 20 files, <= 30s apart) = system/theme
    # rewrite (expected); a handful of files on their own = review.
    WEBDIRS="${CTXCHK_WEBDIRS:-/var/netscaler/logon /netscaler/ns_gui /var/vpn}"
    RECENT=$(find $WEBDIRS 2>/dev/null \
             -type f \( -name '*.php' -o -name '*.xml' -o -name '*.js' -o -name '*.html' \) -mtime -14 2>/dev/null)
    if [ -n "$RECENT" ]; then
      # Cluster all web-file mtimes: a gap of <= 30s keeps files in the same
      # cluster, so a rewrite that takes several seconds counts as one event.
      # Output per distinct mtime: "<mtime> <cluster start> <cluster size>"
      CLMAP=$(allmtimes $WEBDIRS | sort -n | awk '
        { t[NR]=$1 }
        END { if (NR==0) exit; s=t[1]; st=1
              for (i=2;i<=NR+1;i++) {
                if (i>NR || t[i]-t[i-1] > 30) {
                  n=i-st; for (j=st;j<i;j++) if (!(t[j] in seen)) { seen[t[j]]=1; print t[j], t[st], n }
                  st=i }
              } }')
      RWGRP=""; LONE=""
      for f in $RECENT; do
        m=$(mtime "$f"); CL=$(echo "$CLMAP" | awk -v m="$m" '$1==m{print $2, $3; exit}')
        cs=${CL% *}; cn=${CL#* }; [ -n "$CL" ] || cn=0
        if [ "$cn" -ge 20 ]; then RWGRP="$RWGRP
$cs $cn"; else LONE="$LONE
$f"; fi
      done
      echo "$RWGRP" | grep -v '^$' | sort -u | while read -r m n; do
        AT=""; [ -n "$BOOT" ] && [ "$m" -ge "$((BOOT - 60))" ] && [ "$m" -le "$((BOOT + 900))" ] && AT=" at boot"
        okay "$n web files rewritten together$AT on $(fmtdate "$m") - whole theme/system rewrite (expected)"
      done
      if [ -n "$(echo "$LONE" | grep -v '^$')" ]; then
        # Look at each lone file: when, what else in its folder changed with it,
        # and whether the content looks like text or like injected code.
        #   strings.*.js / .xml : should be translated text only -> any code = suspicious
        #   .php                : should not be modified at all -> webshell patterns
        #   other .js / .html   : code by nature -> only obfuscation/loader patterns
        P_TEXT='eval[[:space:]]*\(|atob[[:space:]]*\(|<script|document\.write|createElement|fetch[[:space:]]*\(|new[[:space:]]+XMLHttpRequest|\.send[[:space:]]*\(|https?://|\.src[[:space:]]*=|window\.location|fromCharCode|new[[:space:]]+Function|\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x'
        P_PHP='eval[[:space:]]*\(|base64_decode|assert[[:space:]]*\(|system[[:space:]]*\(|shell_exec|passthru|proc_open|popen[[:space:]]*\(|\$_(POST|GET|REQUEST|COOKIE)'
        P_CODE='eval[[:space:]]*\([[:space:]]*(atob|unescape|decodeURIComponent|String\.fromCharCode)|document\.write[[:space:]]*\([[:space:]]*unescape|new[[:space:]]+Function[[:space:]]*\([[:space:]]*atob|\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}'
        SUSP=""; PLAIN=""; CODEF=""; UPGF=""; TPLF=""
        for f in $(echo "$LONE" | grep -v '^$'); do
          m=$(mtime "$f"); d=${f%/*}; b=${f##*/}; ext=${b##*.}
          case "$b" in strings.*.js) pat="strings.*.js" ;; *) pat="*.$ext" ;; esac
          tot=0; tog=0
          for s in "$d"/$pat; do
            [ -f "$s" ] || continue; tot=$((tot+1)); sm=$(mtime "$s")
            [ -n "$sm" ] && [ -n "$m" ] && [ $((sm - m)) -le 30 ] && [ $((m - sm)) -le 30 ] && tog=$((tog+1))
          done
          ctx="$tog of $tot $pat in folder changed together"
          # Written during the upgrade: from 15 min before the firmware install until 15 min
          # after the next boot (max 24 h apart). On an HA pair this also covers files that
          # HA file sync copied over from the peer while it was being upgraded.
          UPG=0
          for ref in "$FWE" "$BOOT"; do
            [ -n "$ref" ] && [ -n "$m" ] && [ "$m" -ge $((ref - 900)) ] && [ "$m" -le $((ref + 900)) ] && UPG=1
          done
          if [ -n "$FWE" ] && [ -n "$BOOT" ] && [ -n "$m" ] && [ "$BOOT" -ge "$FWE" ] && [ $((BOOT - FWE)) -le 86400 ] \
             && [ "$m" -ge $((FWE - 900)) ] && [ "$m" -le $((BOOT + 900)) ]; then UPG=1; fi
          if [ "$UPG" -eq 1 ]; then UPGF="$UPGF
$(fmtdate "$m")  $f"; continue; fi
          # strings.<lang>.js: identical to an unchanged sibling (language code
          # normalised) = the standard Citrix loader template
          case "$b" in strings.*.js)
            lg=${b#strings.}; lg=${lg%.js}; TPL=0
            me=$(sed -e "s/strings\.$lg\.json/strings.LANG.json/g" -e "s/[\"']$lg[\"']/'LANG'/g" "$f" 2>/dev/null)
            for s in "$d"/strings.*.js; do
              [ "$s" = "$f" ] && continue; sm=$(mtime "$s")
              [ -n "$sm" ] && [ $((sm - m)) -le 30 ] && [ $((m - sm)) -le 30 ] && continue
              sl=${s##*/strings.}; sl=${sl%.js}
              [ "$(sed -e "s/strings\.$sl\.json/strings.LANG.json/g" -e "s/[\"']$sl[\"']/'LANG'/g" "$s" 2>/dev/null)" = "$me" ] && { TPL=1; break; }
            done
            if [ "$TPL" -eq 1 ]; then TPLF="$TPLF
$(fmtdate "$m")  $f"; continue; fi ;;
          esac
          case "$b" in
            strings.*.js|*.xml) hit=$(grep -noE "$P_TEXT" "$f" 2>/dev/null | head -3 | tr '\n' ' ') ;;
            *.php)              hit=$(grep -noE "$P_PHP"  "$f" 2>/dev/null | head -3 | tr '\n' ' ') ;;
            *)                  hit=$(grep -noE "$P_CODE" "$f" 2>/dev/null | head -3 | tr '\n' ' ') ;;
          esac
          line="$(fmtdate "$m")  $f  ($ctx)"
          if [ -n "$hit" ]; then SUSP="$SUSP
$line
   code found: $hit"
          else case "$b" in
            strings.*.js|*.xml) PLAIN="$PLAIN
$line" ;;
            *.php) SUSP="$SUSP
$line
   .php file modified on its own - PHP files should only change with a firmware upgrade" ;;
            *) CODEF="$CODEF
$line" ;;
          esac; fi
        done
        if [ -n "$UPGF" ]; then
          okay "Web files written during the firmware upgrade / reboot, incl. HA sync from the peer (expected):"
          echo "$UPGF" | grep -v '^$' | show 5
        fi
        if [ -n "$TPLF" ]; then
          okay "Language loader files identical to the unchanged ones in their folder (standard Citrix template):"
          echo "$TPLF" | grep -v '^$' | show 5
        fi
        if [ -n "$SUSP" ]; then
          susp "Web files modified on their own WITH suspicious content - treat as possible compromise:"
          echo "$SUSP" | grep -v '^$' | show 30
          note "Preserve evidence (RAM + /var/log + the files) and involve incident response."
          FOLLOWUP=1
        fi
        if [ -n "$CODEF" ]; then
          warn "Code files (.js/.html) modified on their own - no obvious obfuscation, compare with a clean appliance of the same build:"
          echo "$CODEF" | grep -v '^$' | show 15
          FOLLOWUP=1
        fi
        if [ -n "$PLAIN" ]; then
          warn "Text/language files modified on their own - content looks like plain text (typical of a theme or EULA edit):"
          echo "$PLAIN" | grep -v '^$' | show 15
          note "Confirm an admin saved a theme/EULA at these times; if not, diff against a clean copy."
          FOLLOWUP=1
        fi
      fi
    else
      okay "No web files modified in the last 14 days"
    fi
    # httpd.conf changes - expected right after a boot (NetScaler rebuilds /etc)
    HTTPDCHG=0
    for f in /etc/httpd.conf /nsconfig/httpd.conf; do
      [ -f "$f" ] || continue
      m=$(mtime "$f"); [ -n "$m" ] || continue
      [ $((NOW - m)) -lt 1209600 ] || continue
      HTTPDCHG=1
      if [ -n "$BOOT" ] && [ "$m" -ge "$((BOOT - 60))" ] && [ "$m" -le "$((BOOT + 900))" ]; then
        okay "$f changed at boot ($(fmtdate "$m")) - expected after reboot/upgrade"
      else
        warn "$f modified $(fmtdate "$m") - not at boot time; review the changes"
        FOLLOWUP=1
      fi
    done
    [ "$HTTPDCHG" -eq 0 ] && okay "httpd.conf not modified in the last 14 days"
    # /bin/sh permissions (should not be setuid)
    SHPERM=$(ls -l /bin/sh 2>/dev/null | awk '{print $1}')
    case "$SHPERM" in
      *s*) susp "/bin/sh has setuid/setgid bit: $SHPERM - known CVE-2026-88771 post-exploitation step (GreyNoise)"; FOLLOWUP=1 ;;
      *)   okay "/bin/sh permissions: $SHPERM" ;;
    esac
    # Crash dumps (ignore FreeBSD savecore bookkeeping files)
    CORES=$(find /var/core /var/crash 2>/dev/null -type f -mtime -14 ! -name bounds ! -name minfree 2>/dev/null)
    [ -n "$CORES" ] && { warn "Core/crash files from the last 14 days (possible exploit attempts):"; echo "$CORES" | show 10; FOLLOWUP=1; } \
                    || okay "No recent core/crash files"

    # --- Persistence / process checks (adapted from deyda.net checklist) -----
    NOBODYCRON=$(crontab -l -u nobody 2>/dev/null | grep -v '^#')
    [ -n "$NOBODYCRON" ] && { warn "Crontab entries for user 'nobody' (persistence?):"; echo "$NOBODYCRON" | show 10; FOLLOWUP=1; } \
                         || okay "No crontab for user 'nobody'"
    NOBODYPS=$(ps auxww 2>/dev/null | grep '^nobody' | grep -v '/bin/httpd' | grep -v grep)
    [ -n "$NOBODYPS" ] && { warn "Processes running as 'nobody' other than httpd:"; echo "$NOBODYPS" | show 10; FOLLOWUP=1; } \
                       || okay "No unexpected 'nobody' processes"

    # --- Log checks ------------------------------------------------------------
    B64=$(grep -liE 'b64decode|base64_decode' /var/log/httperror.log* /var/log/httpaccess.log* 2>/dev/null)
    [ -n "$B64" ] && { warn "b64decode strings found in HTTP logs:"; echo "$B64" | show; FOLLOWUP=1; } \
                  || okay "No b64decode strings in HTTP logs"
    # ignore notices from the NetScaler's own management GUI (ns_gui/admin_ui/php)
    PHPERR=$(zgrep -h '\.php' /var/log/httperror.log* 2>/dev/null | grep -v 'admin_ui' | wc -l | tr -d ' ')
    PHPGUI=$(zgrep -h '\.php' /var/log/httperror.log* 2>/dev/null | grep -c 'admin_ui')
    [ "${PHPERR:-0}" -gt 0 ] && { warn "$PHPERR '.php' references in httperror logs - review: zgrep '.php' /var/log/httperror.log* | grep -v admin_ui"; FOLLOWUP=1; } \
                             || okay "No '.php' references in httperror logs$( [ "${PHPGUI:-0}" -gt 0 ] && echo " (ignored $PHPGUI from the NetScaler management GUI)")"
    # Successful VPN requests from non-Receiver/Workspace clients - summarised
    NONRCV=$(zgrep -h -E -v 'CitrixReceiver' /var/log/httpaccess-vpn.log* 2>/dev/null | grep ' 200 ')
    if [ -n "$NONRCV" ]; then
      NTOT=$(echo "$NONRCV" | wc -l | tr -d ' ')
      # drop normal Gateway logon-page traffic, keep the rest for review
      ODD=$(echo "$NONRCV" | sed -nE 's/.*"(GET|POST|HEAD|PUT|OPTIONS) ([^ ?"]*).*/\2/p' \
            | grep -vE '^/(vpn/(index|tmindex|logout|tmlogout)\.html|vpn/(login|resources|nsshare|nsutil|nscookie|pluginlist)\.js|logon/|vpn/(js|images|resources|media|scripts)/|vpn/pluginlist|cgi/(login|logout|setclient|GetAuthMethods)|vpn/init|p/u/|menu/|nf/auth|epa/|vpns/j_services\.html|favicon\.ico|robots\.txt)|^\*$' \
            | sort | uniq -c | sort -rn | head -10)
      SRCS=$(echo "$NONRCV" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5)
      TOPSRC=$(echo "$SRCS" | awk 'NR==1{print $1}')
      if [ -n "$ODD" ]; then
        warn "$NTOT successful VPN requests from non-Receiver clients - paths OTHER than normal logon pages:"
        echo "$ODD" | show 10
      else
        okay "$NTOT successful VPN requests from non-Receiver clients - all normal logon-page paths"
      fi
      note "Top source IPs:"; echo "$SRCS" | show 5
      if [ -n "$TOPSRC" ] && [ $((TOPSRC * 100 / NTOT)) -ge 95 ]; then
        note "NOTE: >=95% from one IP - client IPs are probably hidden by NAT; use firewall logs"
      fi
    else
      okay "No successful non-Receiver VPN requests in httpaccess-vpn logs"
    fi
    # CVE-2026-88771 technique (public, watchTowr 2026-09-28): shell metacharacters in
    # logon-related log entries (username, User-Agent, parameters)
    CMDS='sh|bash|csh|tcsh|curl|wget|fetch|tftp|ftp|nc|ncat|python[0-9.]*|perl|php|id|uname|echo|cat|chmod|chown|rm|mv|cp|base64|openssl|mkfifo|kill|touch'
    INJ=$( { zgrep -h -iE 'user|login|logon|agent|aaa' /var/log/ns.log* 2>/dev/null \
             | grep -E "\`|\\\$\\(|[|;&][[:space:]]*($CMDS)([[:space:]<>;|&\`]|\\\$|\$)"
           # obfuscation seen in the wild (Lupovis, 2026-09-28): \${IFS} instead of spaces,
           # fake pitboss messages as the login name: "...unexpectedly died NSPPE;<cmd>;# X" (Lupovis,
           # watchTowr PoC) and "...missed too many heartbeatsNSPPE;<cmd>" (CERT-EU). ns_monuploadd_err.pl
           # also reads /var/log/messages, so that is searched too.
           zgrep -h -E 'died[[:space:]]+NSPPE[[:space:]]*(;|%3B)|missed too many heartbeats[^"]*(;|%3B)|authenticate user :?[[:space:]]*pitboss|\$\{?IFS\}?|%24%7BIFS%7D|pitboss.*(IFS|(;|%3B)[[:space:]]*(sh|bash|curl|wget|fetch|tftp|nc|python|perl|php))|(%3B|%7C)(sh|bash|curl|wget|fetch|tftp|nc|python|perl|php)' /var/log/ns.log* /var/log/messages* 2>/dev/null
         } | sort -u | fixtag "$( [ "$VULN_BUILD" = "no" ] && echo "$FWE")" | head -20)
    [ -n "$INJ" ] && { susp "ns.log entries with shell injection patterns (CVE-2026-88771 exploitation attempts - check whether they succeeded):"; echo "$INJ" | show 10; FOLLOWUP=1; } \
                  || okay "No shell metacharacters in logon-related ns.log entries"
    # Public CVE-2026-88771 indicators (GreyNoise, Marius Sandbu, Lupovis - 28/29 Sep 2026)
    #  COMP = evidence that a command ran on this box -> compromised
    #  TGT  = attacker traffic seen in the logs      -> targeted, check whether it succeeded
    GN_HASH="6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7"
    GN_IPS="149.104.78.141 78.128.113.10 138.28.234.38 82.167.14.7 154.217.251.226 85.203.46.191"
    COMP=""; TGT=""
    # .ctxs.receiver webshell (created 24 Sep 06:52 UTC on seen boxes; HA file sync copies it to the peer)
    F=$(find /var/netscaler/logon /netscaler/ns_gui /var/vpn -name '.ctxs*' 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
webshell file: $F"
    for f in $(find /var/netscaler/logon/LogonPoint/custom /var/vpn -type f 2>/dev/null); do
      h=$(sha256 -q "$f" 2>/dev/null || sha256sum "$f" 2>/dev/null | awk '{print $1}')
      [ "$h" = "$GN_HASH" ] && COMP="$COMP
known webshell SHA-256: $f"
    done
    # PHP / webshell code where no PHP belongs (catches renamed or modified webshells)
    F=$(grep -rlE '<\?php|passthru[[:space:]]*\(|NSC_TASS' /var/netscaler/logon/LogonPoint/custom /var/vpn 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
PHP/webshell code in LogonPoint/custom or /var/vpn: $(echo $F)"
    # httpd alias exposing the webshell
    F=$(grep -nHE 'receiver\\?\.min|^[[:space:]]*Alias(Match)?[[:space:]].*/\.[^/[:space:]]+[[:space:]]*$' /etc/httpd.conf /nsconfig/httpd.conf 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
httpd alias: $F"
    # files written by exploitation (canary / id dump) - proof that the injected command ran
    # (public watchTowr PoC examples write "id" output to /var/tmp; match by name and by content)
    F=$( { find /var/vpn /var/ns /netscaler/ns_gui /var/netscaler -name 'nx_verify.html' 2>/dev/null
           ls -d /var/tmp/wtw* /var/tmp/watchTowr* /var/tmp/boom* 2>/dev/null
           find /var/tmp /tmp /var/vpn /var/netscaler/logon /netscaler/ns_gui/vpn -maxdepth 3 -type f -size -2k -mtime -30 2>/dev/null \
             | xargs grep -lE '^uid=[0-9]+\([a-z_]+\) gid=' 2>/dev/null
         } | sort -u)
    [ -n "$F" ] && COMP="$COMP
files written by exploit payloads: $(echo $F)"
    # attacker traffic in the logs
    for ip in $GN_IPS; do
      F=$(zgrep -lF "$ip" /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* 2>/dev/null)
      [ -n "$F" ] && TGT="$TGT
known exploitation IP $ip in: $(echo $F)"
    done
    FIXREF=""; [ "$VULN_BUILD" = "no" ] && FIXREF="$FWE"
    F=$(zgrep -hE 'LogonPoint/custom/receiver\.min(\.[0-9a-f]+)?\.css|httpworkbench|NX-CVE-OK|nx_verify|wtw888|ns-88771-poc|PoCbit' /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* 2>/dev/null | fixtag "$FIXREF" | head -8)
    [ -n "$F" ] && TGT="$TGT
exploit strings (webshell alias, OOB domain, canary, scanner UA):
$F"
    # Two-stage variant (CERT-EU): base64 shell command parked in the User-Agent as "INDEX:<b64>",
    # later extracted and run by an injected log line. Show the decoded command.
    F=$(zgrep -hoE 'INDEX:[A-Za-z0-9+/=]{8,}' /var/log/httpaccess* /var/log/httperror* 2>/dev/null | sort -u | head -5)
    if [ -n "$F" ]; then
      TGT="$TGT
base64 payloads in User-Agent (INDEX:, CERT-EU two-stage variant), decoded:"
      for x in $F; do
        d=$(echo "${x#INDEX:}" | perl -MMIME::Base64 -ne 'print decode_base64($_)' 2>/dev/null | tr -c '[:print:]' ' ' | cut -c1-150)
        TGT="$TGT
  ${x%"${x#????????????????????}"}... -> $d"
      done
    fi
    if [ -n "$COMP" ]; then
      susp "COMPROMISE indicators for CVE-2026-88771 - an attacker ran commands on this box (follow CTX694799, rebuild, check the HA peer):"
      echo "$COMP" | grep -v '^$' | show 15
      FOLLOWUP=1
    fi
    if [ -n "$TGT" ]; then
      if [ -n "$FIXREF" ] && echo "$TGT" | grep -q '\[after fix\]' && ! echo "$TGT" | grep -q '\[BEFORE fix\]'; then
        warn "Exploitation traffic for CVE-2026-88771 in the logs - all dated lines are AFTER the fixed build was installed ($(fmtdate "$FIXREF")):"
        echo "$TGT" | grep -v '^$' | show 15
        note "Attempts after the fix cannot run commands on this build. A 404 on a canary/alias check confirms it failed."
        note "Still review the time BEFORE the fix: logs may not reach back, so use firewall logs for that period."
      else
        susp "Exploitation traffic for CVE-2026-88771 in the logs - targeted; check the lines above/below and the files for success:"
        echo "$TGT" | grep -v '^$' | show 15
      fi
      FOLLOWUP=1
    fi
    if [ -z "$COMP$TGT" ]; then
      okay "No public CVE-2026-88771 indicators (webshell by name/hash/content, httpd alias, exploit-written files, 6 known attacker IPs, OOB/canary/scanner strings)"
      note "/etc/httpd.conf is rebuilt at boot - an alias added before a reboot is gone from there, but the webshell file is not."
    fi
    echo "             | HA pair? Run this on BOTH nodes - a clean node does not clear its peer."
    echo "             | Official IoCs: run the IoC scan in NetScaler Console > Security Advisory"
    echo "             | (Console service, or on-prem 14.1-73.36+ with Cloud Connect + telemetry),"
    echo "             | or ask Citrix Support to run it. Consider File Integrity Monitoring too."
    echo "             | Capture RAM + /var/log BEFORE upgrading/rebooting if anything looks off."
  fi
  echo
fi

# ---------------------------------------------------------------------------
# 4b. Admin partitions (each partition has its own config and TCP parameters)
# ---------------------------------------------------------------------------
PARTS=$(ls "$(dirname "$CONF")"/partitions/*/ns.conf 2>/dev/null)
if [ -n "$PARTS" ]; then
  echo "${B}Admin partitions${N}"
  PARENT_VULN="$VULN_BUILD"; export PARENT_VULN
  for pc in $PARTS; do
    sh "$0" --partition "$pc" || FOLLOWUP=1
  done
  echo
  echo "             | Per Citrix docs, TCP parameters are partition-specific: enable Enhanced ISN"
  echo "             | in the default partition AND in every admin partition, then from default:"
  echo "             |   save ns config -all"
  echo
fi

# ---------------------------------------------------------------------------
# 5. Verdict
# ---------------------------------------------------------------------------
echo "============================================================================"
case "$VULN_BUILD" in
  yes|eol)
    printf '%sVERDICT: VULNERABLE - upgrade now.%s CVE-2026-88771 and -88772 are exploited in the wild.\n' "$R$B" "$N"
    echo "Assume breach on internet-facing appliances: preserve evidence, upgrade, then hunt."
    echo "Official IoC scan: NetScaler Console > Security Advisory, or via Citrix Support."
    exit 2 ;;
  unknown)
    printf '%sVERDICT: build unknown - verify with "show ns version".%s\n' "$Y$B" "$N"
    exit 3 ;;
  no)
    if [ "$FOLLOWUP" -eq 1 ]; then
      printf '%sVERDICT: fixed build, but follow-up items above need attention.%s\n' "$Y$B" "$N"; exit 1
    fi
    printf '%sVERDICT: fixed build, no follow-up flagged.%s\n' "$G$B" "$N"
    echo "If this box was internet-facing before patching, still hunt for compromise."
    exit 0 ;;
esac
