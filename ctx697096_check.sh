#!/bin/sh
# =============================================================================
# ctx697096_check.sh
# NetScaler ADC / Gateway precondition checker for CTX697096
# (CVE-2026-88771 .. CVE-2026-88778), published 2026-09-27
#
# Version: 1.9 (2026-10-01)
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
#   Set the fix date by hand (optional, normally detected automatically):
#                               sh ctx697096_check.sh --ioc --fixdate "2026-09-27 16:32"
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
# from Manuel Winkel's NetScaler CVE checklist and triage scripts v9.17 and v9.28, deyda.net, and
# indicators from Gotham Technology Group's IoC check, shared with permission, and the
# IoC collection of PitScaler.com with its original sources, and Arctic Wolf's alert pack;
# thanks to Michael Shuster, Ferroque Systems, for review and feedback),
# NOT on Citrix IoCs - a clean result does not prove the appliance was not compromised.
# =============================================================================

VERSION="1.9"
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
    --fixdate) shift; CTXCHK_FIXDATE="$1"; export CTXCHK_FIXDATE ;;
    --fixdate=*) CTXCHK_FIXDATE="${1#--fixdate=}"; export CTXCHK_FIXDATE ;;
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
  cat "$OUTFILE"
  # Defang attacker text in the saved report (safe to paste into mail/Teams): on log lines and
  # decoded payloads only, ; | & ` $ < > become _ and http: becomes hxxp:. The screen shows the raw text.
  perl -i -pe 'if (/^ +\| / && (/\[(after fix|BEFORE fix)\]|^ +\| +[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d |\[\d+\/[A-Z][a-z]{2}\/\d{4}:| -> /)) { ($p,$r)=/^( +\| )(.*)$/s; $r=~s/[;|&`\$<>]/_/g; $r=~s/http(s?):/hxxp$1:/gi; $_=$p.$r }' "$OUTFILE" 2>/dev/null
  echo; echo "Report saved to: $OUTFILE (attacker text defanged)"
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
show() { perl -pe 's/[\x00-\x08\x0b-\x1f\x7f]/./g' 2>/dev/null | awk -v n="${1:-5}" 'NR<=n{print "             | " $0} END{if(NR>n) print "             | ... and " NR-n " more"}'; }
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
    elsif (/^\[\w{3} (\w{3})\s+(\d+) (\d+):(\d+):(\d+)(?:\.\d+)? (\d{4})\]/ && exists $m{$1}) {
      $t=timelocal($5,$4,$3,$2,$m{$1},$6) }
    $p = (!$f || !defined $t) ? "" : ($t > $f ? "[after fix] " : "[BEFORE fix] ");
    print $p.$_' "$1" 2>/dev/null
}
# BEFORE-fix lines first (order otherwise kept), so they are never hidden behind "... and N more"
bfirst() { awk '/^\[BEFORE fix\]/{print; next} {r[++n]=$0} END{for(i=1;i<=n;i++) print r[i]}'; }
# addtgt <heading> <all tagged lines> [lines to show]: add a targeted-traffic group. The yellow/red
# decision uses ALL lines (ALLTGT); only the display is shortened.
addtgt() {
  [ -n "$2" ] || return 0
  _n=${3:-3}; _t=$(printf '%s\n' "$2" | grep -c .); _b=$(printf '%s\n' "$2" | grep -c '^\[BEFORE fix\]')
  ALLTGT="$ALLTGT
$2"
  _h="$1 ($_t line(s)"; [ "$_b" -gt 0 ] && _h="$_h, $_b BEFORE the fix"; [ "$_t" -gt "$_n" ] && _h="$_h, first $_n shown"
  TGT="$TGT
$_h):
$(printf '%s\n' "$2" | bfirst | head -"$_n" | binsafe)"
}
# v1.9: show log lines safely. Lines with binary or terminal-control bytes (common in ns.log, and attackers
# can inject escape codes) could display as blank. Non-printable bytes become ".", the line is cut to 240
# characters and labelled. Only the display changes - counts and the red/yellow decision use the raw lines.
binsafe() {
  perl -ne 'chomp; $b = s/[^\t\x20-\x7e]/./g; $_ = substr($_,0,240); $_ .= "  (line contains binary data)" if $b; print "$_\n"' 2>/dev/null
}
cg() { grep -iE -e "$1" "$CONF"; }
cgq() { grep -iqE -e "$1" "$CONF"; }

NAME='("[^"]*"|[^ ]+)'   # vserver/object name, quoted or not
FOLLOWUP=0
ISN_OPEN=0

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

# On the appliance, prefer the RUNNING build (booted kernel) over the ns.conf header,
# which still shows the old build until "save ns config" is run after an upgrade.
if [ "$CONF" = "/nsconfig/ns.conf" ] && [ -d /netscaler ]; then
  KF="${CTXCHK_BOOTFILE:-$(sysctl -n kern.bootfile 2>/dev/null)}"
  RREL=$(echo "$KF" | sed -nE 's/.*ns-([0-9]+\.[0-9]+)-([0-9]+)\.([0-9]+).*/\1/p')
  RMAJ=$(echo "$KF" | sed -nE 's/.*ns-([0-9]+\.[0-9]+)-([0-9]+)\.([0-9]+).*/\2/p')
  RMIN=$(echo "$KF" | sed -nE 's/.*ns-([0-9]+\.[0-9]+)-([0-9]+)\.([0-9]+).*/\3/p')
  if [ -n "$RREL" ] && [ -n "$RMAJ" ] && [ -n "$RMIN" ]; then
    if [ -n "$REL" ] && [ "$REL-$BMAJ.$BMIN" != "$RREL-$RMAJ.$RMIN" ]; then
      warn "Saved config was written on $REL-$BMAJ.$BMIN, but the running build is $RREL-$RMAJ.$RMIN"
      note "Config not saved since the upgrade - run: save ns config. Using the running build."
      FOLLOWUP=1
    fi
    REL=$RREL; BMAJ=$RMAJ; BMIN=$RMIN
  fi
fi

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
      hit "CVE-2026-88778 (TCP ISN prediction, 8.8) - TCP vservers present, Enhanced ISN NOT enabled in this partition"; ISN_OPEN=1
      echo "             | TCP parameters are partition-specific - enable it inside this partition:"
      echo "             |   switch ns partition <name>; set ns tcpParam -enhancedISNGeneration ENABLED"
      FOLLOWUP=1
    fi
  elif cgq "^set ns tcpParam .*-enhancedISNGeneration ENABLED"; then
    ok "CVE-2026-88778 - TCP vservers present, Enhanced ISN Generation ENABLED"
  else
    hit "CVE-2026-88778 (TCP ISN prediction, 8.8) - TCP vservers present, Enhanced ISN not enabled in config"; ISN_OPEN=1
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
    # v1.8: when did the fixed build start running? installns copies the kernel to /flash as
    # ns-<build>.gz once, at install time, and writes /var/nsinstall/installns_state_post_reboot at
    # the first boot after the install. Other files in /var/nsinstall (e.g. adc.version, rewritten
    # at GUI logon) are NOT used - they made the before/after-fix tags wrong up to v1.7.
    RB="$REL-$BMAJ.$BMIN"
    KF=""; [ -n "$REL" ] && KF=$(ls /flash/ns-"$RB".gz 2>/dev/null | head -1)
    INST=""; [ -n "$KF" ] && INST=$(mtime "$KF")
    PRB=$(mtime /var/nsinstall/installns_state_post_reboot)
    FIXT=""; FIXSRC=""; STAGED=""; NKT=""
    NK=$(ls -t /flash/ns-*.gz 2>/dev/null | head -1); [ -n "$NK" ] && NKT=$(mtime "$NK")
    if [ -n "$NKT" ] && [ -n "$BOOT" ] && [ "$NKT" -gt "$((BOOT + 300))" ] && [ "$NK" != "$KF" ]; then STAGED="$NK"; fi
    if [ -n "$INST" ]; then
      if [ -n "$PRB" ] && [ "$PRB" -ge "$INST" ] && [ $((PRB - INST)) -le 86400 ]; then FIXT=$PRB; FIXSRC="first boot after the install"
      elif [ -n "$BOOT" ] && [ "$BOOT" -ge "$INST" ] && [ $((BOOT - INST)) -le 86400 ]; then FIXT=$BOOT; FIXSRC="boot after the install"
      else FIXT=$INST; FIXSRC="kernel install time"; fi
    else
      # Fallback when /flash cannot be read: install markers / build archives only, never adc.version
      NEWEST=$(ls -t /var/nsinstall 2>/dev/null | grep -E '^installns_state|^build|^[0-9]+\.[0-9]+-' | head -1)
      if [ -n "$NEWEST" ]; then
        INST=$(mtime "/var/nsinstall/$NEWEST"); FIXT=$INST; FIXSRC="/var/nsinstall/$NEWEST"
        if [ -n "$BOOT" ] && [ "$INST" -gt "$((BOOT + 300))" ]; then
          if [ "$VULN_BUILD" != "no" ]; then STAGED="/var/nsinstall/$NEWEST"; NKT=$INST
          else FIXT=$BOOT; FIXSRC="last boot (/var/nsinstall/$NEWEST is newer than the boot)"; fi
        fi
      fi
    fi
    if [ -n "$CTXCHK_FIXDATE" ]; then
      FD=$(perl -MTime::Local -e 'if ($ARGV[0] =~ /^(\d{4})-(\d\d)-(\d\d)(?:[ T](\d\d):(\d\d))?/) { print timelocal(0,$5||0,$4||0,$3,$2-1,$1) }' "$CTXCHK_FIXDATE" 2>/dev/null)
      if [ -n "$FD" ]; then FIXT=$FD; FIXSRC="set with --fixdate"; [ -n "$INST" ] || INST=$FD
      else warn "--fixdate \"$CTXCHK_FIXDATE\" not understood - use \"YYYY-MM-DD HH:MM\""; fi
    fi
    FWE="$INST"   # install time: start of the upgrade window used by the web-file checks
    if [ -n "$STAGED" ] && [ "$VULN_BUILD" != "no" ]; then
      warn "$STAGED ($(fmtdate "$NKT")) is newer than the last boot - that build is installed but NOT running yet (reboot pending?)"
      note "The running vulnerable build has been exposed since at least the last boot ($(fmtdate "$BOOT"))."
    elif [ "$VULN_BUILD" = "no" ]; then
      if [ -n "$FIXT" ]; then
        okay "Fixed build running since $(fmtdate "$FIXT") ($FIXSRC$( [ -n "$KF" ] && [ "$FIXSRC" != "kernel install time" ] && echo "; ${KF##*/} installed $(fmtdate "$INST")")) - exposure window ended here"
        note "Attack lines are tagged [BEFORE fix] / [after fix] against this time. Wrong? Set it with --fixdate \"YYYY-MM-DD HH:MM\"."
      else
        warn "Could not determine when the fixed build was installed - attack lines are not tagged before/after the fix"
        note "Set the date by hand: sh ctx697096_check.sh --ioc --fixdate \"YYYY-MM-DD HH:MM\""
      fi
    elif [ -n "$INST" ]; then
      warn "Current (vulnerable) build installed $(fmtdate "$INST") - exposure window runs from here until you patch"
    else
      warn "Could not determine when the current firmware was installed"
    fi
    if [ -n "$BOOT" ]; then
      UPD=$(( (NOW - BOOT) / 86400 ))
      if [ "$VULN_BUILD" = "no" ]; then
        if [ -n "$INST" ] && [ "$BOOT" -ge "$((INST - 300))" ]; then
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
    # v1.7: all web-served folders (Gotham), minus the one stock file
    DOTS=$(find /var/netscaler/logon /netscaler/ns_gui /var/netscaler/gui /var/vpn /netscaler/portal \
           -name '.*' -type f 2>/dev/null | grep -v '/admin_ui/php/system/\.htaccess$' | grep -v '/\.ctxs')
    [ -n "$DOTS" ] && { warn "Hidden files in web-served folders - compare with a clean appliance of the same build:"; echo "$DOTS" | show 10; FOLLOWUP=1; } \
                   || okay "No hidden files in web-served folders"
    # .dot files under LogonPoint/custom (Deyda triage script)
    DOTF=$(find /var/netscaler/logon/LogonPoint/custom -name '*.dot' -type f 2>/dev/null)
    [ -n "$DOTF" ] && { warn ".dot files under LogonPoint/custom - check when and why they were created:"; echo "$DOTF" | show 10; FOLLOWUP=1; }
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
    # v1.9 (Deyda v9.28): also .pl, .rpm and .tgz (payload scripts and packages)
    PHPERR=$(zgrep -ahE '\.(php|sh|pl|rpm|tgz)([^a-zA-Z]|$)' /var/log/httperror.log* 2>/dev/null | grep -v 'admin_ui' | wc -l | tr -d ' ')
    PHPGUI=$(zgrep -ahE '\.(php|sh|pl|rpm|tgz)([^a-zA-Z]|$)' /var/log/httperror.log* 2>/dev/null | grep -c 'admin_ui')
    [ "${PHPERR:-0}" -gt 0 ] && { warn "$PHPERR '.php'/'.sh'/'.pl'/'.rpm'/'.tgz' references in httperror logs - review: zgrep -E '\.(php|sh|pl|rpm|tgz)' /var/log/httperror.log* | grep -v admin_ui"; FOLLOWUP=1; } \
                             || okay "No '.php'/'.sh'/'.pl'/'.rpm'/'.tgz' references in httperror logs$( [ "${PHPGUI:-0}" -gt 0 ] && echo " (ignored $PHPGUI from the NetScaler management GUI)")"
    # Successful VPN requests from non-Receiver/Workspace clients - summarised
    NONRCV=$(zgrep -ah -E -v 'CitrixReceiver' /var/log/httpaccess-vpn.log* 2>/dev/null | grep ' 200 ')
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
    INJ=$( { zgrep -ah -iE 'user|login|logon|agent|aaa' /var/log/ns.log* 2>/dev/null \
             | grep -E "\`|\\\$\\(|[|;&][[:space:]]*($CMDS)([[:space:]<>;|&\`]|\\\$|\$)"
           # obfuscation seen in the wild (Lupovis, 2026-09-28): \${IFS} instead of spaces,
           # fake pitboss messages as the login name: "...unexpectedly died NSPPE;<cmd>;# X" (Lupovis,
           # watchTowr PoC) and "...missed too many heartbeatsNSPPE;<cmd>" (CERT-EU). ns_monuploadd_err.pl
           # also reads /var/log/messages, so that is searched too.
           zgrep -ah -E 'died[[:space:]]+NSPPE[[:space:]]*(;|%3B)|missed too many heartbeats[^"]*(;|%3B)|authenticate user :?[[:space:]]*pitboss|\$\{?IFS\}?|%24%7BIFS%7D|pitboss.*(IFS|b64decode|base64|(;|%3B)[[:space:]]*(sh|bash|curl|wget|fetch|tftp|nc|python|perl|php))|(%3B|%7C)(sh|bash|curl|wget|fetch|tftp|nc|python|perl|php)' /var/log/ns.log* /var/log/messages* 2>/dev/null
           # v1.9 (Elastic rule "Potential NetScaler Log Poisoning Command Injection Attempt"): any pitboss
           # packet-engine message with a shell metacharacter, also URL-encoded - catches hand-written variants
           # without a known command name after it
           zgrep -ahiE 'pitboss.*(nsppe|ppe|packet.*engine|core)' /var/log/ns.log* /var/log/messages* 2>/dev/null \
             | grep -aiE ';|`|\$\(|&&|\|\||%3b|%60|%7c|%24%28|%26%26|%3e|%3c'
         } | grep -v 'shell_command=' | sort -u | fixtag "$( [ "$VULN_BUILD" = "no" ] && echo "$FIXT")" | bfirst)
    if [ -n "$INJ" ]; then
      N_ALL=$(echo "$INJ" | grep -c .); N_AFT=$(echo "$INJ" | grep -c '^\[after fix\]'); N_BEF=$(echo "$INJ" | grep -c '^\[BEFORE fix\]')
      if [ "$VULN_BUILD" = "no" ] && [ -n "$FIXT" ] && [ "$N_ALL" -eq "$N_AFT" ]; then
        warn "ns.log entries with shell injection patterns - all $N_ALL AFTER the fixed build started running ($(fmtdate "$FIXT")):"
        echo "$INJ" | show 10
        note "Attempts after the fix cannot run commands on this build - still being targeted, not compromised."
      else
        susp "ns.log entries with shell injection patterns ($N_ALL line(s)$( [ "$N_BEF" -gt 0 ] && echo ", $N_BEF BEFORE the fix - shown first")) - CVE-2026-88771 exploitation attempts, check whether they succeeded:"
        echo "$INJ" | show 10
        note "[BEFORE fix] lines (or undated lines) may have run: the command is picked up by a background job, up to ~24h later."
      fi
      FOLLOWUP=1
    else
      okay "No shell metacharacters in logon-related ns.log entries"
    fi
    # v1.7 "ARMED" (Gotham): on a vulnerable build, injected text still sitting in the files the daily
    # ns_monuploadd_err.pl check reads next (ns.log, ns.log.0, messages) runs at its next run.
    if [ "$VULN_BUILD" != "no" ]; then
      ARMED=0; ARMF=""
      for f in /var/log/ns.log /var/log/ns.log.0 /var/log/messages; do
        [ -f "$f" ] || continue
        n=$(grep -aE 'died[[:space:]]+NSPPE[[:space:]]*(;|%3B)|missed too many heartbeats[^"]*(;|%3B)' "$f" 2>/dev/null | grep -vc 'shell_command=')
        [ "${n:-0}" -gt 0 ] && { ARMED=$((ARMED + n)); ARMF="$ARMF $f ($n)"; }
      done
      if [ "$ARMED" -gt 0 ]; then
        susp "ARMED: $ARMED injected payload line(s) waiting in files the vulnerable daily check reads next:$ARMF"
        note "On this build they run at the next daily ns_monuploadd_err.pl run. Upgrade NOW, or shut down / fail over to a patched node."
        FOLLOWUP=1
      fi
      F=$(zgrep -ah 'ns_monuploadd_err' /var/log/callhome* 2>/dev/null | grep -a 'arm restart' | tail -3 | cut -c1-160)
      [ -n "$F" ] && { note "Last runs of the daily check (callhome logs):"; echo "$F" | show 3; }
    fi
    # Public CVE-2026-88771 indicators (GreyNoise, Marius Sandbu, Lupovis - 28/29 Sep 2026)
    #  COMP = evidence that a command ran on this box -> compromised
    #  TGT  = attacker traffic seen in the logs      -> targeted, check whether it succeeded
    GN_HASH="6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7"
    # + Mandiant/GTIG (29 Sep): 143.198.7.94 (scanning/staging), 157.254.167.12 (exploitation)
    GN_IPS="149.104.78.141 78.128.113.10 138.28.234.38 82.167.14.7 154.217.251.226 85.203.46.191 143.198.7.94 157.254.167.12"
    # + Gotham Technology Group (shared with permission): download servers and senders
    GN_IPS="$GN_IPS 62.133.62.80 31.56.197.72 64.94.85.67 158.94.209.12 23.27.143.20 68.178.160.183 5.188.206.226 92.118.204.229 149.28.29.221"
    # + v1.9, compiled by PitScaler.com (30 Sep snapshot): C2, payload hosts, exfiltration, reverse shell and
    #   IR-confirmed exploitation sources (Truesec, eSentire, IFIN, Corelight, Lupovis)
    GN_IPS="$GN_IPS 104.248.244.66 139.180.152.138 77.83.199.39 78.135.96.136 80.240.22.229 89.36.231.206 91.195.240.123 138.199.200.90 194.26.29.88 34.90.151.231 144.172.108.78 185.156.46.162 153.75.82.220 216.203.21.233 185.243.41.247"
    # + v1.9, Arctic Wolf alert pack (30 Sep): reverse-shell, payload and output-exfiltration hosts
    GN_IPS="$GN_IPS 45.141.21.130 89.44.80.7 130.94.42.226 134.175.71.50 177.4.12.11"
    GN_IPRE=$(echo "$GN_IPS" | sed -e 's/\./\\./g' -e 's/ /|/g')
    GN_DOM='echvista\.com|entretiensol\.com'
    # Opportunistic scanners tagged by GreyNoise after the public PoC (via PitScaler.com): hunting leads only.
    # Cloudflare WARP egress addresses (104.28.x) are left out - they are shared by ordinary users.
    OPP_IPRE='172\.247\.44\.85|165\.227\.201\.112|173\.231\.39\.244|64\.225\.103\.14|159\.65\.104\.231|142\.93\.205\.229|182\.101\.54\.57|87\.224\.84\.82|137\.220\.53\.135|120\.28\.233\.211|149\.28\.58\.71|23\.234\.111\.22|198\.13\.159\.233|85\.221\.203\.85|46\.150\.68\.55|159\.26\.103\.184|45\.249\.89\.172|197\.52\.9\.138|180\.242\.113\.168|85\.117\.117\.248|73\.43\.85\.7|88\.180\.103\.22|194\.28\.195\.90|95\.63\.246\.50|31\.13\.192\.160|185\.170\.55\.89|104\.203\.50\.26|37\.19\.221\.171|45\.143\.167\.96|206\.232\.71\.215|130\.94\.106\.141|58\.187\.56\.89|171\.106\.10\.118|82\.24\.212\.15|178\.66\.43\.241|185\.209\.15\.246|94\.190\.77\.195|93\.177\.60\.233|68\.46\.140\.222|178\.218\.40\.232|49\.36\.107\.103|191\.37\.30\.194|23\.234\.74\.48|72\.73\.231\.73|95\.229\.84\.239|113\.137\.102\.68|47\.243\.125\.255|47\.76\.92\.109|8\.217\.173\.25|8\.210\.67\.91|47\.239\.205\.29|47\.76\.132\.65|8\.218\.219\.56|47\.76\.102\.1|47\.76\.63\.52|8\.210\.119\.74|64\.177\.93\.71|44\.252\.255\.141|194\.242\.130\.193|125\.122\.56\.47|23\.132\.164\.35|54\.70\.59\.128|44\.226\.128\.41|4\.246\.63\.96|176\.65\.148\.54'
    COMP=""; TGT=""; ALLTGT=""
    # .ctxs.receiver webshell (created 24 Sep 06:52 UTC on seen boxes; HA file sync copies it to the peer)
    F=$(find /var/netscaler/logon /netscaler/ns_gui /var/vpn -name '.ctxs*' 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
webshell file: $F"
    # + v1.9 (via PitScaler.com): IFIN .ctxs.receiver sample, eSentire .ico and .deb webshell variants.
    # Hashes differ per victim (token inside), so the content checks below matter more.
    WS_HASHES="$GN_HASH ed082f744f035035900f67edf438f2f7d0528ac501234f63d476d65273cdb9a1 5ea5ea61e9062822bee3f66ef5ff47c217178d9e31936ad6daf10c5dfae44d12 7add390ceee4a1373211b3e340451b34f08965fc4d805f94c9b8cebdc0775774"
    # + v1.9 Arctic Wolf: /xd7h/x payload, nsmon.pl, initial payload, update_c08937.pl, Platypus agent script
    AW_HASHES="73b74309f4728d169cc9edfb2767c5aadd75d39b62de93c935a86c777d2646bc 9c7bf01d2c2cb31a3609d27c1bc9abc60d86e37b7f9908547e0c75fb18b99aab 57f9f30c50240fd48d761de7961a430cdebf2c084a36bc76d376a1ce8e6dfa9d 974b69782fdf5d67b97cfd508465939e44ee10798dbcc1e82b92d78776bad938 927c7fbef2e620c1ce482c3ed67ebf53da97693c1d6c7552c77aec84ba982cf8"
    # + v1.9 via Deyda triage script v9.28 (Unit 42 update, 30 Sep): webshell / package / payload samples
    DY_HASHES="ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec 1bd314b661396c7086f6367fbbb48025e03ca2de69c073d53a8b0a38aa5fbb7d 79c65fa04541032e251fa4796b97800374b63c7982593dd1a2e0db605d429186"
    WS_HASHES="$WS_HASHES $AW_HASHES $DY_HASHES"
    for f in $(find /var/netscaler/logon/LogonPoint/custom /var/vpn /var/netscaler/gui/vpn/scripts /var/netscaler/gui/vpns/scripts /netscaler/ns_gui/vpn/scripts /netscaler/ns_gui/vpn/media -type f -size -2000k 2>/dev/null); do
      h=$(sha256 -q "$f" 2>/dev/null || sha256sum "$f" 2>/dev/null | awk '{print $1}')
      case " $WS_HASHES " in *" $h "*) [ -n "$h" ] && COMP="$COMP
known webshell/payload SHA-256: $f" ;; esac
    done
    # v1.9: Arctic Wolf payload hashes, also in the places payloads are saved (/tmp, /var/tmp, top of / and /var)
    for f in $( { find /tmp /var/tmp -maxdepth 3 -type f -size -2000k 2>/dev/null; find / /var -maxdepth 1 -type f -size -2000k 2>/dev/null; } | grep -v ctx697096); do
      h=$(sha256 -q "$f" 2>/dev/null || sha256sum "$f" 2>/dev/null | awk '{print $1}')
      case " $AW_HASHES $DY_HASHES " in *" $h "*) [ -n "$h" ] && COMP="$COMP
known payload SHA-256 (Arctic Wolf / Unit 42): $f ($(fmtdate "$(mtime "$f")"))" ;; esac
    done
    # WHIPSHOT (Mandiant): webshell code reading commands from HTTP_X_UX*, or eval/base64 on HTTP_NSC_CLIENTTYPE /
    # HTTP_NSC_LDAP. Not searched in NetScaler's own ns_gui PHP, which uses NSC_ headers legitimately.
    F=$(find /var/netscaler/logon/LogonPoint/custom /var/vpn /var/netscaler/gui/vpn/scripts /var/netscaler/gui/vpns/scripts /netscaler/ns_gui/vpn/scripts /netscaler/ns_gui/vpn/media -type f -size -2000k 2>/dev/null \
        | xargs grep -lE 'HTTP_X_UX' 2>/dev/null; \
        find /var/netscaler/logon/LogonPoint/custom /var/vpn /var/netscaler/gui/vpn/scripts /var/netscaler/gui/vpns/scripts /netscaler/ns_gui/vpn/scripts /netscaler/ns_gui/vpn/media -type f -size -2000k 2>/dev/null \
        | xargs grep -lE 'HTTP_NSC_(CLIENTTYPE|LDAP)' 2>/dev/null | xargs grep -lE 'eval|base64_decode|assert|system|passthru|shell_exec' 2>/dev/null)
    F=$(echo "$F" | grep -v '^$' | sort -u)
    [ -n "$F" ] && COMP="$COMP
WHIPSHOT-style webshell code (HTTP_X_UX / HTTP_NSC_* command headers, Mandiant): $(echo $F)"
    # SLAPSHOT tunnel (Mandiant): UXD_IDLE_EXIT in a running process environment or in dropped files
    F=$( { ps -axeww 2>/dev/null | grep 'UXD_IDLE_EXIT' | grep -vE 'grep|ctx697096' | cut -c1-160
           grep -rlE 'UXD_IDLE_EXIT' /tmp /var/tmp 2>/dev/null | grep -v ctx697096; } | head -5)
    [ -n "$F" ] && COMP="$COMP
SLAPSHOT tunnel marker UXD_IDLE_EXIT (Mandiant): $(echo $F | cut -c1-240)"
    # php_flag engine on / SetHandler for PHP in httpd.conf (Beazley, CERT-EU)
    F=$(grep -nHiE '^[[:space:]]*(php_flag|php_admin_flag)[[:space:]]+engine[[:space:]]+on|^[[:space:]]*SetHandler[[:space:]]+.*php' /etc/httpd.conf /nsconfig/httpd.conf 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
httpd.conf enables PHP (php_flag engine on / SetHandler php): $F"
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
    # v1.9: the public watchTowr CVE-2026-88772 (DTLS) tool writes a small marker to /tmp/watchTowr.
    # /tmp is in memory on NetScaler, so this file is gone after a reboot.
    F=$(ls -d /tmp/wtw* /tmp/watchTowr* /tmp/boom* 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
marker files in /tmp from exploit tools (e.g. watchTowr CVE-2026-88772 DTLS tool): $(for x in $F; do echo "$x ($(wc -c < "$x" 2>/dev/null | tr -d ' ') bytes, $(fmtdate "$(mtime "$x")"))"; done | tr '\n' ' ')"
    # v1.9 (Arctic Wolf): nsmon.pl Perl implant - hidden folder /var/tmp/.nsmon (.cfg, .state, nsmon.pl),
    # cron persistence (root, every 5 minutes) and a TCP listener on a port between 41000 and 41999.
    F=$(ls -d /var/tmp/.nsmon /var/tmp/.nsmon/.cfg /var/tmp/.nsmon/.state /var/tmp/.nsmon/nsmon.pl /var/tmp/.s 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
nsmon implant files (Arctic Wolf): $(for x in $F; do echo "$x ($(fmtdate "$(mtime "$x")"))"; done | tr '\n' ' ')"
    F=$( { grep -nH 'nsmon' /etc/crontab /nsconfig/crontab /flash/nsconfig/crontab /var/cron/tabs/* 2>/dev/null; crontab -l 2>/dev/null | grep 'nsmon' | sed 's/^/root crontab: /'; } | cut -c1-200)
    [ -n "$F" ] && COMP="$COMP
nsmon cron persistence (Arctic Wolf):
$F"
    F=$( { ps auxww 2>/dev/null | grep -E 'nsmon' | grep -vE 'grep|ctx697096' | cut -c1-200
           sockstat -4l 2>/dev/null | awk '$2 ~ /^perl/ && $6 ~ /:41[0-9][0-9][0-9]$/'; } )
    [ -n "$F" ] && COMP="$COMP
nsmon process or Perl listener on port 41000-41999 (Arctic Wolf):
$F"
    # v1.7: files the known payloads drop (Gotham Technology Group)
    F=$( { ls -d /.x /s /tmp/s /var/tmp/s /lula /tmp/lula /var/tmp/lula /var/1.py 2>/dev/null
           find / /tmp /var/tmp -maxdepth 1 -name 'update_c*.pl' 2>/dev/null
           find /var/netscaler/logon/themes -maxdepth 1 -name 'wt88771*' 2>/dev/null
           ls -d /var/tmp/wtw888* 2>/dev/null; } | sort -u)
    [ -n "$F" ] && COMP="$COMP
files dropped by known payloads (Gotham): $(for x in $F; do echo "$x ($(fmtdate "$(mtime "$x")"))"; done | tr '\n' ' ')"
    # Files the payloads write stolen data or loaders into (Gotham + Deyda). Contents are NOT
    # shown - they can hold configuration data. Preserve and inspect them securely.
    F=$(ls -d /var/netscaler/logon/insight-new.js /netscaler/ns_gui/admin_ui/e.txt /netscaler/ns_gui/admin_ui/log.txt \
              /var/netscaler/gui/admin_ui/e.txt /var/netscaler/gui/admin_ui/log.txt 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
payload-targeted files (contents not shown - may hold config data): $(for x in $F; do echo "$x ($(wc -c < "$x" | tr -d ' ') bytes, $(fmtdate "$(mtime "$x")"))"; done | tr '\n' ' ')"
    # Payload output files seen in the wild on 29 Sep 2026 (tested on a production appliance):
    # c88771.json (expr test) and xua.html (tar of /flash/nsconfig disguised as a web page)
    F=$(find /var/netscaler/logon /netscaler/ns_gui /var/netscaler/gui /var/vpn /var/ns/gui -type f \( -name 'c88771*' -o -name 'xua.html' \) 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
payload output files (c88771.json / xua.html): $(for x in $F; do echo "$x ($(fmtdate "$(mtime "$x")"))"; done | tr '\n' ' ')"
    # Any archive disguised as a web file: .html/.htm/.json/.css/.js/.txt whose content is gzip or tar
    # (how a stolen /flash/nsconfig is staged for download, whatever the file is called)
    F=$(find /var/netscaler/logon /netscaler/ns_gui /var/netscaler/gui /var/vpn /var/ns/gui -type f \
          \( -name '*.html' -o -name '*.htm' -o -name '*.json' -o -name '*.css' -o -name '*.js' -o -name '*.txt' \) -size +0 2>/dev/null \
        | perl -ne 'chomp; open(my $h,"<",$_) or next; binmode $h; read($h,my $b,265); close $h;
                    print "$_\n" if substr($b,0,2) eq "\x1f\x8b" || (length($b)>=262 && substr($b,257,5) eq "ustar") || substr($b,0,4) eq "PK\x03\x04"' 2>/dev/null | head -10)
    [ -n "$F" ] && COMP="$COMP
archive disguised as a web file (gzip/tar/zip content - possible stolen config staged for download): $(for x in $F; do echo "$x ($(wc -c < "$x" | tr -d ' ') bytes, $(fmtdate "$(mtime "$x")"))"; done | tr '\n' ' ')"
    # Setuid shell copy in /var/tmp (Deyda)
    if [ -e /var/tmp/sh ]; then
      if [ -u /var/tmp/sh ]; then COMP="$COMP
setuid shell copy: /var/tmp/sh ($(ls -l /var/tmp/sh | awk '{print $1}'))"
      else warn "/var/tmp/sh exists (not setuid) - a shell binary should not be in /var/tmp; check why"; FOLLOWUP=1; fi
    fi
    # Persistence in startup files (Deyda): Python one-liners, decoders and reversed strings
    # (fnoc.dptth = httpd.conf, php.xedni = index.php, relacsten = netscaler, hs/pmt/rav/ = /var/tmp/sh,
    #  tnioPnogoL = LogonPoint, gifnocsn = nsconfig) used to hide persistence in earlier NetScaler campaigns
    F=$(grep -nHiE 'python[0-9.]*[[:space:]]+-c|base64[.](b64|b85)decode|zlib[.]decompress|fnoc[.]dptth|php[.]xedni|relacsten|hs/pmt/rav/|tnioPnogoL|gifnocsn' \
          /flash/nsconfig/rc.netscaler /nsconfig/rc.netscaler /nsconfig/ns.conf /etc/rc /etc/rc.conf.defaults 2>/dev/null | cut -c1-200)
    [ -n "$F" ] && COMP="$COMP
persistence strings in startup files (Python one-liner / decoder / reversed paths):
$F"
    # v1.9 (Beazley Security): /nsconfig/nsafter.sh runs after every boot - a persistence spot like rc.netscaler
    F=$(grep -nHiE 'python[0-9.]*|base64|b64decode|zlib|curl|wget|fetch[[:space:]]|(^|[^a-z])nc[[:space:]]|chmod[[:space:]]+[ug]?\+?s|chmod[[:space:]]+[0-7]*[4-7][0-7]{3}|/var/netscaler/logon|/netscaler/ns_gui|/var/vpn|/var/netscaler/gui|httpd\.conf' \
          /nsconfig/nsafter.sh /flash/nsconfig/nsafter.sh 2>/dev/null | grep -v ':[0-9]*:[[:space:]]*#' | cut -c1-200)
    [ -n "$F" ] && COMP="$COMP
suspicious commands in nsafter.sh (runs after every boot - persistence, Beazley):
$F"
    for f in /nsconfig/nsafter.sh /flash/nsconfig/nsafter.sh; do
      [ -f "$f" ] || continue; m=$(mtime "$f")
      [ -n "$m" ] && [ $((NOW - m)) -lt 2592000 ] && [ -z "$F" ] && { warn "$f changed $(fmtdate "$m") (runs after every boot) - confirm the change was yours:"; grep -v '^[[:space:]]*#' "$f" | grep -v '^[[:space:]]*$' | show 5; FOLLOWUP=1; }
    done
    # v1.9 (Beazley Security): cron jobs used to wipe forensic traces. User crontabs only (/var/cron/tabs);
    # NetScaler's own jobs live in /etc/crontab.
    F=$(for t in /var/cron/tabs/*; do [ -f "$t" ] || continue
          grep -HvE '^[[:space:]]*(#|$)' "$t" 2>/dev/null | grep -E '(rm[[:space:]]+-|rm[[:space:]]+/|truncate|find[^|;]*-delete|find[^|;]*-exec[[:space:]]+rm|(^|[^0-9>])>[[:space:]]*/var/(log|nslog|tmp|core)|cat[[:space:]]+/dev/null[[:space:]]*>)' \
          | grep -E '/var/log|/var/nslog|/var/tmp|/tmp|/var/core|/var/netscaler|/netscaler|/var/vpn|history|\.log'; done | cut -c1-200)
    [ -n "$F" ] && COMP="$COMP
cron job that deletes or empties logs/files (trace wiping, Beazley):
$F"
    [ -z "$F" ] && F=$(grep -nHi 'python' /flash/nsconfig/rc.netscaler /nsconfig/rc.netscaler 2>/dev/null | cut -c1-200) && [ -n "$F" ] && { warn "Python referenced in rc.netscaler - compare with the approved startup file:"; echo "$F" | show 5; FOLLOWUP=1; }
    # Script files in the Gateway client-package folders (Gotham): these should only hold packages/images
    F=""
    for d in /var/netscaler/gui/vpn/scripts/linux /var/netscaler/gui/vpns/scripts/vista /var/netscaler/gui/vpns/scripts/mac \
             /netscaler/ns_gui/vpn/media /var/vpn/theme; do
      for x in $(find "$d" -maxdepth 1 -type f 2>/dev/null); do
        case "$x" in *.xml|*.js|*.css|*.html|*.htm|*.txt|*.json|*.svg|*.map) continue ;; esac
        grep -q '<?php' "$x" 2>/dev/null && continue   # already reported as PHP/webshell code
        if command -v file >/dev/null 2>&1; then
          file "$x" 2>/dev/null | grep -qiE 'PHP script|shell script|perl script|python script|ASCII text|UTF-8 Unicode text' && F="$F $x"
        else
          grep -qE '<\?php|^#!' "$x" 2>/dev/null && F="$F $x"
        fi
      done
    done
    [ -n "$F" ] && COMP="$COMP
text/script files in Gateway client-package folders (should only hold packages/images):$F"
    # Live state (Gotham): payload processes and open connections to campaign infrastructure
    F=$(ps auxww 2>/dev/null | grep -E 'lula|update_c|nsmon|xd7h|/\.x([[:space:]]|$)|/var/1\.py' | grep -vE 'grep|ctx697096')
    [ -n "$F" ] && COMP="$COMP
payload process running now:
$(echo "$F" | cut -c1-200)"
    F=$(netstat -an 2>/dev/null | grep -E "$GN_IPRE|$GN_DOM")
    [ -n "$F" ] && COMP="$COMP
open connection to campaign infrastructure NOW:
$F"
    # attacker traffic in the logs (show the dated lines, tagged before/after the fix)
    FIXREF=""; [ "$VULN_BUILD" = "no" ] && FIXREF="$FIXT"
    for ip in $GN_IPS; do
      F=$(zgrep -ahF "$ip" /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* 2>/dev/null | grep -v 'shell_command=' | fixtag "$FIXREF")
      addtgt "known exploitation IP $ip" "$F" 3
    done
    addtgt "attacker domains echvista.com (IFIN) / entretiensol.com (Arctic Wolf)" "$(zgrep -ahE "$GN_DOM" /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* 2>/dev/null | grep -v 'shell_command=' | fixtag "$FIXREF")" 3
    F=$(zgrep -ahE "(^|[^0-9.])($OPP_IPRE)([^0-9]|$)" /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* 2>/dev/null | grep -v 'shell_command=' | fixtag "$FIXREF")
    if [ -n "$F" ]; then
      addtgt "opportunistic scanner IPs tagged by GreyNoise (hunting lead only - often residential/proxy, do not block on this alone)" "$F" 3
      TGT="$TGT
  IPs seen: $(echo "$F" | grep -oE "(^|[^0-9.])($OPP_IPRE)([^0-9]|$)" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn | head -6 | awk '{printf "%s x%s  ", $2, $1}')"
    fi
    F=$(zgrep -ahE 'LogonPoint/custom/receiver\.min(\.[0-9a-f]+)?\.css|httpworkbench|NX-CVE-OK|nx_verify|wtw888|ns-88771-poc|PoCbit|c88771\.json|xua\.html|xd7h/|nsmon|update_c08937|/dev/tcp/|nc[[:space:]]+-e[[:space:]]|base64[[:space:]]+-w0|exec-ok|HTTP_X_UX|HTTP_NSC_(LDAP|CLIENTTYPE)' /var/log/httpaccess* /var/log/httperror* /var/log/ns.log* /var/log/messages* 2>/dev/null | grep -v 'shell_command=' | fixtag "$FIXREF")
    addtgt "exploit strings (webshell alias, OOB domain, canary, payload files, reverse shells, webshell header names, scanner UA)" "$F" 8
    # v1.7 probe / recon markers (Gotham): 1-byte nsepa.deb pre-check (HTTP 206), vp_probe_nonexist,
    # scanner-probe logins. They show the box was found and tested.
    addtgt "1-byte nsepa.deb pre-check probes" "$(zgrep -ahE 'nsepa\.deb' /var/log/httpaccess* 2>/dev/null | grep -E '" 206 1 ' | fixtag "$FIXREF")" 3
    addtgt "recon marker vp_probe_nonexist" "$(zgrep -ahE 'vp_probe_nonexist' /var/log/httperror* /var/log/httpaccess* 2>/dev/null | fixtag "$FIXREF")" 3
    addtgt "scanner-probe logins" "$(zgrep -ahE 'scanner-probe' /var/log/ns.log* 2>/dev/null | grep -v 'shell_command=' | fixtag "$FIXREF")" 3
    # Requests for the webshell name = someone checking whether it already exists (Gotham)
    F=$(zgrep -ahE 'ctxs\.receiver' /var/log/httpaccess* 2>/dev/null | fixtag "$FIXREF")
    if [ -n "$F" ]; then
      addtgt "requests for .ctxs.receiver (webshell probing)" "$F" 3
      TGT="$TGT
  per source IP: $(echo "$F" | sed -E 's/^\[[^]]*\] //' | awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | awk '{printf "%s x%s  ", $2, $1}')"
    fi
    # Two-stage variant (CERT-EU): base64 shell command parked in the User-Agent as "INDEX:<b64>",
    # later extracted and run by an injected log line. Show the decoded command.
    FA=$(zgrep -ahE 'INDEX:[A-Za-z0-9+/=]{8,}' /var/log/httpaccess* /var/log/httperror* 2>/dev/null | fixtag "$FIXREF")
    if [ -n "$FA" ]; then
      ALLTGT="$ALLTGT
$FA"
      _t=$(echo "$FA" | grep -c .); _b=$(echo "$FA" | grep -c '^\[BEFORE fix\]')
      TGT="$TGT
base64 payloads in User-Agent (INDEX:, CERT-EU two-stage variant) ($_t line(s)$( [ "$_b" -gt 0 ] && echo ", $_b BEFORE the fix")$( [ "$_t" -gt 5 ] && echo ", first 5 shown")), decoded:"
      F=$(echo "$FA" | bfirst | head -5)
      OIFS=$IFS; IFS='
'
      for L in $F; do
        tg=$(echo "$L" | grep -oE '^\[(after fix|BEFORE fix)\] ')
        x=$(echo "$L" | grep -oE 'INDEX:[A-Za-z0-9+/=]{8,}' | head -1)
        d=$(echo "${x#INDEX:}" | perl -MMIME::Base64 -ne 'print decode_base64($_)' 2>/dev/null | tr -c '[:print:]' ' ' | cut -c1-150)
        TGT="$TGT
${tg}${x%"${x#????????????????????}"}... -> $d"
      done
      IFS=$OIFS
    fi
    # Mandiant/GTIG (29 Sep 2026): webshells disguised as client packages / signatures / icons
    # in the Gateway plugin folders, served via httpd.conf handlers for non-.php extensions.
    F=$(grep -nHiE 'Add(Handler|Type)[[:space:]]+["'"'"']?application/x-httpd-php["'"'"']?[[:space:]]+\.' /etc/httpd.conf /nsconfig/httpd.conf 2>/dev/null \
        | grep -viE 'x-httpd-php["'"'"']?[[:space:]]+\.php[s]?([[:space:]]|$)')
    [ -n "$F" ] && COMP="$COMP
httpd.conf runs a non-.php extension as PHP: $F"
    F=$(grep -nHiE '^[[:space:]]*AliasMatch.*(/vpns?/(media|theme|themes|images|help|logon|support)/|vpns?/scripts/)' /etc/httpd.conf /nsconfig/httpd.conf 2>/dev/null)
    [ -n "$F" ] && COMP="$COMP
httpd.conf AliasMatch into Gateway folders: $F"
    F=$(find /var/netscaler/gui/vpn/scripts /var/netscaler/gui/vpns/scripts /netscaler/ns_gui/vpn/scripts /netscaler/ns_gui/vpn/media -type f 2>/dev/null \
        | xargs grep -lE '<\?php|eval\(|base64_decode\(|shell_exec\(|passthru\(' 2>/dev/null | head -10)
    [ -n "$F" ] && COMP="$COMP
PHP/webshell code in Gateway plugin or media folders (should only hold packages/images): $(echo $F)"
    F=$(ls -a /tmp/.uxdport* /tmp/.uxdlock* 2>/dev/null; ps auxww 2>/dev/null | grep -E 'python.*(uxdport|uxdlock|b64decode|base64)' | grep -v grep)
    [ -n "$F" ] && COMP="$COMP
tunnel artefacts (/tmp/.uxdport, /tmp/.uxdlock or python started from base64): $(echo $F | cut -c1-200)"
    # 88772 (DTLS) attempts and resulting packet-engine crashes in the logs
    addtgt "possible CVE-2026-88772 (DTLS) attempts / packet-engine crashes (Mandiant)" "$(zgrep -ahE 'ClientVersion DTLSv1\.0.*Handshake failure-Internal Error|exit with orphan rings|NOT restarting NSPPE' /var/log/ns.log* /var/log/messages* 2>/dev/null | fixtag "$FIXREF")" 5
    # v1.9 (Deyda v9.28): DTLS handshake failures AND packet-engine crashes together = likely CVE-2026-88772 attempt
    if zgrep -ahE 'ClientVersion DTLSv1\.0.*Handshake failure-Internal Error' /var/log/ns.log* /var/log/messages* 2>/dev/null | grep -q . \
       && zgrep -ahE 'exit with orphan rings|NOT restarting NSPPE' /var/log/ns.log* /var/log/messages* 2>/dev/null | grep -q .; then
      TGT="$TGT
  !! DTLS handshake failures AND packet-engine crashes both present: likely CVE-2026-88772 exploitation attempt - compare their times, check /var/core"
    fi
    # v1.9 (Deyda v9.28): attack payloads in requests to the login pages, as recorded in the HTTP logs
    # (still visible after ns.log has rotated). Normal requests to these pages are not flagged.
    addtgt "attack payload in a login-page request (HTTP logs)" "$(zgrep -ahiE '(/nf/auth/doAuthentication\.do|/cgi/login|/p/u/doLogon\.do|/logon/LogonPoint/tmindex\.html|/logon/LogonPoint/Authentication/GetUserName)[^[:cntrl:]]*(pitboss|NSPPE|PPE unexpectedly died|missed too many heartbeats|%3B|%60|\$\{IFS\}|curl[[:space:]]|wget[[:space:]]|fetch[[:space:]])' /var/log/httpaccess* /var/log/httperror* 2>/dev/null | fixtag "$FIXREF")" 3
    addtgt "errors for package/signature/icon files in Gateway folders (possible webshell staging)" "$(zgrep -ahiE '/vpns?/scripts/[^ ]*\.(deb|sig|php)|/vpn/media/[^ ]*\.ico' /var/log/httperror* 2>/dev/null | fixtag "$FIXREF")" 3
    # Webshells differ per appliance (Kevin Beaumont), so also look for PHP / shell scripts
    # in /netscaler/ns_gui written after boot (it is unpacked from the firmware at boot)
    if [ -n "$BOOT" ]; then
      NOWM=$(date +%s); AGE=$(( (NOWM - BOOT) / 60 - 30 ))
      if [ "$AGE" -gt 0 ]; then
        F=$(find /netscaler/ns_gui -type f \( -name '*.php' -o -name '*.sh' -o -name '*.pl' \) -mmin -"$AGE" 2>/dev/null | head -10)
        [ -n "$F" ] && COMP="$COMP
PHP/shell scripts in /netscaler/ns_gui written after boot: $(echo $F)"
      fi
    fi
    # v1.9 base64 PHP ("PD9" = "<?") in the User-Agent, e.g. GET /vpn/media/*.ico: webshell staging through the
    # access log (eSentire, CERT-EU technique). Shown decoded.
    FA=$(zgrep -ahE '"[^"]*[^A-Za-z0-9+/:]PD9[A-Za-z0-9+/]{16,}={0,2}[^"]*"' /var/log/httpaccess* 2>/dev/null | grep -v 'INDEX:' | fixtag "$FIXREF")
    if [ -n "$FA" ]; then
      ALLTGT="$ALLTGT
$FA"
      _t=$(echo "$FA" | grep -c .); _b=$(echo "$FA" | grep -c '^\[BEFORE fix\]')
      TGT="$TGT
base64 PHP (PD9...) in the User-Agent - webshell staging via the access log (eSentire) ($_t line(s)$( [ "$_b" -gt 0 ] && echo ", $_b BEFORE the fix")$( [ "$_t" -gt 3 ] && echo ", first 3 shown")), decoded:"
      F=$(echo "$FA" | bfirst | head -3)
      OIFS=$IFS; IFS='
'
      for L in $F; do
        tg=$(echo "$L" | grep -oE '^\[(after fix|BEFORE fix)\] ')
        u=$(echo "$L" | grep -oE '"(GET|POST|HEAD) [^ ]+' | head -1 | tr -d '"')
        x=$(echo "$L" | grep -oE '[^A-Za-z0-9+/:]PD9[A-Za-z0-9+/]{16,}={0,2}' | head -1 | cut -c2-)
        d=$(echo "$x" | perl -MMIME::Base64 -ne 'print decode_base64($_)' 2>/dev/null | tr -c '[:print:]' ' ' | cut -c1-140)
        TGT="$TGT
${tg}${u} -> $d"
      done
      IFS=$OIFS
    fi
    # Base64 blob as the whole User-Agent (Kevin Beaumont), decoded
    FA=$(zgrep -ahE '" "[A-Za-z0-9+/]{40,}={0,2}"' /var/log/httpaccess* 2>/dev/null | fixtag "$FIXREF")
    if [ -n "$FA" ]; then
      ALLTGT="$ALLTGT
$FA"
      _t=$(echo "$FA" | grep -c .); _b=$(echo "$FA" | grep -c '^\[BEFORE fix\]')
      TGT="$TGT
User-Agent that is only a base64 string ($_t line(s)$( [ "$_b" -gt 0 ] && echo ", $_b BEFORE the fix")$( [ "$_t" -gt 3 ] && echo ", first 3 shown")), decoded:"
      F=$(echo "$FA" | bfirst | head -3)
      OIFS=$IFS; IFS='
'
      for L in $F; do
        tg=$(echo "$L" | grep -oE '^\[(after fix|BEFORE fix)\] ')
        x=$(echo "$L" | grep -oE '" "[A-Za-z0-9+/]{40,}={0,2}"' | tail -1 | tr -d '" ')
        d=$(echo "$x" | perl -MMIME::Base64 -ne 'print decode_base64($_)' 2>/dev/null | tr -c '[:print:]' ' ' | cut -c1-150)
        TGT="$TGT
${tg}$(echo "$x" | cut -c1-16)... -> $d"
      done
      IFS=$OIFS
    fi
    # Post-exploitation in shell history: LDAP credential theft via the bind account (Kevin Beaumont)
    addtgt "shell history with ldapsearch / openssl s_client / ns_gui/vpn (post-exploitation, check who ran it)" "$(zgrep -ahE 'ldapsearch|openssl[[:space:]]+s_client|ns_gui/vpn' /var/log/sh.log* /var/log/bash.log* 2>/dev/null | fixtag "$FIXREF")" 5
    # v1.7 key / config theft in shell history (Deyda triage script)
    addtgt "shell history touching keys / config / auth files (possible key or credential theft - check who ran it; if before the fix, rotate keys and passwords)" "$(zgrep -ahE '/flash/nsconfig/keys|F[12]\.key|database\.php|LDAPTLS_REQCERT|cp[[:space:]]+/usr/bin/bash|del[[:space:]]+/etc/auth\.conf' /var/log/sh.log* /var/log/bash.log* 2>/dev/null | fixtag "$FIXREF")" 5
    if [ -n "$COMP" ]; then
      susp "COMPROMISE indicators (CVE-2026-88771/88772) - an attacker ran commands on this box (follow CTX694799, rebuild, check the HA peer):"
      echo "$COMP" | grep -v '^$' | show 20
      note "Do NOT reboot or upgrade yet: copy this report, /var/log and the files above off the box first."
      note "Then isolate it (fail over / firewall), disable HA sync, rebuild, rotate ALL secrets."
      FOLLOWUP=1
    fi
    if [ -n "$TGT" ]; then
      TG_BEF=$(echo "$ALLTGT" | grep -c '^\[BEFORE fix\]'); TG_ALL=$(echo "$ALLTGT" | grep -c .)
      if [ -n "$FIXREF" ] && [ "$TG_BEF" -eq 0 ] && echo "$ALLTGT" | grep -q '^\[after fix\]'; then
        warn "Exploitation traffic for CVE-2026-88771/88772 in the logs - all dated lines are AFTER the fixed build started running ($(fmtdate "$FIXREF")):"
        echo "$TGT" | grep -v '^$' | show 25
        note "Attempts after the fix cannot run commands on this build. A 404 on a canary/alias check confirms it failed."
        note "Still review the time BEFORE the fix: logs may not reach back, so use firewall logs for that period."
      else
        susp "Exploitation traffic for CVE-2026-88771/88772 in the logs - targeted$( [ "$TG_BEF" -gt 0 ] && echo "; $TG_BEF of $TG_ALL line(s) BEFORE the fix, shown first in each group"); check whether it succeeded:"
        echo "$TGT" | grep -v '^$' | show 40
        [ "$TG_BEF" -gt 0 ] && note "A [BEFORE fix] attempt may have run: the command is picked up by a background job, up to ~24h later. Look for the files it tried to write (persistent /var paths) and check the COMPROMISE section."
      fi
      FOLLOWUP=1
    fi
    if [ -z "$COMP$TGT" ]; then
      okay "No public CVE-2026-88771/88772 indicators (webshells, dropped files, persistence, 37 known attacker IPs + GreyNoise scanners, probe/canary/scanner strings)"
      note "/etc/httpd.conf is rebuilt at boot - an alias added before a reboot is gone from there, but the webshell file is not."
    fi

    # --- v1.7 live state and recent changes outside the web folders (Gotham) ------
    # Generic download / one-liner processes: NetScaler's own jobs use some of these, so [CHECK]
    F=$(ps auxww 2>/dev/null | grep -E 'curl|wget|perl -e|\| *perl|sh -c|(^|[[:space:]/])nc -' \
        | grep -vE 'grep|ctx697096|/netscaler/monitors/|showtechsupport|nsconmsg|pitboss_check|gotham_ioc' | cut -c1-200)
    [ -n "$F" ] && { warn "Processes running download tools or one-liners - check they are NetScaler's own jobs:"; echo "$F" | show 8; FOLLOWUP=1; }
    # Connections from the management plane to public addresses
    F=$(sockstat -4c 2>/dev/null | awk 'NR>1 && $7 !~ /^(10\.|192\.168\.|127\.|172\.(1[6-9]|2[0-9]|3[01])\.|\*)/ {print}' | grep -viE 'nsppe')
    [ -n "$F" ] && { warn "Connections from the management plane to public addresses - check each is expected:"; echo "$F" | show 8; FOLLOWUP=1; }
    # v1.9 (Deyda v9.28): PHP / XHTML files under /var/netscaler outside the management GUI and websocketd,
    # with a content check. [CHECK]: customisations can be legitimate.
    F=$(find /var/netscaler -type f \( -name '*.php' -o -name '*.xhtml' \) ! -path '/var/netscaler/gui/admin_ui/*' ! -path '/var/netscaler/websocketd/*' 2>/dev/null | head -50)
    if [ -n "$F" ]; then
      warn "PHP/XHTML files under /var/netscaler outside admin_ui and websocketd - compare with a clean same-build appliance:"
      echo "$F" | show 8
      H=$(echo "$F" | xargs grep -liE 'base64_decode[[:space:]]*\(|eval[[:space:]]*\(|passthru[[:space:]]*\(|shell_exec[[:space:]]*\(|system[[:space:]]*\(|proc_open[[:space:]]*\(|NSC_TASS' 2>/dev/null)
      [ -n "$H" ] && { note "Of these, webshell-like code (eval/system/passthru/base64_decode) in:"; echo "$H" | show 8; }
      FOLLOWUP=1
    fi
    # Files changed in the last 3 days at the top of / and /var, and in /tmp and /var/tmp
    # (where payloads drop files), minus NetScaler's own files and anything written at boot/upgrade
    F=$( { find / /var -maxdepth 1 -type f -mtime -3 2>/dev/null
           find /tmp /var/tmp -maxdepth 2 -type f -mtime -3 2>/dev/null; } \
       | grep -vE '/var/tmp/(pitboss_check|gotham_ioc|support|ioc|ns_system_backup|\.shrun|ch_metrics|netscaler-ioc-check)|/tmp/(\.|pb\.sock|hostname\.txt|DIFF_)|\.(log|gz|lock|pid|sock)$|/var/tmp/par-[0-9a-f]+/|/tmp/_nsprofmon_tmp_file|/var/tmp/_tmp_(local|latest)_mapfile_digest|/tmp/machine\.counters\.list|/tmp/[0-9a-f]{8}\.(so|pl)$|/tmp/(GslbSync\.so|Config_git\.pl)$|^/var/(results[^/]*|ioc-script[^/]*|gotham_ioc[^/]*|\.monit\.state|\.monit\.id|ns_system_backup\.pl)$|/var/tmp/(install_pre_check\.json|_callhome_tmp_file)$|^/\.nscli_history$|ctx697096' \
       | while read -r x; do
           m=$(mtime "$x"); [ -n "$m" ] || continue
           # NetScaler Console Security Advisory scan: detection scripts plus its log.txt / results.txt
           case "$x" in /var/tmp/*-detection.py|/var/tmp/*_detection.py|/var/tmp/*_detetction.py) continue ;; esac
           case "$x" in /var/tmp/log.txt|/var/tmp/results.txt)
             sa=0; for d in /var/tmp/*-detection.py /var/tmp/*_detection.py /var/tmp/*_detetction.py; do
               [ -f "$d" ] || continue; dm=$(mtime "$d")
               [ -n "$dm" ] && [ $((m - dm)) -le 300 ] && [ $((dm - m)) -le 300 ] && { sa=1; break; }
             done
             [ "$sa" -eq 1 ] && continue ;;
           esac
           [ -n "$BOOT" ] && [ "$m" -ge "$((BOOT - 60))" ] && [ "$m" -le "$((BOOT + 900))" ] && continue
           [ -n "$FWE" ] && [ "$m" -ge "$((FWE - 900))" ] && [ "$m" -le "$((FWE + 900))" ] && continue
           echo "$(fmtdate "$m")  $x"
         done | sort | head -30)
    [ -n "$F" ] && { warn "Files changed in the last 3 days in / , /var (top level), /tmp or /var/tmp - payloads drop files here:"; echo "$F" | show 15
                     note "Expected: backups, Console/ADM scripts, client-package refreshes, your own tools. Anything else needs review."; FOLLOWUP=1; } \
                || okay "No unexpected files changed in the last 3 days in / , /var, /tmp or /var/tmp"
    # Root crontab lines that download something
    F=$( { grep -hE 'curl|wget|fetch[[:space:]]' /etc/crontab 2>/dev/null; crontab -l 2>/dev/null | grep -E 'curl|wget|fetch[[:space:]]'; } | grep -v '^#' \
        | grep -vE '(curl|wget|fetch)[^|;&]*[[:space:]]"?(https?://)?(localhost|127\.0\.0\.1)([:/"[:space:]]|$)')
    [ -n "$F" ] && { warn "Root crontab lines that download from the network - compare with a clean appliance:"; echo "$F" | show 5; FOLLOWUP=1; }
    # v1.9: crontabs for users other than root (Beazley: check /var/cron/tabs, root and nsroot)
    F=$(for t in /var/cron/tabs/*; do [ -f "$t" ] || continue; case "${t##*/}" in root|nobody) continue ;; esac
          n=$(grep -cvE '^[[:space:]]*(#|$)' "$t" 2>/dev/null); [ "${n:-0}" -gt 0 ] && echo "${t##*/} ($n job(s), changed $(fmtdate "$(mtime "$t")")): $(grep -vE '^[[:space:]]*(#|$)' "$t" | head -2 | tr '\n' ' ' | cut -c1-140)"; done)
    [ -n "$F" ] && { warn "Crontabs for users other than root - check each job is expected:"; echo "$F" | show 8; FOLLOWUP=1; }
    # Packet engines started after boot = crashed and restarted (possible CVE-2026-88772 DTLS overflow);
    # works even when the crash lines have rotated out of the logs
    if [ -n "$BOOT" ]; then
      F=$(ps -axo lstart,command 2>/dev/null | grep -E 'NSPPE-[0-9]' | grep -v grep \
          | perl -MTime::Local -ne 'BEGIN{$b=shift @ARGV; %m=(Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11)}
               if (/^\s*\w{3}\s+(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d{4})\s+(.*)$/ && exists $m{$1}) {
                 $t=timelocal($5,$4,$3,$2,$m{$1},$6); print "$_" if $t > $b + 900 }' "$BOOT" 2>/dev/null)
      [ -n "$F" ] && { warn "Packet engine(s) started more than 15 min after boot - they crashed and restarted (possible CVE-2026-88772):"; echo "$F" | show 5
                       note "Confirm whether this was planned (e.g. a core capture requested by Citrix Support)."; FOLLOWUP=1; }
    fi
    # Headless browser automation against the Gateway (Deyda) - can be legitimate monitoring
    F=$(zgrep -ahE 'HeadlessChrome' /var/log/httpaccess-vpn.log* 2>/dev/null | fixtag "$FIXREF" | tail -3)
    [ -n "$F" ] && { warn "HeadlessChrome user agent in VPN access logs - automation; check source, URL and time:"; echo "$F" | cut -c1-240 | show 3; FOLLOWUP=1; }
    echo "             | /tmp is emptied at reboot: after a reboot, CVE-2026-88772 (DTLS) traces are mainly packet-engine"
    echo "             | crashes/restarts and /var/core dumps (checked above)."
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
    PO=$(sh "$0" --partition "$pc"); PRC=$?
    echo "$PO"; [ "$PRC" -ne 0 ] && FOLLOWUP=1
    echo "$PO" | grep -q 'CVE-2026-88778 (TCP ISN' && ISN_OPEN=1
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
    printf '%sVERDICT: VULNERABLE - upgrade now.%s The fixed build covers all eight CVEs in CTX697096; CVE-2026-88771 and -88772 are exploited in the wild.\n' "$R$B" "$N"
    [ "$ISN_OPEN" -eq 1 ] && echo "After the upgrade, also enable Enhanced ISN: CVE-2026-88778 needs that config change."
    echo "Assume breach on internet-facing appliances: preserve evidence, upgrade, then hunt."
    echo "Official IoC scan: NetScaler Console > Security Advisory, or via Citrix Support."
    exit 2 ;;
  unknown)
    printf '%sVERDICT: build unknown - verify with "show ns version".%s\n' "$Y$B" "$N"
    exit 3 ;;
  no)
    if [ "$ISN_OPEN" -eq 1 ]; then
      printf '%sVERDICT: fixed build, but CVE-2026-88778 is still open - enable Enhanced ISN Generation (see the CVE-2026-88778 lines above).%s\n' "$Y$B" "$N"
      [ "$FOLLOWUP" -eq 1 ] && echo "Also review the other follow-up items above."
      exit 1
    fi
    if [ "$FOLLOWUP" -eq 1 ]; then
      printf '%sVERDICT: fixed build, but follow-up items above need attention.%s\n' "$Y$B" "$N"; exit 1
    fi
    printf '%sVERDICT: fixed build, no follow-up flagged.%s\n' "$G$B" "$N"
    echo "If this box was internet-facing before patching, still hunt for compromise."
    exit 0 ;;
esac
