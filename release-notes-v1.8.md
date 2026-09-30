## v1.8: reliable fix date for the before/after-fix tags

**Fix for a false red.** Up to v1.7, the checker used the newest entry of any kind in `/var/nsinstall` as the moment the fixed build was installed. That folder also holds `adc.version`, which is rewritten when someone logs on to the NetScaler GUI. After a GUI logon, attacks that came **after** the patch were tagged `[BEFORE fix]` and shown as a red `[SUSPECT]`. Thanks to the World of EUC Slack community for reporting this!

**How v1.8 finds the fix date**
1. The running build's kernel in `/flash` (`ns-14.1-73.37.gz`). `installns` writes it once, at install time, and nothing changes it afterwards.
2. The first boot after that install (`/var/nsinstall/installns_state_post_reboot`), or the last boot if it is within 24 hours of the install. That is when the fixed build started running.
3. `adc.version` and other files in `/var/nsinstall` are no longer used. They are only a fallback when `/flash` cannot be read, and then only the install markers and build archives.

The output now says where the date comes from, for example:
```
[OK]  Fixed build running since 2026-09-27 16:32 (first boot after the install; ns-14.1-73.37.gz installed 2026-09-27 16:29)
```

**Also new**
- `--fixdate "YYYY-MM-DD HH:MM"`: an optional override if you know better, e.g. from the change record. Normally not needed.
- Staged firmware (installed but not yet booted) is now detected from `/flash` as well.

**If v1.7 or earlier showed `[BEFORE fix]` lines on an appliance that was patched days earlier**, check the "Fixed build installed" line at the top of the IoC sweep. If that date was later than your upgrade, run v1.8 again.

Tested on the file layout of a production HA pair (with a later `adc.version` and an extra reboot after the upgrade), without the post-reboot marker, without `/flash`, with a staged kernel on a vulnerable build, and with the real log lines of an appliance attacked before and after its patch.
