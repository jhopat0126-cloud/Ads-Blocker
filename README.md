# AdBlocker (Android, no-root prototype)

A working starting point for a local, VPN-based ad/tracker blocker for
Android — the same basic technique used by DNS66 and Blokada. It doesn't
need root.

## How it works

1. The app starts an Android `VpnService`, which routes the device's
   DNS traffic through a local "tunnel" it controls.
2. Every outgoing DNS query is inspected. If the requested domain is on
   `app/src/main/assets/blocklist.txt`, the app immediately replies with
   `0.0.0.0` — so the ad/tracker never loads, in *any* app on the device.
3. Everything else is forwarded untouched to a real DNS resolver
   (Google Public DNS, `8.8.8.8`, configurable in `AdBlockVpnService.kt`).

## Opening the project

1. Install [Android Studio](https://developer.android.com/studio).
2. Open the `AdBlockerApp` folder as an existing project.
3. Let Gradle sync (it will download the Android Gradle Plugin/Kotlin
   plugin the first time — needs internet).
4. Run on a device or emulator (minSdk 24 / Android 7.0+).
5. Tap **Start Blocking**, accept the "Connection request" VPN prompt —
   that's Android's standard permission dialog for any VPN app.

## Important limitations of this prototype

- **DNS-only filtering.** It blocks ads/trackers that are looked up by
  domain name. It does not inspect or filter IP-level/HTTP traffic, so
  ads served from an IP address already cached by the OS, or from a
  domain not on the blocklist, will get through. This is the same
  limitation every non-root DNS-based blocker has.
- **Non-DNS traffic is currently dropped, not forwarded.** The packet
  loop only handles UDP port 53. To make the device fully usable while
  the VPN is active, you'll want to add a general-purpose passthrough
  for TCP/UDP traffic that isn't DNS (a NAT/proxy layer) — this is the
  standard next step and what apps like DNS66 do; it's beyond a first
  prototype's scope.
- **Small starter blocklist.** Swap `blocklist.txt` for a larger list —
  e.g. a StevenBlack `hosts` file with the `0.0.0.0 ` prefix stripped —
  for meaningfully better coverage.
- **One device VPN slot.** Android allows only one active VPN app at a
  time (that includes actual VPN apps a user might also use); starting
  this one will disconnect any other.

## Play Store note

Google Play requires apps using `VpnService` for content filtering to
declare this clearly in their Play Store listing and privacy policy
(what's blocked, that no traffic leaves the device to a remote server,
etc.). Worth reading Play's current policy on VPN apps before
publishing.
