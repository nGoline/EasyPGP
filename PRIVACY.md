# Privacy Policy for Easy PGP

**Last updated:** 3 September 2026

Easy PGP is free software published by Níckolas Goline. This document describes what the app
does with your data. It is a factual description of the app's behaviour, and can be checked
against the [source code](https://github.com/nGoline/EasyPGP).

## The short version

Easy PGP collects nothing, sends nothing, and has no servers. **The app does not request the
`INTERNET` permission**, so it cannot transmit your data anywhere even if it tried. Everything
it holds stays on your device.

## What the app stores, and where

Everything below lives in the app's private storage, readable only by Easy PGP:

- **Your key rings.** Public and private PGP keys you generate or import. Private key rings are
  encrypted with a passphrase you choose, and additionally sealed with a key held in the Android
  Keystore that requires your fingerprint or device PIN.
- **Your settings.** Privacy mode, how long a passphrase is remembered, whether to clear fields
  after an operation, whether to obfuscate PGP markers.

**Your passphrase is never written to disk.** It is held in memory for the duration you choose —
until the screen turns off, one hour, or one day — then overwritten. It is gone when the app
process ends. It cannot be recovered; if you forget it, messages encrypted to that key cannot be
decrypted by anyone, including us.

## Notification access

If you enable it, Easy PGP uses Android's notification listener to detect encrypted messages in
notifications from other apps, so it can offer to decrypt them.

This is the app's most sensitive permission, so to be precise about it:

- The app reads notification text **on your device only**, to check whether it begins with a PGP
  message marker.
- Notifications that are not encrypted messages are ignored. Nothing about them is stored.
- When an encrypted message is found, the message text is passed to the app's own decrypt screen.
  It is not written to disk, logged, or transmitted.
- The feature is entirely optional. Android requires you to grant it explicitly in system
  settings, and you can revoke it at any time. The rest of the app works without it.

## What the app does not do

- No analytics, telemetry, crash reporting, or advertising.
- No accounts, sign-in, or user identifiers.
- No network requests of any kind. The app holds no `INTERNET` permission.
- Your keys are never uploaded, backed up to a server, or shared.

## Hardware keys

If you use a YubiKey, the app communicates with it directly over USB or NFC. That communication
stays between your phone and the key.

## Other permissions

| Permission | Why |
| --- | --- |
| `POST_NOTIFICATIONS` | To tell you an encrypted message was detected |
| `RECEIVE_BOOT_COMPLETED` | To restart the detection service after a reboot |
| `HIDE_OVERLAY_WINDOWS` | Privacy mode: stop other apps drawing over the app |
| `NFC` | Talking to a YubiKey over NFC |
| `USE_BIOMETRIC` | Unlocking your private keys with fingerprint or device PIN |

## Google Play

Distribution through Google Play means Google collects its own data about installs and, if you
have opted in on your device, crash reports. That collection is Google's, governed by the
[Google Privacy Policy](https://policies.google.com/privacy), and is outside this app's control.
Easy PGP itself sends nothing to Google.

## Children

Easy PGP is not directed at children and collects no data from anyone.

## Changes

Changes to this policy will be published in this file, and its history is public in the
repository.

## Contact

Questions about this policy, or about the app's handling of data, can be raised as an issue at
[github.com/nGoline/EasyPGP/issues](https://github.com/nGoline/EasyPGP/issues). Please report
security vulnerabilities privately instead — see
[CONTRIBUTING.md](https://github.com/nGoline/EasyPGP/blob/main/CONTRIBUTING.md#security-issues).

## A note on trust

Easy PGP is **alpha software and has not been security audited**. This policy describes what the
app is designed to do, and the source is public so the claims can be verified. It is not a
warranty that the software is free of defects. Do not rely on it to protect information whose
disclosure would put you at risk.
