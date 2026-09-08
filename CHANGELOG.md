# Changelog

Notable changes to Easy PGP. Versions correspond to `versionName` in
`app/build.gradle.kts`; the `versionCode` Play uses is noted alongside.

Easy PGP is **alpha, unaudited software**. See the
[security notes](README.md#security) before trusting it with anything that matters.

## 0.5 — 2026-09-08 (versionCode 7)

### Notifications

- Several encrypted messages arriving together now raise one notification each. Previously every
  detection overwrote the same notification, so only the most recent one could be reached.
- Tapping a notification no longer dismisses it immediately. It is cleared once the message is
  actually on screen, so a cancelled or mistyped authentication no longer loses the message —
  the notification is still there to tap again.
- The notification announcing a detected message showed a camera icon. It is now a key.

### Appearance

- The app now uses its own palette rather than the Android Studio default, so it matches its
  icon and store listing. Contrast was measured for both light and dark.
- New launcher icon: a brass key on indigo, replacing the Android robot placeholder. Includes a
  monochrome layer for themed icons.
- The navigation drawer showed a placeholder name and email address, and the menu used camera
  and gallery icons for Encrypt, Decrypt and Keys. Both fixed.
- The button on the home screen did nothing. It now opens the Encrypt screen.

## 0.4 — 2026-09-03 (versionCode 6)

The first release published through CI, and a long one: 0.3 shipped in July 2025.
Almost everything here is about keeping key material out of reach.

### Key protection

- Secret key rings are encrypted with a passphrase you choose when the key is generated,
  instead of a placeholder baked into the app. Key rings created by earlier versions are
  migrated the first time you decrypt.
- Private keys are additionally sealed with an Android Keystore key that requires biometric
  or device-credential authentication within the last five minutes, so they cannot be read
  without you being present.
- Removing or resetting the device lock screen destroys that key, and with it access to the
  stored private keys. This is deliberate.
- Private keys can be exported, after authenticating.

### Passphrase handling

- Choose how long an entered passphrase is remembered: until the screen turns off, one hour
  (the default), or one day. It is held in memory only, overwritten when it expires, and gone
  once the app process ends.
- Secret input is read into buffers the app owns and overwrites after use, rather than into
  `String`s that cannot be scrubbed.

### Privacy

- App-wide privacy mode keeps the app out of screenshots and the recents list.
- Overlay windows are blocked while the app is in the foreground.
- Text fields opt out of personalised keyboard learning, so passphrases and plaintext are not
  added to the keyboard's dictionary or prediction model.
- Nothing is shown until authentication succeeds.
- Optional setting to clear the encrypt and decrypt fields after each operation.

### Key management

- Delete your own keys from the Keys screen.
- Imported keys ask for confirmation before deletion.
- Fingerprints use the same short format everywhere they appear.

### Fixes

- The Encrypt message field is a proper multi-line text area.
- The overflow menu is readable in dark mode.

## 0.3 — 2025-07-07 (versionCode 4)

- Key rings are encrypted at rest.
- Optional obfuscation of PGP markers in encrypted output.
