# Easy PGP

An Android app that makes PGP/GPG encryption approachable. Encrypt and decrypt
messages, manage your keys, and use a hardware YubiKey — without touching a
command line.

**[ngoline.github.io/EasyPGP →](https://ngoline.github.io/EasyPGP/)** — what the app does, and
how to join the closed beta.

> ⚠️ **Alpha software.** Easy PGP is under active development and has not been
> audited. Do not rely on it to protect data whose disclosure would put you at
> risk. See [Security](#security) below.

## Features

- 🔐 Encrypt and share messages with PGP public keys
- 🔓 Decrypt messages with your private keys
- 🗝️ Generate, import, and manage key rings on device
- 🛡️ Hardware-backed key storage via the Android Keystore
- 🔑 YubiKey support over USB and NFC (OpenPGP applet)
- 🌐 Localizable string resources (English)

## Tech stack

- Kotlin, Android SDK 35+ (`compileSdk` 36)
- [Bouncy Castle](https://www.bouncycastle.org/) (`bcpg` / `bcprov`) for OpenPGP
- [Yubico YubiKit](https://github.com/Yubico/yubikit-android) for hardware keys
- AndroidX (Navigation, Lifecycle, Preference, Security-Crypto, Biometric)

## Building

Requires Android Studio (latest stable) and JDK 21.

```bash
git clone https://github.com/<your-username>/EasyPGP.git
cd EasyPGP
./gradlew assembleDebug
```

Or open the project in Android Studio and run it on a device/emulator. The SDK
location is read from `local.properties`, which Android Studio generates for you
(it is intentionally not committed).

## Contributing

Contributions are very welcome — this project is looking for help to keep
development alive. Please read [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## Security

Easy PGP handles cryptographic material, so please treat it with care:

- It is **alpha, unaudited** software.
- Secret key rings are encrypted with a passphrase you choose when the key is
  generated, on top of the Android Keystore layer. Key rings created by earlier
  versions used a placeholder passphrase; the app asks you to replace it the
  first time you decrypt a message.
- Your passphrase cannot be recovered. If you forget it, messages encrypted to
  that key can no longer be decrypted.
- When you enter a passphrase you choose how long it is remembered: until the
  screen turns off, for one hour (default), or for one day. It is held in memory
  only, overwritten when it expires, and always gone once the app process ends.
- Private keys are additionally sealed with an Android Keystore key that requires
  biometric or device-credential authentication within the last five minutes, so
  they cannot be read without you being present. Removing or resetting the device
  lock screen destroys that key, and with it access to the stored private keys.
- Found a vulnerability? Please **do not** open a public issue. Instead, report
  it privately to the maintainer (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Privacy

Easy PGP collects nothing and has no servers — it does not even hold the `INTERNET`
permission. See [PRIVACY.md](PRIVACY.md) for what it stores on your device and why it asks
for notification access.

## License

Easy PGP is free software licensed under the
[GNU General Public License v3.0](LICENSE). You may redistribute and/or modify
it under those terms. It comes with **no warranty**.
