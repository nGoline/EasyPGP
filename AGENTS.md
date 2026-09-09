# AGENTS.md

Single-module Android app (`:app`), Kotlin. On-device PGP/OpenPGP via Bouncy Castle; hardware YubiKey via Yubikit. No monorepo: `settings.gradle.kts` includes only `:app`.

Contributor policy (PR etiquette, security disclosure, licensing) lives in `CONTRIBUTING.md`. This file covers what an agent needs in order to build and change the code.

## Naming
- The app is **Easy PGP**. It was renamed from Easy GPG in 0.6; the user-visible name is `app_name` in `app/src/main/res/values/strings.xml`.
- The old name survives where renaming would be churn or an outright break: the `com.ngoline.easygpg` namespace and `applicationId`, the source tree under `app/src/main/java/com/ngoline/easygpg/`, and `rootProject.name = "Easy GPG"`. Leave these alone; the `applicationId` is the identity Play installs against.

## Toolchain
- JDK 21 required (AGP 8.13.2, Kotlin 2.2.0, Gradle 8.14.5 through the wrapper).
- `compileSdk` and `targetSdk` are 36, `minSdk` is 35.
- `local.properties` (sdk.dir) is not committed; Android Studio generates it.

## Commands
- Full check (same as the CI build job): `./gradlew assembleDebug testDebugUnitTest lintDebug`
- Single test: `./gradlew testDebugUnitTest --tests "com.ngoline.easygpg.SecretsTest"`
- Instrumented (needs a device/emulator): `./gradlew connectedDebugAndroidTest`. CI runs these in a second job on an API 35 emulator.

## Testing
- Unit tests in `app/src/test/`. Tests touching Android APIs (`SharedPreferences`, `Context`, `Handler`) run under Robolectric; `PassphraseCacheTest` is the pattern.
- Robolectric is pinned to `sdk=35` in `app/src/test/resources/robolectric.properties`. Robolectric 4.15 only emulates up to API 35 while the app targets 36; `minSdk` is 35, so the pin is still a supported configuration. Do not bump it to 36.
- `app/src/testShared/java` is added to both the `test` and `androidTest` source sets, so a fixture there is shared by the JVM and instrumented tests (e.g. `TestKeyRings.kt`).
- The `PGPKeyManager` Keystore tests need a secure lock screen plus a biometric or device-credential authentication within `SECRET_KEY_AUTH_VALIDITY_SECONDS` (300). CI sets a PIN and unlocks immediately before running (`.github/scripts/prepare-emulator.sh`); a long Gradle build beforehand lets the auth window expire and the tests fail.
- The instrumented tests clear the target app's `filesDir`. Debug builds use `applicationIdSuffix = ".debug"` to stay a separate install from release.

## Releases and versioning
- `versionCode` and `versionName` live in `app/build.gradle.kts`.
- User-facing changes go in `CHANGELOG.md` under the version they ship in.
- A release is triggered by pushing a `v*` tag (tag must equal `versionName`) or by running workflow_dispatch. The workflow rejects a `versionCode` that is not greater than the previous tag's, because Play rejects a duplicate versionCode.
- Play "What's new" lives in `distribution/whatsnew/whatsnew-<locale>` (no extension). It must be non-empty and <= 500 characters or the release fails; checked by `.github/scripts/check-release-notes.sh`.
- Play listing copy lives in `distribution/listing/<locale>/`: `title.txt` (30 characters), `short-description.txt` (80), `full-description.txt` (4000). Check with `.github/scripts/check-listing.sh`.

## Conventions
- Commit subjects follow Conventional Commits, with an optional scope: `fix:`, `fix(ui):`, `feat(site):`, `docs:`, `chore:`, `ci:`, `style:`, `test(notifications):`, `release:`.
- The app handles cryptographic material. Report security issues privately to the maintainer rather than as a public issue (see `CONTRIBUTING.md`).
- No `INTERNET` permission and no servers; the app is offline by design.
- Kotlin is compiled with `-Xmulti-dollar-interpolation` (see `app/build.gradle.kts`).
- `docs/` deploys to GitHub Pages as-is (plain HTML, no build step).
