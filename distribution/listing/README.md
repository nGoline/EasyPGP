# Store listing copy

The text Google Play shows on the store page, kept here so it is reviewed in a pull request
rather than edited straight into the console and lost.

**These files are not uploaded by CI.** The release workflow only uploads the bundle and the
release notes in `distribution/whatsnew/`. Listing copy is pasted into Play Console by hand;
this directory is the source of truth for what was pasted.

| File | Play field | Limit |
| --- | --- | --- |
| `en-US/title.txt` | App name | 30 characters |
| `en-US/short-description.txt` | Short description | 80 characters |
| `en-US/full-description.txt` | Full description | 4000 characters |

Run `.github/scripts/check-listing.sh` to confirm each file is within its limit.

## Visual assets

In `en-US/graphics/`. The artwork masters live in `graphics/source/`; the files Play actually
wants are derived from them by `build-graphics.py`, so they are reproducible rather than
hand-cropped. Re-run it after changing the artwork or the wording on the feature graphic:

```sh
python3 distribution/listing/build-graphics.py
```

| Asset | File | Requirement |
| --- | --- | --- |
| App icon | `icon-512.png` | 512×512 PNG, under 1 MB, square — Play applies its own corner mask, so do not pre-round |
| Feature graphic | `feature-graphic-1024x500.png` | 1024×500, no transparency |
| Phone screenshots | `screenshots/phone/` | 2–8, 320–3840px, longest side at most twice the shortest, 24-bit PNG with **no alpha** |

Tablet, Chromebook and Android XR screenshots are optional.

### Screenshots

Five, in `en-US/graphics/screenshots/phone/`, ordered to read as a sequence: encrypt, share the
ciphertext anywhere, import someone's public key, protect the private key, privacy settings.

Taken from 0.5, after the template leftovers were removed, so they show the app's own indigo
and brass rather than the Android Studio default.

Two rules that are easy to get wrong:

- Play requires 9:16 only for the large-format **promotion** slots, not to publish. To publish,
  the longest side must be at most twice the shortest — which a raw Pixel 9 Pro XL capture
  (1344×2992, 2.23×) fails. Four of these are exact 9:16 so promotion stays available; the share
  sheet is left at its natural ratio because cropping to 9:16 clipped the app labels.
- Screenshots must be **24-bit PNG with no alpha**. `adb exec-out screencap -p` produces RGBA,
  which has to be converted.

When capturing, three things bite:

- Privacy mode blocks screenshots, so leave it off.
- Use a throwaway key. A fingerprint in a store screenshot is public permanently.
- `adb shell input text` repeats itself several times per call while the soft keyboard is up, and
  a dialog's buttons end up underneath the keyboard where taps do not reach. `adb exec-out
  screencap` respects the size override and produces no letterboxing, unlike Android Studio's own
  capture button, which grabs the whole framebuffer.

Set the emulator to a size Play accepts before capturing:

```sh
adb shell wm size 1080x1920 && adb shell wm density 420
# ... capture ...
adb shell wm size reset && adb shell wm density reset
```

### The launcher icon is not this icon

`en-US/graphics/icon-512.png` is the store listing icon. The icon inside the app is still
`app/src/main/res/mipmap-*/ic_launcher`, which is the unmodified Android Studio template — a
green robot. Replacing it is a separate change: adaptive icons need foreground and background
layers, not a single square image.
