# QuVault V2 Phase 1 — POS hardware security audit

**Date:** 2026-09-20. **Status:** Phase 1 only. No signing architecture was built, and none
should be until the UNKNOWNs below are answered on the physical device.

## How this was determined

No POS device is attached to this machine and `adb` is not installed on it, so **nothing that
requires running code on the device could be measured**. Everything here comes from static
inspection of the shipped APK, decompiled at `C:\ubtc\qufi-node-app\build3\src`
(`io.veyns.auth.native`, the QuFi Node build of the palm terminal). Where the APK cannot
answer a question, the answer below is `UNKNOWN`, not a guess.

## The report

```text
DEVICE                  UNKNOWN — no device attached; the APK does not name its host hardware
MODEL                   UNKNOWN
ANDROID VERSION         UNKNOWN on the device. The APK is built against SDK 34 (Android 14)
SECURITY PATCH LEVEL    UNKNOWN
BOOTLOADER STATUS       UNKNOWN
VERIFIED BOOT           UNKNOWN
TEE                     UNKNOWN — see "what the APK shows" below
STRONGBOX               UNKNOWN — never requested by application code
SECURE ELEMENT          UNKNOWN
ANDROID KEYSTORE        YES — used by the application and by two libraries it bundles
HARDWARE BACKED KEYS    UNKNOWN — the app never checks, and never records the answer
KEY ATTESTATION         NO — no setAttestationChallenge anywhere in the APK
BIOMETRIC HARDWARE      NO Android biometric. The palm scanner is a USB peripheral (below)
USB HOST                YES — declared and used
USB ACCESSORY           NO — no accessory code, no accessory intent filter
```

## What the APK actually shows

| Finding | Evidence |
|---|---|
| The app uses Android Keystore | `com.nabd.usb.data.local.EnrollmentRecoveryCrypto` builds a `KeyGenParameterSpec` under the `AndroidKeyStore` provider; `androidx.security.crypto.MasterKey` and Tink's `AndroidKeystoreKmsClient` are bundled too |
| It does **not** ask for StrongBox | `setIsStrongBoxBacked` appears only inside `androidx.security.crypto.MasterKey$Builder$Api23Impl$Api28Impl`, a library path; the app's own key spec does not call it |
| It does **not** bind keys to user authentication | no `setUserAuthenticationRequired` in the app's key spec |
| It does **not** attest keys | no `setAttestationChallenge` in the whole APK |
| It never checks where its keys live | no `KeyInfo.isInsideSecureHardware()`, no `getSecurityLevel()` anywhere |
| The palm scanner is an external USB device | `com.saintdeem.palmvein.usb.PalmUSBManager` matches VID `0x7985`, PIDs `0x1001` / `0x4000`, over USB **host** |
| The palm is not an Android biometric | no `BiometricPrompt`, no `androidx.biometric`, no `USE_BIOMETRIC` permission |
| Declared permissions are modest | INTERNET, ACCESS_NETWORK_STATE, CAMERA, VIBRATE, and `uses-feature android.hardware.usb.host` (not required) |

**The consequence worth stating plainly:** the terminal already stores something in Keystore,
but nothing in the app establishes that those keys are in a TEE rather than in software. On a
device whose Keystore is software-backed, that code produces exactly the protection of a file.
Until a probe reports `TRUSTED_ENVIRONMENT` or `STRONGBOX`, QuVault must not describe this
device as hardware-backed.

## The architectural obstacle, found in Phase 1

The POS is the **USB host** for the palm scanner. For QuVault-in-a-browser to talk to the POS
over USB, the POS would have to be a USB **device** to the computer. Android offers that only
through accessory mode (AOA) or a custom gadget configuration, and this APK contains no
accessory support at all. One USB port cannot be host and device at once.

So before any protocol work, one of these has to be true, and which one is a hardware question:

1. The POS has a **second USB port** (or a port that can switch roles) while the scanner stays
   on its own bus — then AOA plus WebUSB is workable, and the APK needs accessory support added.
2. The scanner is on an **internal** bus and the external port is free — same as 1.
3. Neither — then USB is not the transport, and the honest alternatives are USB tethering (an
   IP link over the same cable, with the session authenticated exactly as it would be over
   USB) or a local network link. Both keep the security model; neither is "USB" in the literal
   sense the brief describes.

## The probe that answers the UNKNOWNs

Run this with the POS attached and USB debugging on. It needs `adb`, which is not installed on
this machine.

```bash
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.flash.locked
adb shell pm list features | grep -iE "keystore|strongbox|se_|hardware.security|biometric|usb"
```

`pm list features` is the decisive line. `android.hardware.strongbox_keystore` present means
StrongBox exists; `android.hardware.keystore.app_attest_key` means attestation keys are
available; neither present means software or TEE only, and only an in-app probe distinguishes
those two.

For the part `adb` cannot answer — whether a *generated* key lands in hardware — a small probe
inside the app is required:

```kotlin
val spec = KeyGenParameterSpec.Builder("quvault.probe", PURPOSE_SIGN)
    .setDigests(DIGEST_SHA256)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .build()
KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply { initialize(spec) }.generateKeyPair()

val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey("quvault.probe", null)
val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
// API 31+: info.securityLevel — 1 TRUSTED_ENVIRONMENT, 2 STRONGBOX, 0 SOFTWARE
// below 31: info.isInsideSecureHardware
```

Repeat with `.setIsStrongBoxBacked(true)`; a `StrongBoxUnavailableException` is itself the
answer. Report the number, not an impression of it.

## What I recommend, given what is known today

**Do not** start Phases 3 to 13 yet. The two facts that decide the design — whether generated
keys are hardware-backed, and whether the device can be a USB device to a PC — are both
unmeasured, and both change the architecture rather than the code.

**Do** run the probe above. Then:

- If keys report `TRUSTED_ENVIRONMENT` or `STRONGBOX` **and** a transport exists: build the
  secure-device mode as the brief describes, with the POS parsing the transaction itself,
  deriving its own digest, displaying it, taking the palm, and signing in Keystore. QuVault's
  browser mode stays as the default until the device mode is proven.
- If keys are software-backed: the POS still improves the product — it is a separate screen
  and a separate approval surface, which defeats a compromised browser display — but it is not
  a secure element, and neither the UI nor this repository should say it is.
- ML-DSA-65 will **not** be hardware-backed on any current Android Keystore: Keystore has no
  ML-DSA algorithm. The attestation key stays a software key wherever it lives, on the phone
  or in the browser, and that limit belongs in the documentation rather than in a footnote.

## What has not been done

No code was written for V2. QuVault V1 is untouched by this audit.
