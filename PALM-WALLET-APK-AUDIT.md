# Palm wallet APK — audit of the mainnet demo build

Companion to [POS-HARDWARE-AUDIT.md](POS-HARDWARE-AUDIT.md), which examined the palm terminal
app. This is the same binary lineage one step on: the key-handling classes are still
`com.nabd.usb.*`, now inside a Veyns-branded wallet pointed at a live chain.

| | |
|---|---|
| **File** | `app-0.1.4-mainnet-demo-build5-configured-signed.apk.zip` |
| **Package** | `io.veyns.palmwallet.mainnetdemo` |
| **Version** | `0.1.4-mainnet-demo`, versionCode 5 |
| **SDK** | min 25 (Android 7.1), target 34, compiled 34 |
| **Size** | 48 MB, 992 entries |
| **Examined** | 19 October 2026 |

**Method.** Static analysis only: manifest and resources parsed from binary AXML, certificate
read from the PKCS#7 block, DEX analysed with androguard (bytecode and cross-references, 238k
strings). No device, no emulator, no dynamic analysis, no network capture. Where a question
needs runtime observation it is marked as unresolved rather than guessed at.

The `.zip` extension is cosmetic — the file is the APK itself, presumably renamed to survive a
download filter.

---

## 1. The finding that matters: a live-money configuration carrying demo and sandbox code

`assets/wallet-network.json` is the "configured" part of the filename:

```json
{ "configured": true, "chainId": 56, "symbol": "USDT", "decimals": 18, "confirmations": 15,
  "token": "0x55d398326f99059fF775485246999027B3197955",
  "authorizer": "0x72D315647a33E49096CF7D3f954a5eb05D18F2E5",
  "backendOrigin": "https://sukuk.atl.ae:8443",
  "rpc": "https://bsc.rpc.blxrbdn.com",
  "tokenCodeHash": "0x97a48aa4…a74a59" }
```

`chainId: 56` is **BNB Smart Chain mainnet**, and `0x55d398…7955` is the live Binance-Peg
BSC-USD contract. 18 decimals is correct for that token. This build moves real value.

Three environment markers disagree with that:

| Marker | Evidence |
|---|---|
| **Demo enrolment paths** | `DemoEnrollmentReferenceStore`, `configureDirectDemo`, `clearDirectDemoReference`, `getOrCreateDemoEnrollmentReference`, `demoReferences` |
| **Sandbox identity namespace** | `veyns.identity.sandbox.device.v1` is the only identity namespace constant in the binary |
| **Signing key identity** | the certificate is `CN=NABD, O=NABD Wallet Mainnet Demo` |

None of these is a defect on its own. Together they say the build is a demonstration wired to
production money, and **what those demo paths bypass has to be established before anyone funds
it.** A demo enrolment reference that shortcuts palm verification would be a direct path to
someone else's USDT.

---

## 2. The three questions this audit was asked

### Q1 — Is `tokenCodeHash` verified, or only read? **Verified.**

`Lio/veyns/palmwallet/WalletRpcRefresh;->verify(Lorg/json/JSONObject;Ljava/lang/String;)V`
calls `eth_getCode`, reads `runtimeCode`, and immediately after the `tokenCodeHash` constant
performs `Lkotlin/text/StringsKt;->equals(Ljava/lang/String;Ljava/lang/String;Z)Z`, with
`Failed requirement.` throw paths in the same method.

So the app fetches the deployed contract's runtime bytecode and compares it against the hash
baked into the config. **This is a real control**: a token contract swapped at the configured
address is rejected rather than trusted. It is the strongest thing in this build.

The same method also verifies `eth_chainId`, the finalized block, `deploymentHash` and a
transaction receipt — the configuration is checked against the chain, not assumed.

### Q2 — Does palm imagery leave the device? **No image. The template and feature vector do.**

On-device, the vendor SDK extracts from the sensor:

```
CloudPalmManager$NativeHandEnrollment.getPalmFeature() → [B
CloudPalmManager$NativeHandEnrollment.getTemplate()    → [B
PalmVeinManager.extractFeature(...)                    (native, libSDPV*/libPV_algorithm310)
```

What crosses the network is those values encoded as strings:

```
AuthenticateRequest.getPalmFeature()  → String   (+ featureProtocol, featureSdkVersion,
                                                   featureAlgorithmVersion)
TeeEnrollmentHand.getPalmFeature()    → String
TeeEnrollmentHand.getTemplate()       → String   (+ templateProtocol, templateSdkVersion,
                                                   templateAlgorithmVersion)
CloudApiService.enrollTeeTemplateUnique(TeeEnrollRequest)
```

No upload path for an image exists: no `getRawImage`, no `uploadImage`, no image base64
helper. `PalmPreviewFrame.getBitmap()` exists but feeds the on-screen viewfinder.

**The honest statement is therefore narrower than "biometrics stay on the device".** A raw palm
image never leaves, which matters — but a biometric **template** does, and a template is
biometric personal data. If the receiving store is breached the template is compromised, and
unlike a password a palm cannot be reissued.

The design is deliberate rather than careless: matching happens on a remote **TEE** palm server
(`X-TEE-Token` header, `teeAuthenticate`, `TeeCapabilitiesResponse`,
`enrollTeeTemplateUnique`), so templates are meant to live inside a trusted execution
environment. That shifts the question from *does it leak* to *who operates that TEE, under what
retention policy, and what happens on compromise* — which is a governance answer, not a code
one, and it is not answerable from the binary.

The Kakadu JPEG2000 codec bundled in `lib/` is not evidence of image upload; it ships with the
vendor SDK and is reachable from the capture path. Where it writes, if anywhere, needs runtime
observation.

### Q3 — Which USB device? **VID `0x7985`, PID `0x1001`.**

From `res/FZ.xml`, the `USB_DEVICE_ATTACHED` filter:

```xml
<usb-device vendor-id="31109" product-id="4097"/>
```

`31109` = `0x7985`, `4097` = `0x1001`. Same vendor as POS-HARDWARE-AUDIT, but **this build binds
only PID `0x1001`**, where the terminal app matched `0x1001` and `0x4000`. One device model.

---

## 3. Done well

- **Signed v1 + v2 + v3** (`X-Android-APK-Signed: 2, 3`, APK Signing Block present)
- **`allowBackup=false`** — wallet state stays out of cloud and adb backups
- **`usesCleartextTraffic=false`**, and not debuggable
- **Minimal permissions**: INTERNET, ACCESS_NETWORK_STATE, CAMERA, FOREGROUND_SERVICE,
  FOREGROUND_SERVICE_CONNECTED_DEVICE, POST_NOTIFICATIONS, VIBRATE. No external storage, no
  location, no contacts, no phone state. Unusually clean for an app of this size.
- **One exported component**, `MainActivity`. The only other is androidx's
  `ProfileInstallReceiver`, gated on `android.permission.DUMP`.
- **`https://unconfigured.invalid`** as the unset sentinel — a missing configuration fails
  loudly instead of defaulting somewhere plausible.
- **Signed device requests**: `X-Veyns-Device`, `X-Veyns-Nonce`, `X-Veyns-Signature`,
  `X-Veyns-Time` on `/v1/devices/palm`. Replay has been thought about.
- **The chain configuration is verified against the chain** (Q1).

---

## 4. Weaknesses

### W1 — No key attestation. Unchanged from POS-HARDWARE-AUDIT.

`setAttestationChallenge` appears **zero** times across 238,000 strings. The app cannot prove to
`sukuk.atl.ae` that its key was generated in secure hardware. A backend authorising USDT
transfers has no cryptographic basis for believing anything about the device it is talking to.

### W2 — No check that hardware backing was obtained.

`isInsideSecureHardware` and `getSecurityLevel`: zero occurrences. On a device with no TEE or
StrongBox the key falls back to software and nothing notices, reports, or refuses.

### W3 — `setIsStrongBoxBacked` is the library's, not the app's.

It appears once, inside `androidx.security.crypto.MasterKey`'s API-28 path. The app's own
`KeyGenParameterSpec` usage does not request StrongBox. `setUserAuthenticationRequired` does now
appear twice, which is an improvement on the terminal app.

### W4 — The constraint underneath W1–W3

**Android Keystore has no secp256k1.** A BSC wallet key therefore cannot be held in hardware at
all; it must exist in process memory to sign. What this build does — `EncryptedSharedPreferences`
over a Keystore-wrapped `MasterKey` — is encryption at rest, which is the best available, and it
is not the same as a hardware-protected signing key.

The consequence is the same one the QuVault work reached by a different route: **the palm is an
authorisation control, not key custody.** Any copy that implies the key is protected by hardware
or by the palm would be wrong.

### W5 — No certificate pinning

There is no `networkSecurityConfig`. TLS is enforced, but nothing pins `sukuk.atl.ae:8443`, and
that host authorises transfers and receives biometric templates.

### W6 — The signing key is permanent

The certificate is self-signed `CN=NABD, O=NABD Wallet Mainnet Demo`, issued 2026-10-18, valid
to 2054. On Android, application identity **is** the signing key: it cannot be rotated, and a
different key means users must uninstall and reinstall. For a wallet, uninstall risks key loss.

If this key is a throwaway for a demonstration, it must not reach real users. If it is the
production key, it should be named and custodied as such, and the "Mainnet Demo" subject is
misleading in a certificate that will outlive the product.

---

## 5. Not determined

Each of these needs a device or an emulator, not another read of the binary:

1. **What the demo enrolment paths actually bypass**, and whether any is reachable in this
   build. This is the open question with money attached.
2. **Whether the Kakadu JPEG2000 encoder ever writes or transmits**, as opposed to being linked
   and unused on this path.
3. **Who operates the TEE palm server**, its retention policy for templates, and its behaviour
   on compromise.
4. **Whether `authorizer` `0x72D315…F2E5` is a contract or an externally owned account**, and
   what it is permitted to do. A chain query answers this in seconds and was not run here.
