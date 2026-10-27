# ZTE ZXHN F670L — Firmware Extraction & Security Teardown

**Author:** Varun (`varun935`)
**Date:** October 2026
**Target:** ZTE ZXHN F670L GPON ONT (ISP-supplied, firmware `V9.0.10P1N12A`)
**Category:** Hardware / firmware security — UART, bootloader, config cryptanalysis, reverse engineering

> **Scope & authorization.** All work was performed on a single unit that I own, in a lab setting, physically disconnected from any live fiber/GPON line. No third-party systems, networks, or ISP infrastructure were touched. The findings below reproduce and extend weaknesses that are already publicly documented (see *Prior work & CVEs*); nothing here is presented as a novel 0-day. Device-specific secrets and fleet-wide credentials are **redacted or masked** throughout — this document is written to be publishable without handing anyone a working key.

---

## Executive summary

Starting from nothing but a retail GPON ONT, I gained a serial console over UART, extracted the full 256 MB NAND firmware, decrypted the device's configuration backup offline, and reverse-engineered three core binaries in Ghidra. The work demonstrates that this device's security model rests almost entirely on **static, firmware-embedded secrets** — values that are either printed on the sticker or shipped inside the firmware image itself.

Headline results:

- **Config-backup encryption is fully reversible** — the AES key is derived from the device's serial number and MAC (both on the label), and the IV is a fixed constant stored in the firmware.
- **A vendor factory-mode authentication path** (undocumented by ZTE, but publicly known and tooled) accepts a hardcoded, fleet-wide credential and yields a root telnet shell, bypassing the owner's admin password.
- **The "hardcoded secret" store is self-defeating** — its contents are AES-encrypted, but the master key ships in the same firmware image.
- A complete credential set (ISP management, PPPoE, Wi-Fi, SMB/FTP, embedded TLS private keys) was recovered, and a persistent root console was established.

| # | Finding | Severity | CVSS 3.1 (base) |
|---|---------|----------|-----------------|
| F1 | Reversible config-backup encryption | High | 7.1 (`AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`) |
| F2 | Factory-mode auth backdoor → root | High | 8.0 (`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`) |
| F3 | Hardcoded-secret store, key shipped in firmware | Medium | 5.5 |
| F4 | Full credential disclosure | High | 7.5 |
| F5 | Static root password hash in firmware | Medium | 5.0 |
| F6 | Embedded static TLS private keys | Medium | 5.9 |
| F7 | Unauthenticated firmware extraction (open bootloader) | Medium | 6.0 |
| F8 | Admin web password equals the serial number | Low | 3.9 |

*Severity note: most vectors require physical or LAN-adjacent access, which correctly caps the scores — this is not an internet-facing device on these paths. The impact is to device/account confidentiality, not remote mass-exploitation.*

---

## Target overview

| Component | Detail |
|-----------|--------|
| Model | ZTE ZXHN F670L (GPON ONT / router) |
| SoC | ZTE ZX279128S — ARM Cortex-A9 @ 1 GHz |
| Flash | Micron `MT29F2G01ABAGDWB` — SPI-NAND, 256 MB, 3.3 V |
| RAM | 256 MB |
| Wi-Fi | MediaTek `mt7613e` + `mt7603e` |
| Bootloader | U-Boot 2013.04 (`versioninfo` string `V9.0.10P10N1` — distinct from the software release) |
| Kernel | Linux 4.1.25 (ARM), BusyBox 1.17.2 userland |
| Web backend | Lua (`thinklua` framework) |
| Firmware (software) | `V9.0.10P1N12A` (2021-08-04 build; device string `ZXHN F670L UNI V9.0.10P1N12A`) |

### Flash layout (`/proc/mtd`, from the live device)

| Partition | Size | Name |
|-----------|------|------|
| mtd0 | 0x10000000 | whole flash |
| mtd1 | 0x00200000 | u-boot |
| mtd2 | 0x00400000 | others |
| mtd3 | 0x00400000 | parameter tags |
| mtd4 | 0x00400000 | wlan |
| mtd5 | 0x00800000 | usercfg |
| mtd6 | 0x00400000 | middleware |
| mtd7 | 0x02000000 | kernel1 |
| mtd8 | 0x02000000 | kernel2 |
| mtd9 | 0x01fe0000 | rootfs (JFFS2) |

Note the A/B layout (`kernel1`/`kernel2`) typical of carrier ONTs.

---

## Methodology — the access chain

This is the full journey, including the approaches that failed. The dead ends are kept deliberately: they are where most of the actual learning happened.

### 1. Getting a UART console

The board has an unpopulated 4-pin header but no silkscreen labels. I identified the pins with a multimeter:

- **GND** — continuity to the RF-shield can (power off).
- **VCC** — steady 3.3 V the instant power is applied (left disconnected).
- **TX** — voltage flickers during the first seconds of boot (the log streaming out).
- **RX** — the remaining quiet pin.

I didn't have a dedicated USB-TTL adapter on hand. Rather than improvise something unsafe (cut USB cable, 5 V GPIO), I used a **ESP-01 flashing adapter**, which is simply a CH340 USB-to-TTL bridge with an ESP socket — a perfect 3.3 V substitute.

**First failure:** I could read the boot log but couldn't type. The cause was a wrong assumption about the header order — the real layout was `VCC-TX-RX-GND`, not what I'd guessed, so my transmit line was on the wrong pad. A loopback test on the adapter (bridging its own TX↔RX) confirmed the adapter was fine and isolated the fault to the wiring. Correcting the pinout fixed it. Console settings: **115200 8N1**.

### 2. Reading the boot ROM & U-Boot

With the console live I captured the full boot sequence, which identified the SoC, the Micron SPI-NAND, and the firmware version, and showed an **interruptible, unprotected U-Boot** (`Hit any key to stop autoboot`). Dropping to the `=>` prompt and reading the environment revealed how the kernel is loaded (`bootcmd` builds the kernel command line and `bootm`s a JFFS2-resident `uImage`).

### 3. The locked serial login (failed path)

The Linux serial login (`F670L login:`) rejected every credential I tried — `root/root`, `root/Zte521`, the GPON serial, the device EN, and other published ZTE defaults. At this point I did not yet know the root password was a **static hash baked into the firmware** (confirmed later in *F5*), unrelated to any value on the sticker. The control held; guessing was a dead end.

### 4. Bootloader shell injection (failed path)

I attempted to bypass the login by overriding the kernel command line with `init=/bin/sh`:

```text
setenv bootcmd '... init=/bin/sh; bootm 0x44000000'   # → "Wrong Image Format"
nand read 0x42000000 0x1a20000 0x1520000; bootm ...    # → "Wrong Image Format"
fsload / fsinfo                                         # → stubbed ("no version")
```

This route failed for three vendor-specific reasons, which the later firmware analysis made clear:

- **The kernel is staged only on cold boot.** The ZTE preloader reconstructs and copies the kernel to `0x44000000` during a full power-cycle; interrupting autoboot leaves that RAM empty, so a manual `bootm 0x44000000` at the prompt fails with a bad-header / wrong-format error.
- **The kernel partition is a ZTE chunked container, not a raw uImage.** Dumping it shows the header magic `99999999 44444444 55555555 aaaaaaaa` — the *same* container format used by the config backup — followed by a device string `ZXHN F670L UNI V9.0.10P1N12A`, a load address and CRC, then a payload chunked per 128 KiB erase block (each chunk prefixed `e0 0x1985`, size, CRC, index). `bootm`/`bootz` cannot boot it directly; the ZTE boot code reassembles the real image itself.
- **`init=` is ignored.** Even when the kernel was allowed to cold-boot with a patched `init=/bin/sh`, the firmware ran its hardcoded `/sbin/init` and returned to the login prompt.

The bootloader route to a shell was therefore abandoned in favour of the paths below.

### 5. Network + web admin

Pivoting to the LAN, the router was unreachable at first — my laptop's wired interface was on `10.42.0.x` (NetworkManager "shared" mode), not the router's `192.168.1.0/24`. A manual static IP fixed it. The web UI then accepted **`admin`/`admin`** (a limited role — no config download, no telnet toggle).

I also tried enabling Telnet through the web UI's **Service Control (IPv4)** page — adding an *Allow* rule for the TELNET service on LAN ingress — but port 23 stayed `filtered` on re-scan. That page is a firewall/ACL only: it governs *access* to a service but cannot *start* the telnet daemon when the service is disabled at the system level. This is why the ACL route was insufficient and the factory-mode path (step 9) was ultimately required.

### 6. Config backup → offline decryption (success)

The limited web role still allowed a **USB configuration backup** (`usbbak.cfg`). The file begins with ZTE's `99999999 44444444 55555555 aaaaaaaa` magic and an `F670LV9.0` tag, followed by an AES-encrypted body. Using the public [`mkst/zte-config-utility`](https://github.com/mkst/zte-config-utility):

```text
auto.py --mac <REDACTED> --serial <REDACTED> usbbak.cfg config.xml
→ Successfully decrypted using (key, iv): ('<serial-tail><reversed-MAC>', 'ZTE%FN$GponNJ025')
```

The decrypted XML exposed the full configuration (see *F4*). Crucially, the **key is derived entirely from the device label** and the **IV is a static firmware constant** — proven in code in *F1*.

### 7. Firmware extraction over UART (the dump saga)

With no `tftpput` in this U-Boot and telnet still locked, I dumped NAND over the serial line from the bootloader: `nand read` a partition into RAM, then `md.b` (byte memory-display) it out while logging the console.

The practical lesson: my 3-wire hookup has **no hardware flow control**, so a single multi-hour `md.b` of the rootfs overran the USB-serial FIFO and dropped two multi-MB chunks. The fixes that got to a **byte-perfect** image:

- Dump in bounded chunks rather than one marathon stream.
- Capture headless with a `pyserial` script (reads straight to disk, far faster FIFO drain than a scrolling terminal).
- Reconstruct by absolute address, then re-dump only the specific gap ranges and merge.

### 8. Filesystem extraction

The rootfs is JFFS2; [`jefferson`](https://github.com/onekey-sec/jefferson) extracted **1701 files** — a full BusyBox/uClibc userland with a Lua web backend, MediaTek wireless stack, and ZTE service daemons.

### 9. Factory-mode → root shell (success)

Telnet (port 23) was ACL-filtered on the LAN segment, but the web endpoint on port 80 was open. The public [`douniwan5788/zte_modem_tools`](https://github.com/douniwan5788/zte_modem_tools) `zte_factroymode.py` authenticated to the hidden factory endpoint with an embedded credential, ran its `facStep` sequence to enable telnet, and was issued **temporary telnet credentials** — dropping me into a BusyBox **root shell**. (Mechanism reverse-engineered in *F2*.)

### 10. Persistent console access

From the root shell I remounted the (read-only) JFFS2 rootfs read-write and reset the root password, so the **serial console** now accepts a known password across reboots — closing the very login wall that blocked step 3, not by cracking the static hash but by replacing it once root was obtained through another path.

### 11. Alternative root path — `/etc/shadow` patch + reflash

Independently of factory-mode, root can also be obtained offline from the firmware dump itself: patch `/etc/shadow` in the extracted rootfs to give `root` an **empty password**, repack the JFFS2 image, and reflash it to the rootfs partition from U-Boot (`mtddebug write`). On reboot the device accepts `root` with a blank password at both the serial and telnet logins. This path is more invasive — it rewrites NAND and risks bricking on error — but it does **not** depend on the factory endpoint, so it remains viable if that path is ever closed by a firmware update. Both root methods were validated on the device.

---

## Findings

### F1 — Reversible config-backup encryption (High)

The configuration backup is AES-CBC encrypted, but the key and IV offer no real protection. Decompiling `PdtDBSetUserCfgAESCBCEncryKey` in `cspd` (ARM, unstripped) shows the derivation:

```c
// key_out / iv_out produced for the config AES-CBC cipher
if (GetTagParam(0x720, buf, 0x20, ...) == 0)        // optional precomputed key tag
    strncpy(key_out, buf, key_len - 1);
else {                                               // fallback: derive from device identity
    GetTagParam(0x881, id, 8, ...);                  // device ID  (default "00000001")
    GetTagParam(0x100, mac, 6, ...);                 // MAC address (default "00:d0:d0:00:00:01")
    snprintf(key_out, key_len, "%s%02x%02x%02x%02x%02x%02x",
             id, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
CspHardCodeParamGet("/etc/hardcodefile/dataprotocol", "DefAESCBCIV", buf, 200);  // static IV
strncpy(iv_out, buf, iv_len - 1);
```

> *Screenshot placeholder:* `images/f1_cspd_keyderiv.png` — decompiled `PdtDBSetUserCfgAESCBCEncryKey`.

- **Key** = device ID (tag `0x881`, the serial suffix) **+** MAC (tag `0x100`), both printed on the label.
- **IV** = `DefAESCBCIV`, a fixed value (`ZTE%FN$GponNJ025`) stored in the firmware and identical on every unit.

This matches the key my own decryption produced byte-for-byte (serial-tail + reversed-MAC). **Impact:** any `config.bin` from any unit of this build is decryptable by anyone who can read the device's sticker — no secret material is involved.

### F2 — Factory-mode authentication backdoor (High)

The `httpd` binary's `doWebCheckAuth` has two authentication paths:

```c
GetTagParam(0xb01, flag, 7, ...);                    // factory-mode flag
if (flag == "1") {                                   // PATH A — factory mode:
    strncpy(buf, "user=factorymode&pass=<HARDCODED>", 0x20b);  // fixed, fleet-wide credential
    result = strcmp(client_input, buf);              // accept if client sent exactly this
} else {                                             // PATH B — normal:
    CmDevGetAuthInfo("IGD.AU1", creds);              // real configured admin credentials
    snprintf(buf, ..., "user=%s&pass=%s", creds...);
    result = strcmp(client_input, buf);
}
return (result == 0) ? AUTH_OK : AUTH_FAIL;
```

> *Screenshot placeholder:* `images/f2_httpd_backdoor.png` — decompiled `doWebCheckAuth`.

When the factory-mode flag (`tag 0xb01`) is set, authentication ignores the owner's admin password entirely and accepts a **hardcoded credential compiled into the binary** — identical across the fleet and extractable from the firmware. The factory endpoint's step sequence sets that flag, so a LAN-adjacent attacker can flip the gate and walk through it to telnet/root. The comparison is a plaintext `strcmp` (no hashing, no constant-time check).

This factory path is **not a discovery** — it is undocumented by ZTE but publicly known in the ONT/security community and implemented in the open-source `douniwan5788/zte_modem_tools`. The contribution here is confirming the mechanism at the binary level by decompiling the actual authentication routine, rather than treating the tool as a black box. The specific credential is published in that project and is not reproduced here.

### F3 — Hardcoded-secret store with firmware-shipped key (Medium)

`/etc/hardcodefile/*` holds ZTE's "protected" default secrets as AES-CBC blobs. `CspHardCodeDecry` (in `libhardcode.so`) decrypts them:

```c
read(in, hdr, 0x3c);
if (hdr[0] != 0x04030201) return ERR;                // container magic
fseek(in, 0x3c);
do {
    fread(&blk, 1, 0xc, in);                          // per-block: plain_len, cipher_len, more
    buf = malloc(cipher_len); fread(buf, 1, cipher_len, in);
    out = AESCBCDecry(buf, cipher_len, &outlen, key, iv);   // key/iv sourced from /etc/hardcode
    fwrite(out, 1, plain_len, dst);
} while (more);
```

> *Screenshot placeholder:* `images/f3_libhardcode_decry.png` — decompiled `CspHardCodeDecry`.

The decryption key is read from **`/etc/hardcode`**, a file shipped *inside the same firmware image*. Encrypting secrets with a key you distribute alongside them provides no protection: `zte_hardcode_dump.py` (reading `/etc/hardcode` as the root key) decrypts the entire store. Recovered contents included the config IV (confirming *F1*), default service passwords, and TLS material (see *F4*/*F6*).

### F4 — Full credential disclosure (High)

Combining the decrypted config backup and the decrypted hardcode store yielded, among others (all **redacted/masked** here):

- **ISP management (TR-069/ACS):** username + password, ConnectionRequest credentials.
- **WAN/PPPoE:** subscriber login.
- **Wi-Fi:** WPA/WPA2 PSKs for all SSIDs.
- **Service defaults:** SMB (`samba`), SSH/FTP (`admin`) — static across the build.
- **TLS:** PKCS12 password and embedded private keys (see *F6*).
- **Admin/SMB account password = the device serial number** (see *F8*).

**Impact:** physical possession of the device — or merely a copy of its config backup — exposes the owner's ISP account, Wi-Fi, and VoIP/management credentials.

### F5 — Static root password hash in firmware (Medium)

`/etc/shadow` on the extracted rootfs contains a `$5$` (SHA-256-crypt) root hash:

```text
root:$5$<redacted-salt>$<redacted-hash>:...
```

The hash is part of the **firmware image**, so it is identical on every unit of this build (not device-derived). It resisted a focused dictionary of known ZTE/ISP defaults and a `hashcat` run (mode 7400, sha256crypt) against rockyou did not recover it. Throughput was the limiting factor — CPU-only via PoCL at ~3.4 kH/s (the RX 6500M GPU path was unusable: ROCm does not support `gfx1034`), so the full keyspace was not covered. Targeted masks (e.g. `Zte?d?d?d`) remain an option for a later attempt. The weakness is structural regardless: a single shared root hash means one successful offline crack yields root on the entire fleet. (In practice the factory-mode path in *F2* and the reflash path in step 11 make cracking unnecessary.) The full hash is withheld.

### F6 — Embedded static TLS private keys (Medium)

The rootfs ships RSA private keys (`/etc/server-key.pem`, `/etc/zxv10.pem`, `/etc/tr064/tr064.key`) and the hardcode store yields the keystore passwords. Because these are the same on every unit, an attacker can impersonate or MITM the device's HTTPS/TR-064 services fleet-wide. Keys are not reproduced here.

### F7 — Unauthenticated firmware extraction via open bootloader (Medium)

U-Boot autoboot is interruptible with no bootloader password, and there is no secure/verified boot. Anyone with brief physical access and a UART adapter can read the entire NAND (`nand read` + memory display, as done here), exposing every secret above. Signed-boot / bootloader lockdown would raise the bar for all of these physical-access findings.

### F8 — Admin web password equals the serial number (Low)

The provisioned `admin` account's password is the device serial number (also the SMB password). The serial is printed on the label and is the GPON serial, so it is both physically visible and, in some deployments, discoverable — making the "strong" provisioned password effectively public.

---

## Root cause

A single theme runs through every finding: **security built on static, shared, firmware-embedded secrets.**

- Config "encryption" keyed on label values + a constant IV (F1).
- A hardcoded factory credential (F2).
- A secret store whose key ships beside it (F3).
- A fleet-wide root hash (F5) and fleet-wide TLS keys (F6).

None of these survive an attacker obtaining the firmware — and *F7* shows the firmware is trivially obtainable with physical access. The model assumes the firmware stays secret; it does not.

## Recommendations

- **Per-device random key material** for config encryption and service accounts — never derive keys from label-visible identifiers, and never use a fixed IV.
- **Remove the hardcoded factory credential** (F2); if a factory path must exist, gate it on a per-device secret and disable it in production builds.
- **Separate keys from ciphertext** — do not ship the hardcode master key inside the image (F3).
- **Unique per-device root password and TLS keys** (F5, F6).
- **Secure boot + bootloader password** to resist trivial physical firmware extraction (F7).
- **Do not set application passwords to the serial number** (F8).

## Prior work & CVEs

This device family has a documented history; my work reproduces and extends it:

| CVE | Summary |
|-----|---------|
| CVE-2018-7363 | Improper authorization in `appviahttp` — credential brute force (F670). |
| CVE-2019-3417 | Authenticated command injection → device takeover (F670). |
| CVE-2020-6879 | Web input-validation bypass (F670L). |
| CVE-2021-21727 | DoS (F670L). |

The config-decryption and factory-mode techniques build on the public `mkst/zte-config-utility` and `douniwan5788/zte_modem_tools` projects.

---

## Appendix — reproduction

**Toolchain:** `picocom`, `pyserial`, `jefferson`, `radare2`, Ghidra, `mkst/zte-config-utility`, `douniwan5788/zte_modem_tools`, `pycryptodome`.

**Key steps:**
1. UART @ 115200 8N1 via CH340 (3.3 V); identify pins with a multimeter.
2. Interrupt U-Boot; `nand read` + `md.b` per-partition dump, logged; reconstruct and verify.
3. Extract JFFS2 with `jefferson`.
4. Web `admin/admin` → USB config backup; decrypt offline with `zte-config-utility` (key = serial+MAC, IV = firmware constant).
5. `zte_hardcode_dump.py` with `/etc/hardcode` to decrypt `/etc/hardcodefile/*`.
6. `zte_factroymode.py telnet open` → root telnet shell.
7. Ghidra analysis of `httpd`, `cspd`, `libhardcode.so` (ARM:LE:32, unstripped).

**Integrity:** SHA-256 hashes of the reconstructed `rootfs0` image and extracted archive are recorded alongside the artifacts. Device-specific and fleet-wide secrets are redacted in all published material.

---

*Written up as a personal hardware-security learning project. Testing was limited to my own device, offline. Findings reflect publicly known weakness classes in this product family.*
