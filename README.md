bt-synckeys
---
Python script to sync Bluetooth pairing keys from Windows to your Linux installations.
**Now don't need to pair device in Linux for successful sync*

## Changes in this fork
### Fixes
- Fixed the update confirmation prompt: it used to be inverted, applying the update on any answer OTHER than "y" (including just pressing Enter), and doing nothing when you actually answered "y".
- Auto-detects the active ControlSet instead of assuming `ControlSet001`.
- Rejects malformed/unexpected registry entries instead of misbehaving on them.

### Improvements
- No need to manually create the device's `/var/lib/bluetooth/<adapter>/<device>` directory or copy an existing pairing folder — the script creates it from scratch under the correct MAC.
- No need to pair in Linux first, then Windows, then back to Linux, and so on — pair once in Windows and run the script; that's it.
- BLE devices: `KeyLength` falls back to 16 when Windows reports it as 0 — a known Windows registry quirk; a real key length is never 0, and leaving it as 0 makes BlueZ treat the encryption key as invalid.
- BLE devices: syncs address type (public/static) and forces the LE technology flag — without these, BlueZ may fail to connect even with fully correct keys.
- BLE devices: pulls the real device name from the Windows registry instead of leaving it blank.
- BLE devices: cleans up leftover entries left behind by MAC rotation (matched by Identity Resolving Key).
- No need to manually restart the bluetooth service — the script does it for you, trying systemd, SysV init and OpenRC.

## Warning / Disclaimer
> The code and instructions within this project accesses and modifies system files on your Windows and Linux installations. Although care has been taken to ensure that nothing harmful happens, there could be a risk of damage to your software and hardware. Your usage of the program and instructions herein constitutes acceptance of those risks and the author cannot be held liable for any claims whatsoever.

## Prerequisites 
* Python 3.6+
* **sudo** / **root** access.

## Usage
For either of the methods to work, **you need to have the Bluetooth devices paired with Windows system**. This is necessary to create the required initial pairing configurations.

Do note, however, that **it's not necessary to have the devices connected to your system at the time of the procedures.**
But it **is** necessary to have the device **working on Windows** prior to running the script, as it will read the pairing keys from the Windows registry.

### Notes for BLE devices
Modern BLE devices rotate their random MAC address on each new pairing, so the MAC address Windows recorded may differ from whatever MAC Linux paired with before. This isn't a problem: the script creates the device entry from scratch under the Windows-reported MAC regardless of any prior Linux pairing.

If the device was already paired with Linux under a different, now-stale MAC (same device, matching Identity Resolving Key), the script automatically removes that leftover entry so it doesn't linger as a dead duplicate.


### Method A. Dump and sync keys from within Linux
#### Additional Prerequisites
* `chntpw` 
  - Arch: `sudo pacman -S chntpw`
  - Debian/Ubuntu: `sudo apt install chntpw`

This method requires at least read-only access to your Windows drive in Linux.
- Run the `bt-synckeys.py` Python 3 script with **root** or **sudo**:
```
sudo ./bt-synckeys.py -w /path/to/windows/drive/root
```
The root path should be the root of your Windows drive, i.e. there's a `Windows` folder in it.
- Follow the prompts.
- Once the keys are updated, the script automatically restarts the bluetooth service so the changes take effect — no manual step needed. If it can't (e.g. an unrecognized init system), it'll tell you to restart it yourself:
```
sudo systemctl restart bluetooth
```
### Method B. Dump keys from Windows and sync to Linux
#### Additional Prequisites

On Windows you need **Administrator** access. No third-party tools are required — `reg save` is built into Windows.

### Steps
- Reboot into your Windows system and pair the same devices again. We will use the keys generated from this OS.
- Open a command prompt in **Administrator** mode and run the following command to save a copy of the registry hive:
```
reg save HKLM\SYSTEM C:\system.hive
```
- Copy the file from `C:\system.hive` into a removeable storage or a location which is accessible by your Linux system.
- Reboot into your Linux system.
- Copy the `system.hive` file to an accessible location in your Linux filesystem.
- Open a terminal and navigate to the location where `bt-synckeys.py` is located.
- Run the `bt-synckeys.py` Python 3 script with **root** or **sudo**:
```
sudo ./bt-synckeys.py -r /path/to/system.hive
```
> **NOTE:** `-r` expects a raw registry hive file (as produced by `reg save`), not a text `.reg` export — the script parses it internally with `reged` (from `chntpw`, same as Method A). Make sure `chntpw` is installed on the Linux system as well.
- The adapters and devices from the key dump will be compared to the pairing in Linux and if a difference is detected, it will prompt you to update the keys. You can choose Yes or No (default). If you choose `Yes`, a timestamped backup file is created in the `/var/lib/bluetooth/{ADAPTER_MAC}/{DEVICE_MAC}` directory before the update is performed.
```
Bluetooth Adapter - 7C:B2:7D:57:EA:D5
  DC:0C:2D:ED:01:65 (# not paired #)
  04:00:00:00:6A:8B (# not paired #)

  0C:E0:E4:C8:27:5D (PLT_BBTSENSE / PLT_BBTSENSE)
    | LinkKey: 63C1F72FB8E5F474AED058019A834FDA > No change required.

  F3:46:AD:D7:53:3C (Orochi V2 / Orochi V2)
    | IdentityResolvingKey: BB123FA60524A22A5AF33EE83514FF0B > Update to: AA764EA60524A76A5AF50EE49463ED0C
    | LongTermKey: 28513DB654511A7346BDA3F676CAE7F8 > Update to: 85140DC915611A7346ECD3F676CFF7E9
    |   EncSize: 16 > No change required.
    |   EDiv: 43465 > Update to: 74325
    |   Rand: 5734307009814747306 > Update to: 9876302985738291827
    > Update keys for device? (y/N): y
    > OK!
```
- Once the keys are updated, the script automatically restarts the bluetooth service so the changes take effect — no manual step needed. If it can't (e.g. an unrecognized init system), it'll tell you to restart it yourself:
```
sudo systemctl restart bluetooth
```