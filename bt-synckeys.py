#!/usr/bin/env python3

import configparser
import argparse
import os
import shutil
import re
from datetime import datetime
from tempfile import TemporaryDirectory
import subprocess
import sys
from collections import defaultdict

# General global variables
_prev_adapter_mac = None

class WindowsRegistryRepository:
    WINDOWS_REGISTRY_PATH = os.path.join("Windows", "System32", "config", "SYSTEM")
    WINDOWS_BT_REGISTRY_KEYS_PATH_TEMPLATE = r"{control_set}\Services\BTHPORT\Parameters\Keys"
    WINDOWS_BT_REGISTRY_DEVICES_PATH_TEMPLATE = r"{control_set}\Services\BTHPORT\Parameters\Devices"
    DEFAULT_CONTROL_SET = "ControlSet001"
    keys_registry = None
    device_names = None

    def __init__(self, windows_path=None, registry_file=None):
        control_set = self._resolve_current_control_set(windows_path, registry_file)
        keys_path = self.WINDOWS_BT_REGISTRY_KEYS_PATH_TEMPLATE.format(control_set=control_set)
        keys_raw = self._export_registry(windows_path, keys_path, registry_file)
        self.keys_registry = self.load_windows_devices(keys_raw)
        self.device_names = self._load_device_names(windows_path, control_set, registry_file)

    def _load_device_names(self, windows_root, control_set, registry_file_path) -> dict:
        """Best-effort lookup of device_mac -> friendly name, read from the sibling
        Devices registry key (flat, keyed by device MAC, holding a "Name" REG_BINARY
        value with a null-terminated ASCII/UTF-8 string) - not the Keys key used for
        pairing material."""
        devices_path = self.WINDOWS_BT_REGISTRY_DEVICES_PATH_TEMPLATE.format(control_set=control_set)
        try:
            devices_raw = self._export_registry(windows_root, devices_path, registry_file_path)
            devices_registry = self.load_windows_devices(devices_raw)
        except Exception as e:
            print(f"WARNING: Could not read device names from registry: {e}")
            return {}

        names = {}
        for section, values in devices_registry.items():
            if "Name" not in values:
                continue
            try:
                device_mac = RegistryParameterFormat.mac_address(section.split("\\")[-1])
                names[device_mac] = RegistryParameterFormat.ascii(values["Name"])
            except ValueError:
                continue
        return names

    def _resolve_current_control_set(self, windows_root, registry_file_path):
        """Determines the active ControlSet (HKLM\\SYSTEM\\Select\\Current), falling back to
        DEFAULT_CONTROL_SET if it cannot be read."""
        select_raw = self._export_registry(windows_root, "Select", registry_file_path)
        match = re.search(r'(?im)^"?Current"?\s*=\s*dword:([0-9a-fA-F]+)', select_raw)
        if not match:
            print(f"WARNING: Could not determine active ControlSet from Select\\Current, falling back to {self.DEFAULT_CONTROL_SET}")
            return self.DEFAULT_CONTROL_SET
        current = int(match.group(1), 16)
        return f"ControlSet{current:03d}"

    def _export_registry(self, windows_root, registry_location, registry_file_path=None):
        """Exports given registry key as text
        Args:
            registry_file_path: registry file_path
            registry_location (str): key for export
                NOTE:   key should be relative to Hive file. For example, "ControlSet001" placed in root of "SYSTEM" file.
                        @see chntpw and reged manuals for details

        Returns:
            (str): content of registry
        """
        if registry_file_path is None: registry_file_path = self.WINDOWS_REGISTRY_PATH
        with TemporaryDirectory() as temp_dir_name:
            exported_reg_filename = os.path.join(temp_dir_name, "exported.reg")
            # SAMPLE: reged -x ./Windows/System32/config/SYSTEM PREFIX "ControlSet001\Services\...." out.reg
            export_cmd = [
                "reged",
                "-x",
                registry_file_path if windows_root is None else os.path.join(windows_root, registry_file_path),
                "HKEY_LOCAL_MACHINE\\SYSTEM",
                registry_location,
                exported_reg_filename,
            ]
            subprocess.run(export_cmd)

            with open(exported_reg_filename, "r") as f:
                exported_text = f.read()
        return exported_text

    def load_windows_devices(self, contents: str, prefix=None) -> dict:
        # .reg export wraps long values across lines with a trailing "\" - join them
        # back into one line before parsing, otherwise the value gets truncated.
        contents = re.sub(r"\\\r?\n\s*", "", contents)
        contents = contents.replace('"', "")

        contents = re.sub(
            r"HKEY_LOCAL_MACHINE\\SYSTEM\\[^\\]*\\Services\\BTHPORT\\Parameters\\Keys\\",
            "",
            contents,
        )

        lines = contents.splitlines()[4:]

        data = defaultdict(dict)
        current_key = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # find [section]
            if line.startswith('[') and line.endswith(']'):
                current_key = line.strip("[ ]")
                if prefix is not None and not current_key.startswith(prefix):
                    continue
                data[current_key] = {}
                continue

            if prefix is not None and not current_key.startswith(prefix):
                continue

            if current_key is None or "=" not in line:
                continue

            k, v = map(str.strip, line.split("=", 1))
            data[current_key][k] = v

        return dict(data)


class ProcessWindowsRegistryKeys:
    registry_repository: WindowsRegistryRepository = None

    def __init__(self, registry_repository, auto_confirm=False):
        self.registry_repository = registry_repository
        self.auto_confirm = auto_confirm
        self.any_update = False

    def _process_win_br_edr_pairing(self, window_device_keys, adapter_mac):
        # Iterate through each device and pairing key from the dumped registry config
        for device, windows_key in window_device_keys.items():
            if device.lower() == "masterirk": continue

            try:
                device_mac = RegistryParameterFormat.mac_address(device)
            except ValueError as e:
                print(f"    ! Skipping unexpected registry entry: {e}")
                continue
            windows_key = RegistryParameterFormat.hex(windows_key)

            # Check this adapter's paired devices in the current Linux system
            linux_config = LinuxDeviceInfo.get_info(adapter_mac, device_mac)
            LinuxDeviceInfo.print_device_info(linux_config, device_mac)
            require_update = False

            if not linux_config.get("General", "Name", fallback=None):
                device_name = self.registry_repository.device_names.get(device_mac, device_mac)
                require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Name", device_name)
            require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "LinkKey", "Key", windows_key)
            require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Trusted", "true")
            require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Paired", "yes")
            require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Blocked", "false")

            if not require_update: continue

            action = "y" if self.auto_confirm else input(f"    > Update keys for device? (y/N): ")
            if action.lower() == "y":
                LinuxDeviceInfo.write_info(adapter_mac, device_mac, linux_config)
                self.any_update = True
                print(f"    > OK!")

    def _process_win_ble_pairing(self, windows_config, adapter_mac, device_mac):
        # BLE devices can rotate their random address between OSes, so a device previously
        # synced/paired under an old MAC may now show up under a new one. Syncing from
        # scratch under the new MAC already works on its own; a matching IRK guarantees
        # it's the same physical device, so we clean up the old MAC's leftover entry.
        if "IRK" in windows_config:
            irk = RegistryParameterFormat.hex(windows_config["IRK"])
            for stale_mac in LinuxDeviceInfo.find_stale_by_irk(adapter_mac, irk, device_mac):
                print(f"    > Removing stale Linux entry {stale_mac} (same IRK, old MAC)")
                LinuxDeviceInfo.remove(adapter_mac, stale_mac)

        # Check this adapter's paired devices in the current Linux system
        linux_config = LinuxDeviceInfo.get_info(adapter_mac, device_mac)
        LinuxDeviceInfo.print_device_info(linux_config, device_mac)
        require_update = False

        if not linux_config.get("General", "Name", fallback=None):
            device_name = self.registry_repository.device_names.get(device_mac, device_mac)
            require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Name", device_name)

        def process_parameter_by_key(win_key: str, section, key: str, value_callback=RegistryParameterFormat.hex) -> None:
            if not win_key in windows_config: return
            value = windows_config.get(win_key)
            if value_callback is not None:
                value = value_callback(value)
            if type(section) == str:
                section = [section]
            for s in section:
                nonlocal require_update
                require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, s, key, value)

        keys_sections = ["LongTermKey", "SlaveLongTermKey", "PeripheralLongTermKey"]
        process_parameter_by_key("IRK", "IdentityResolvingKey", "Key")
        process_parameter_by_key("CSRK", "LocalSignatureKey", "Key")
        process_parameter_by_key("LTK", keys_sections, "Key")
        process_parameter_by_key("KeyLength", keys_sections, "EncSize", lambda v: str(int(RegistryParameterFormat.dword(v), 16) or 16))
        # EDIV/Rand are legitimately 0 for LE Secure Connections pairing - BlueZ appears to use
        # EDiv==0 && Rand==0 as the signal that a key is SC-derived, so don't paper over real zeros here.
        process_parameter_by_key("EDIV", keys_sections, "EDiv", lambda v: str(int(RegistryParameterFormat.dword(v), 16)))
        process_parameter_by_key("ERand", keys_sections, "Rand", lambda v: str(int(RegistryParameterFormat.hex_b(v), 16)))
        # BlueZ needs to know whether this is a public or a static random address to
        # actually connect to it - without it, LE devices using a random address (like
        # most modern mice/keyboards) may fail to reconnect even with correct keys.
        process_parameter_by_key("AddressType", "General", "AddressType", lambda v: "static" if int(RegistryParameterFormat.dword(v), 16) else "public")
        # BlueZ can default this to "BR/EDR;" when it first creates the device entry,
        # before it knows better - which makes it page as classic and never try LE at all.
        # This is a BLE-only entry, so force it to LE.
        require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "SupportedTechnologies", "LE;")
        require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Trusted", "true")
        require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Paired", "yes")
        require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Blocked", "false")

        if not require_update: return

        action = "y" if self.auto_confirm else input(f"    > Update keys for device? (y/N): ")
        if action.lower() == "y":
            LinuxDeviceInfo.write_info(adapter_mac, device_mac, linux_config)
            self.any_update = True
            print(f"    > OK!")
        else:
            print("    > Omitted")

    def run(self):
        windows_devices = self.registry_repository.keys_registry
        # Sort the list of adapters and adapter\device pairs to make sequential grouping by adapter and parsing easier
        for windows_device in sorted(windows_devices.keys()):
            try:
                if not "\\" in windows_device:
                    adapter_mac = RegistryParameterFormat.mac_address(windows_device)
                    print_adapter_mac(adapter_mac)
                    # Launch basic pairing extraction and update
                    self._process_win_br_edr_pairing(windows_devices[windows_device], adapter_mac)
                else:
                    mac_addresses = windows_device.split("\\")
                    adapter_mac = RegistryParameterFormat.mac_address(mac_addresses[0])
                    device_mac = RegistryParameterFormat.mac_address(mac_addresses[1])
                    print_adapter_mac(adapter_mac)
                    # Launch advanced pairing extraction and update
                    self._process_win_ble_pairing(windows_devices[windows_device], adapter_mac, device_mac)
            except ValueError as e:
                print(f"! Skipping unexpected registry entry {windows_device!r}: {e}")
                continue


class RegistryParameterFormat:
    @staticmethod
    def hex(hex_string):
        return hex_string.replace("hex:", "").replace(",", "").upper()

    @staticmethod
    def ascii(hex_string):
        raw_bytes = bytes.fromhex(RegistryParameterFormat.hex(hex_string))
        return raw_bytes.decode("utf-8", errors="replace").rstrip("\x00")

    @staticmethod
    def hex_b(hex_string):
        hex_parts = hex_string.replace("hex(b):", "").split(",")
        hex_parts.reverse()
        return "".join(hex_parts)

    @staticmethod
    def dword(dword_string):
        dword = dword_string.replace("dword:", "")
        return dword

    @staticmethod
    def mac_address(mac_string):
        address = mac_string.upper()
        if not re.fullmatch(r"[0-9A-F]{12}", address):
            raise ValueError(f"Invalid MAC address in registry data: {mac_string!r}")
        address_parts = [address[i : i + 2] for i in range(0, len(address), 2)]
        return ":".join(address_parts)


class LinuxDeviceInfo:
    @staticmethod
    def get_path(adapter_mac, device_mac):
        return f"/var/lib/bluetooth/{adapter_mac}/{device_mac}"

    @staticmethod
    def find_stale_by_irk(adapter_mac, irk, exclude_mac):
        """Find other paired Linux devices under this adapter with a matching IRK.
        Used to clean up leftover entries from BLE devices that rotated their
        random address between OSes (same physical device, old MAC)."""
        adapter_path = f"/var/lib/bluetooth/{adapter_mac}"
        if not os.path.isdir(adapter_path):
            return []
        matches = []
        for entry in os.listdir(adapter_path):
            if entry == exclude_mac:
                continue
            config = LinuxDeviceInfo.get_info(adapter_mac, entry)
            if config.get("IdentityResolvingKey", "Key", fallback=None) == irk:
                matches.append(entry)
        return matches

    @staticmethod
    def remove(adapter_mac, device_mac):
        shutil.rmtree(LinuxDeviceInfo.get_path(adapter_mac, device_mac), ignore_errors=True)

    @staticmethod
    def backup_linux_info_file(adapter_mac, device_mac):
        device_path = LinuxDeviceInfo.get_path(adapter_mac, device_mac)
        now = datetime.now()
        current_datetime = now.strftime("%Y%m%d%H%M%S")
        if os.path.isfile(device_path):
            os.remove(device_path)
        if not os.path.isdir(device_path):
            os.makedirs(device_path)
        if os.path.isfile(f"{device_path}/info"):
            shutil.copyfile(f"{device_path}/info", f"{device_path}/info-{current_datetime}")


    @staticmethod
    def get_info(adapter_mac, device_mac):
        device_path = LinuxDeviceInfo.get_path(adapter_mac, device_mac)
        info_file = f"{device_path}/info"

        pairing_config = configparser.ConfigParser()
        pairing_config.optionxform = str

        if os.path.isfile(info_file):
            # Read info data into a config structure
            pairing_config.read(info_file)
        return pairing_config

    @staticmethod
    def write_info(adapter_mac, device_mac, config):
        LinuxDeviceInfo.backup_linux_info_file(adapter_mac, device_mac)
        # Write config structure back to info file
        device_path = LinuxDeviceInfo.get_path(adapter_mac, device_mac)
        info_file = open(f"{device_path}/info", "w")
        config.write(info_file)
        info_file.close()

    @staticmethod
    def print_device_info(device_config, device_mac):
        if not device_config.has_section("General"):
            print(f"  {device_mac} (# not paired #)")
            return

        # Get paired device name
        device_name = device_config.get("General", "Name", fallback="# No name #")
        device_alias = device_config.get("General", "Alias", fallback="# No alias #")
        print(f"\n  {device_mac} ({device_name} / {device_alias})")

    @staticmethod
    def set_config_parameter(linux_config: configparser.ConfigParser, section: str, key: str, value: str):
        if not linux_config.has_section(section):
            linux_config.add_section(section)
        old_value = linux_config.get(section, key, fallback=None)
        linux_config.set(section, key, value)
        return print_updated_values(section + "." + key, old_value, value)



def print_updated_values(name: str, current_value: str, new_value: str) -> bool:
    change_required = False

    if current_value == new_value:
        print(f"    | {name}: {current_value} > No change required.")
    else:
        print(f"    | {name}: {current_value} > Update to: {new_value}")
        change_required = True

    return change_required


def print_adapter_mac(current_adapter_mac):
    global _prev_adapter_mac
    # Only print the adapter mac information if we are starting for the first time or when we change adapter group of devices.
    # Will work only if we sort device and adapter\device pairs first such that they are grouped together.
    if _prev_adapter_mac != current_adapter_mac:
        if _prev_adapter_mac is not None:
            print()
        print(f"Bluetooth Adapter - {current_adapter_mac}")
    _prev_adapter_mac = current_adapter_mac


def restart_bluetooth_service() -> bool:
    """Try a handful of known ways to restart the bluetooth service, covering the
    common init systems. Never raises - only ever returns whether one of them
    reported success, so the script itself never crashes over this."""
    candidates = [
        ["systemctl", "restart", "bluetooth"],
        ["systemctl", "restart", "bluetooth.service"],
        ["service", "bluetooth", "restart"],
        ["rc-service", "bluetooth", "restart"],
        ["/etc/init.d/bluetooth", "restart"],
    ]
    for cmd in candidates:
        binary = cmd[0]
        if not os.path.isabs(binary) and shutil.which(binary) is None:
            continue
        if os.path.isabs(binary) and not os.path.isfile(binary):
            continue
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception:
            continue
        if result.returncode == 0:
            return True
    return False


def find_mounted_windows_root():
    """Look for an already-mounted Windows partition (containing Windows/System32/config/SYSTEM)
    among the currently mounted filesystems. Returns its mount point, or None if there isn't
    exactly one candidate."""
    try:
        with open("/proc/mounts") as f:
            mount_points = {line.split()[1] for line in f}
    except OSError:
        return None

    candidates = [
        mount_point for mount_point in mount_points
        if os.path.isfile(os.path.join(mount_point, WindowsRegistryRepository.WINDOWS_REGISTRY_PATH))
    ]

    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        print("WARNING: Multiple mounted Windows partitions found, please pick one with -w:")
        for candidate in candidates:
            print(f"  {candidate}")
    return None


def parse_args():
    parser = argparse.ArgumentParser(
        description="SyncKeys - Update Linux Bluetooth keys from Windows-paired devices"
    )
    parser.add_argument(
        "-w",
        "--windows-dir",
        help="Path to the root of your mounted Windows drive",
    )
    parser.add_argument(
        "-r",
        "--registry-file",
        help="Path to the dumped Registry file. Ignored if `-w` (`--windows-dir`) is also given",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Apply all detected updates without asking for confirmation (for unattended/automated runs)",
    )
    return parser.parse_args()


def __main__():
    if not os.geteuid() == 0:
        print("ERROR: You need to be root to be able to run this script.")
        return 1
    if shutil.which("reged") is None:
        print("ERROR: `reged` was not found. Install `chntpw` first, e.g.:")
        print("  Arch:          sudo pacman -S chntpw")
        print("  Debian/Ubuntu: sudo apt install chntpw")
        print("  Fedora:        sudo dnf install chntpw")
        print("  RHEL:          sudo dnf install epel-release && sudo dnf install chntpw")
        print("  openSUSE:      sudo zypper install chntpw")
        return 1
    args = parse_args()
    if not args.windows_dir and not args.registry_file:
        args.windows_dir = find_mounted_windows_root()
        if args.windows_dir:
            print(f"Auto-detected mounted Windows partition at {args.windows_dir}")

    if args.windows_dir:
        print(f"Using Windows root {args.windows_dir}")
    elif args.registry_file:
        print(f"Reading from Registry file {args.registry_file}")
    else:
        print(
            "ERROR: You must specify either a Windows directory (-w) or a Registry file (-r).\n"
            "       If you have a Windows partition, mount it anywhere (e.g. `sudo mount /dev/sdXN /mnt/win`)\n"
            "       and either pass that path via -w, or just re-run without arguments to auto-detect it."
        )
        return 1

    registry_repository = WindowsRegistryRepository(args.windows_dir, args.registry_file)
    processor = ProcessWindowsRegistryKeys(registry_repository, auto_confirm=args.yes)
    processor.run()

    if processor.any_update:
        print()
        print("Restarting bluetooth service to apply changes...")
        if restart_bluetooth_service():
            print("Done.")
        else:
            print("! Could not restart the bluetooth service automatically - please restart it manually, e.g.:")
            print("  sudo systemctl restart bluetooth")
    return 0


if __name__ == "__main__":
    sys.exit(__main__())
