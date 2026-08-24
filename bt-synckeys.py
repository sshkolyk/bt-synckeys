#!/usr/bin/env python

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
    DEFAULT_CONTROL_SET = "ControlSet001"
    keys_registry = None

    def __init__(self, windows_path=None, registry_file=None):
        control_set = self._resolve_current_control_set(windows_path, registry_file)
        keys_path = self.WINDOWS_BT_REGISTRY_KEYS_PATH_TEMPLATE.format(control_set=control_set)
        keys_raw = self._export_registry(windows_path, keys_path, registry_file)
        self.keys_registry = self.load_windows_devices(keys_raw)

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


class ProcessWindowKeys:
    registry_repository: WindowsRegistryRepository = None

    def __init__(self, registry_repository):
        self.registry_repository = registry_repository

    def _process_win_basic_pairing(self, window_device_keys, adapter_mac):
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

            require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "LinkKey", "Key", windows_key)
            require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Trusted", "true")
            require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Paired", "yes")
            require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Blocked", "false")

            if not require_update: continue

            action = input(f"    > Update keys for device? (y/N): ")
            if action.lower() == "y":
                LinuxDeviceInfo.write_info(adapter_mac, device_mac, linux_config)
                print(f"    > OK!")

    def _process_win_advanced_pairing(self, windows_config, adapter_mac, device_mac):
        # Check this adapter's paired devices in the current Linux system
        linux_config = LinuxDeviceInfo.get_info(adapter_mac, device_mac)
        LinuxDeviceInfo.print_device_info(linux_config, device_mac)
        require_update = False

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
        process_parameter_by_key("EDIV", keys_sections, "EDiv", lambda v: str(int(RegistryParameterFormat.dword(v), 16) or 16))
        process_parameter_by_key("ERand", keys_sections, "Rand", lambda v: str(int(RegistryParameterFormat.hex_b(v), 16) or 16))
        require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Trusted", "true")
        require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Paired", "yes")
        require_update |= LinuxDeviceInfo.set_config_parameter(linux_config, "General", "Blocked", "false")

        if not require_update: return

        action = input(f"    > Update keys for device? (y/N): ")
        if action.lower() == "y":
            LinuxDeviceInfo.write_info(adapter_mac, device_mac, linux_config)
            print(f"    > OK!")
        else:
            print("    > Omitted")

    def process_windows_devices(self):
        windows_devices = self.registry_repository.keys_registry
        # Sort the list of adapters and adapter\device pairs to make sequential grouping by adapter and parsing easier
        for windows_device in sorted(windows_devices.keys()):
            try:
                if not "\\" in windows_device:
                    adapter_mac = RegistryParameterFormat.mac_address(windows_device)
                    print_adapter_mac(adapter_mac)
                    # Launch basic pairing extraction and update
                    self._process_win_basic_pairing(windows_devices[windows_device], adapter_mac)
                else:
                    mac_addresses = windows_device.split("\\")
                    adapter_mac = RegistryParameterFormat.mac_address(mac_addresses[0])
                    device_mac = RegistryParameterFormat.mac_address(mac_addresses[1])
                    print_adapter_mac(adapter_mac)
                    # Launch advanced pairing extraction and update
                    self._process_win_advanced_pairing(windows_devices[windows_device], adapter_mac, device_mac)
            except ValueError as e:
                print(f"! Skipping unexpected registry entry {windows_device!r}: {e}")
                continue


class RegistryParameterFormat:
    @staticmethod
    def hex(hex_string):
        return hex_string.replace("hex:", "").replace(",", "").upper()

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
        if not device_config:
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
    return parser.parse_args()


def __main__():
    if not os.geteuid() == 0:
        print("ERROR: You need to be root to be able to run this script.")
        return 1
    args = parse_args()
    if args.windows_dir:
        print(f"Using Windows root {args.windows_dir}")
    elif args.registry_file:
        print(f"Reading from Registry file {args.registry_file}")
    else:
        print(
            "ERROR: You must specify either a Windows directory (-w) or a Registry file (-r)"
        )
        return 1

    registry_repository = WindowsRegistryRepository(args.windows_dir, args.registry_file)
    ProcessWindowKeys(registry_repository).process_windows_devices()
    return 0


if __name__ == "__main__":
    sys.exit(__main__())
