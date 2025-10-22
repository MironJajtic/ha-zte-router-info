from __future__ import annotations
from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN
from .coordinator import ZteCoordinator

SENSOR_KEYS = {
    # Network & Signal
    "network_type": {"name": "Network Type"},
    "rssi": {"name": "RSSI", "unit": "dBm"},
    "rscp": {"name": "RSCP", "unit": "dBm"},
    "lte_rsrp": {"name": "LTE RSRP", "unit": "dBm"},
    "sinr": {"name": "SINR", "unit": "dB"},
    "ecio": {"name": "Ec/Io", "unit": "dB"},
    "signalbar": {"name": "Signal Bars"},
    "network_provider_fullname": {"name": "Network Provider"},

    # LTE Info
    "ZCELLINFO_band": {"name": "LTE Band"},
    "cell_id": {"name": "Cell ID"},
    "Z_PCI": {"name": "PCI"},
    "Z_dl_earfcn": {"name": "DL EARFCN"},

    # Carrier Aggregation
    "wan_lte_ca": {"name": "Carrier Aggregation Status"},
    "lte_ca_pcell_band": {"name": "CA Primary Band"},
    "lte_ca_scell_band": {"name": "CA Secondary Band"},
    "lte_ca_pcell_bandwidth": {"name": "CA Primary Bandwidth", "unit": "MHz"},
    "lte_ca_scell_bandwidth": {"name": "CA Secondary Bandwidth", "unit": "MHz"},
    "lte_ca_pcell_arfcn": {"name": "CA Primary ARFCN"},
    "lte_ca_scell_arfcn": {"name": "CA Secondary ARFCN"},
    "lte_ca_scell_info": {"name": "CA Secondary Cell Info"},

    # Network Status
    "modem_main_state": {"name": "Modem State"},
    "ppp_status": {"name": "PPP Status"},
    "simcard_roam": {"name": "Roaming Status"},

    # IP Addresses
    "lan_ipaddr": {"name": "LAN IP"},
    "wan_ipaddr": {"name": "WAN IP"},

    # Throughput (real-time)
    "realtime_tx_thrpt": {"name": "Upload Speed", "unit": "bps"},
    "realtime_rx_thrpt": {"name": "Download Speed", "unit": "bps"},
    "realtime_tx_bytes": {"name": "Session TX Bytes", "unit": "B"},
    "realtime_rx_bytes": {"name": "Session RX Bytes", "unit": "B"},
    "realtime_time": {"name": "Session Time", "unit": "s"},

    # Monthly usage
    "monthly_rx_bytes": {"name": "Monthly Download", "unit": "B"},
    "monthly_tx_bytes": {"name": "Monthly Upload", "unit": "B"},
    "monthly_time": {"name": "Monthly Time", "unit": "s"},

    # Battery (if present)
    "battery_charging": {"name": "Battery Charging"},
    "battery_vol_percent": {"name": "Battery Percent", "unit": "%"},
    "battery_value": {"name": "Battery Voltage", "unit": "mV"},
    "battery_pers": {"name": "Battery Level", "unit": "%"},

    # WiFi
    "wifi_onoff_state": {"name": "WiFi State"},
    "wifi_chip1_ssid1_ssid": {"name": "WiFi SSID"},
    "wifi_chip1_ssid1_access_sta_num": {"name": "WiFi Clients 2.4GHz"},
    "wifi_chip2_ssid1_access_sta_num": {"name": "WiFi Clients 5GHz"},

    # Device Info
    "cr_version": {"name": "Firmware Version"},

    # SMS
    "sms_unread_num": {"name": "Unread SMS"},
}

UNIT_MAP = {
    "rssi": "dBm",
    "rsrp": "dBm",
    "rscp": "dBm",
    "sinr": "dB",
    "ecio": "dB",
    "thrpt": "bps",
    "bytes": "B",
    "volt": "V",
    "temp": "°C",
    "bandwidth": "MHz",
}

IGNORE_KEYS = {"isTest", "_",
               "sms_received_flag_flag", "sts_received_flag_flag"}


def guess_unit(key: str):
    lk = key.lower()
    for pattern, unit in UNIT_MAP.items():
        if pattern in lk:
            return unit
    return None


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator: ZteCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = []

    # Only create sensors for fields that have actual data (not empty strings)
    for key, meta in SENSOR_KEYS.items():
        val = coordinator.data.get(key)
        # Only add sensor if field exists and has a non-empty value
        if key in coordinator.data and val not in (None, "", []):
            entities.append(ZteRouterInfoSensor(coordinator, key, meta))

    if coordinator.autodiscovery:
        known = set(SENSOR_KEYS.keys())
        for key in coordinator.data.keys():
            if key in known or key in IGNORE_KEYS or key.startswith("_"):
                continue
            val = coordinator.data.get(key)
            # Only add dynamic sensor if it has a non-empty value
            if val not in (None, "", []):
                entities.append(ZteRouterDynamicSensor(coordinator, key))

    async_add_entities(entities, True)


class ZteRouterInfoSensor(CoordinatorEntity, SensorEntity):
    def __init__(self, coordinator, key, meta):
        super().__init__(coordinator)
        self._key = key
        self._attr_name = f"ZTE {meta['name']}"
        self._attr_native_unit_of_measurement = meta.get("unit")
        self._attr_unique_id = f"zte_{coordinator.config_entry.entry_id}_{key}"

        # Set device class and state class for appropriate sensors
        if key in ("monthly_rx_bytes", "monthly_tx_bytes", "realtime_tx_bytes", "realtime_rx_bytes"):
            self._attr_device_class = SensorDeviceClass.DATA_SIZE
            self._attr_state_class = SensorStateClass.TOTAL_INCREASING
        elif key in ("realtime_tx_thrpt", "realtime_rx_thrpt"):
            self._attr_device_class = SensorDeviceClass.DATA_RATE
            self._attr_state_class = SensorStateClass.MEASUREMENT
        elif key in ("battery_vol_percent", "battery_pers"):
            self._attr_device_class = SensorDeviceClass.BATTERY
            self._attr_state_class = SensorStateClass.MEASUREMENT
        elif key in ("rssi", "rscp", "lte_rsrp", "sinr", "ecio"):
            self._attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
            self._attr_state_class = SensorStateClass.MEASUREMENT
        elif key in ("realtime_time", "monthly_time"):
            self._attr_device_class = SensorDeviceClass.DURATION
            self._attr_state_class = SensorStateClass.TOTAL_INCREASING

        # Device info to group all sensors
        self._attr_device_info = {
            "identifiers": {(DOMAIN, coordinator.config_entry.entry_id)},
            "name": f"ZTE Router ({coordinator.api._host})",
            "manufacturer": "ZTE",
            "model": self._get_model_from_firmware(),
            "sw_version": coordinator.data.get("cr_version", "Unknown"),
        }

    def _get_model_from_firmware(self):
        """Extract model from firmware version"""
        fw = self.coordinator.data.get("cr_version", "")
        if "MF297D2" in fw:
            return "MF297D2"
        elif "MF" in fw:
            # Extract MF### from firmware string
            import re
            match = re.search(r'MF\d+[A-Z]*\d*', fw)
            if match:
                return match.group(0)
        return "ZTE Router"

    @property
    def native_value(self):
        val = self.coordinator.data.get(self._key)

        # Return None for empty values instead of empty string
        if val in (None, "", []):
            return None

        # Fix RSSI sign (router returns positive, should be negative)
        if self._key == "rssi" and val not in (None, ""):
            try:
                iv = int(val)
                return -iv if iv > 0 else iv
            except Exception:
                return None

        # Convert throughput from bps to Mbps for better readability
        if self._key in ("realtime_tx_thrpt", "realtime_rx_thrpt"):
            try:
                bps = int(val)
                mbps = round(bps / 1_000_000, 2)
                return mbps
            except Exception:
                return None

        # Convert large byte values to GB for readability
        if self._key in ("monthly_rx_bytes", "monthly_tx_bytes", "realtime_tx_bytes", "realtime_rx_bytes"):
            try:
                bytes_val = int(val)
                gb = round(bytes_val / (1024**3), 2)
                return gb
            except Exception:
                return None

        # Convert time in seconds to hours
        if self._key in ("realtime_time", "monthly_time"):
            try:
                seconds = int(val)
                hours = round(seconds / 3600, 1)
                return hours
            except Exception:
                return None

        # For other numeric fields with units, try to convert to number
        if self._attr_native_unit_of_measurement:
            try:
                # Try int first
                return int(val)
            except (ValueError, TypeError):
                try:
                    # Then try float
                    return float(val)
                except (ValueError, TypeError):
                    # If conversion fails, return the string value
                    return val

        return val

    @property
    def native_unit_of_measurement(self):
        # Override units for converted values
        if self._key in ("realtime_tx_thrpt", "realtime_rx_thrpt"):
            return "Mbit/s"  # Home Assistant standard unit
        if self._key in ("monthly_rx_bytes", "monthly_tx_bytes", "realtime_tx_bytes", "realtime_rx_bytes"):
            return "GB"
        if self._key in ("realtime_time", "monthly_time"):
            return "h"
        return self._attr_native_unit_of_measurement

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        # Entity is available if coordinator update was successful
        # Don't check individual value - let it show None/unavailable state instead
        return self.coordinator.last_update_success


class ZteRouterDynamicSensor(CoordinatorEntity, SensorEntity):
    def __init__(self, coordinator, key):
        super().__init__(coordinator)
        self._key = key
        self._attr_name = f"ZTE {key.replace('_', ' ').title()}"
        self._attr_native_unit_of_measurement = guess_unit(key)
        self._attr_unique_id = f"zte_{coordinator.config_entry.entry_id}_dynamic_{key}"

        # Device info to group all sensors
        self._attr_device_info = {
            "identifiers": {(DOMAIN, coordinator.config_entry.entry_id)},
            "name": f"ZTE Router ({coordinator.api._host})",
            "manufacturer": "ZTE",
            "model": "ZTE Router",
            "sw_version": coordinator.data.get("cr_version", "Unknown"),
        }

    @property
    def native_value(self):
        val = self.coordinator.data.get(self._key)

        # Return None for empty values
        if val in (None, "", []):
            return None

        # For numeric fields with units, try to convert to number
        if self._attr_native_unit_of_measurement:
            try:
                return int(val)
            except (ValueError, TypeError):
                try:
                    return float(val)
                except (ValueError, TypeError):
                    return val

        return val

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success
