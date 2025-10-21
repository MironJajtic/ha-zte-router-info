from __future__ import annotations
from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN
from .coordinator import ZteCoordinator

SENSOR_KEYS = {
    "network_type": {"name": "Network Type"},
    "rssi": {"name": "RSSI", "unit": "dBm"},
    "rscp": {"name": "RSCP", "unit": "dBm"},
    "lte_rsrp": {"name": "LTE RSRP", "unit": "dBm"},
    "sinr": {"name": "SINR", "unit": "dB"},
    "ZCELLINFO_band": {"name": "LTE Band"},
    "cell_id": {"name": "Cell ID"},
    "wan_lte_ca": {"name": "Carrier Aggregation"},
    "signalbar": {"name": "Signal Bars"},
    "network_provider_fullname": {"name": "Network Provider"},
    "lan_ipaddr": {"name": "LAN IP"},
    "wan_ipaddr": {"name": "WAN IP"},
    "modem_main_state": {"name": "Modem State"},
    "realtime_tx_thrpt": {"name": "TX Throughput", "unit": "bps"},
    "realtime_rx_thrpt": {"name": "RX Throughput", "unit": "bps"},
    "monthly_rx_bytes": {"name": "Monthly RX Bytes", "unit": "B"},
    "monthly_tx_bytes": {"name": "Monthly TX Bytes", "unit": "B"},
    "cr_version": {"name": "Firmware Version"},
    "wifi_chip1_ssid1_ssid": {"name": "SSID"},
    "lte_ca_pcell_band": {"name": "CA Primary Band"},
    "lte_ca_scell_band": {"name": "CA Secondary Band"},
    "lte_ca_pcell_bandwidth": {"name": "CA Primary Bandwidth", "unit": "MHz"},
    "lte_ca_scell_bandwidth": {"name": "CA Secondary Bandwidth", "unit": "MHz"},
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

    for key, meta in SENSOR_KEYS.items():
        if key in coordinator.data:
            entities.append(ZteRouterInfoSensor(coordinator, key, meta))

    if coordinator.autodiscovery:
        known = set(SENSOR_KEYS.keys())
        for key in coordinator.data.keys():
            if key in known or key in IGNORE_KEYS or key.startswith("_"):
                continue
            entities.append(ZteRouterDynamicSensor(coordinator, key))

    async_add_entities(entities, True)


class ZteRouterInfoSensor(CoordinatorEntity, SensorEntity):
    def __init__(self, coordinator, key, meta):
        super().__init__(coordinator)
        self._key = key
        self._attr_name = f"ZTE {meta['name']}"
        self._attr_native_unit_of_measurement = meta.get("unit")
        self._attr_unique_id = f"zte_{coordinator.config_entry.entry_id}_{key}"

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

        # Fix RSSI sign (router returns positive, should be negative)
        if self._key == "rssi" and val not in (None, ""):
            try:
                iv = int(val)
                return -iv if iv > 0 else iv
            except Exception:
                pass

        # Convert throughput from bps to Mbps for better readability
        if self._key in ("realtime_tx_thrpt", "realtime_rx_thrpt") and val not in (None, ""):
            try:
                bps = int(val)
                mbps = round(bps / 1_000_000, 2)
                return mbps
            except Exception:
                pass

        return val

    @property
    def native_unit_of_measurement(self):
        # Override unit for throughput
        if self._key in ("realtime_tx_thrpt", "realtime_rx_thrpt"):
            return "Mbps"
        return self._attr_native_unit_of_measurement


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
        return self.coordinator.data.get(self._key)
