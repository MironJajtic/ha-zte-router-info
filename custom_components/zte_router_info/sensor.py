from __future__ import annotations
from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN
from .coordinator import ZteCoordinator

SENSOR_KEYS = {
    "network_type": {"name": "Network Type"},
    "rssi": {"name": "RSSI", "unit": "dBm"},
    "lte_rsrp": {"name": "RSRP", "unit": "dBm"},
    "sinr": {"name": "SINR", "unit": "dB"},
    "ZCELLINFO_band": {"name": "LTE Band"},
    "Z_PCI": {"name": "PCI"},
    "cell_id": {"name": "Cell ID"},
    "wan_lte_ca": {"name": "Carrier Aggregation"},
    "signalbar": {"name": "Signal Bars"},
    "network_provider_fullname": {"name": "Network Provider"},
    "lan_ipaddr": {"name": "LAN IP"},
    "realtime_tx_thrpt": {"name": "TX Throughput", "unit": "kbps"},
    "realtime_rx_thrpt": {"name": "RX Throughput", "unit": "kbps"},
    "monthly_rx_bytes": {"name": "Monthly RX Bytes"},
    "monthly_tx_bytes": {"name": "Monthly TX Bytes"},
    "cr_version": {"name": "Firmware Version"},
    "wifi_chip1_ssid1_ssid": {"name": "SSID"},
    "wan_ipaddr": {"name": "WAN IP"},
}

UNIT_MAP = {
    "rssi": "dBm",
    "rsrp": "dBm",
    "sinr": "dB",
    "thrpt": "kbps",
    "bytes": "B",
    "volt": "V",
    "temp": "°C",
}

IGNORE_KEYS = {"isTest", "_", "sms_received_flag_flag", "sts_received_flag_flag"}

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
        self._attr_unique_id = f"zte_{key}"

    @property
    def native_value(self):
        val = self.coordinator.data.get(self._key)
        if self._key == "rssi" and val not in (None, ""):
            try:
                iv = int(val)
                return -iv if iv > 0 else iv
            except Exception:
                pass
        return val

class ZteRouterDynamicSensor(CoordinatorEntity, SensorEntity):
    def __init__(self, coordinator, key):
        super().__init__(coordinator)
        self._key = key
        self._attr_name = f"ZTE {key.replace('_', ' ').title()}"
        self._attr_native_unit_of_measurement = guess_unit(key)
        self._attr_unique_id = f"zte_dynamic_{key}"

    @property
    def native_value(self):
        return self.coordinator.data.get(self._key)
