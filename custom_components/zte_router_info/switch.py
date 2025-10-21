from __future__ import annotations
from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN
import async_timeout


class ZteRebootSwitch(CoordinatorEntity, SwitchEntity):
    def __init__(self, coordinator):
        super().__init__(coordinator)
        self._attr_name = "ZTE Router Reboot"
        self._attr_icon = "mdi:restart"
        self._attr_is_on = False
        self._attr_unique_id = f"zte_{coordinator.config_entry.entry_id}_reboot"

        # Device info to group with sensors
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
            import re
            match = re.search(r'MF\d+[A-Z]*\d*', fw)
            if match:
                return match.group(0)
        return "ZTE Router"

    async def async_turn_on(self, **kwargs):
        api = self.coordinator.api
        url = f"http://{api._host}/goform/goform_set_cmd_process"
        payload = "isTest=false&goformId=REBOOT_DEVICE"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": f"http://{api._host}/",
        }
        try:
            async with async_timeout.timeout(10):
                async with api._session.post(url, data=payload, headers=headers) as resp:
                    if resp.status == 200:
                        self._attr_is_on = True
                        await self.async_update_ha_state()
        except Exception as e:
            import logging
            _LOGGER = logging.getLogger(__name__)
            _LOGGER.error("Reboot failed: %s", e)

    async def async_turn_off(self, **kwargs):
        self._attr_is_on = False
        await self.async_update_ha_state()


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([ZteRebootSwitch(coordinator)], True)
