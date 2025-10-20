from __future__ import annotations
from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN
import async_timeout

class ZteRebootSwitch(CoordinatorEntity, SwitchEntity):
    _attr_name = "ZTE Router Reboot"
    _attr_icon = "mdi:restart"
    _attr_is_on = False

    async def async_turn_on(self, **kwargs):
        api = self.coordinator.api
        await api.login()
        url = f"http://{api._host}/goform/goform_set_cmd_process"
        payload = "isTest=false&goformId=REBOOT_DEVICE"
        async with async_timeout.timeout(10):
            await api._session.post(url, data=payload)
        self._attr_is_on = True
        await self.async_update_ha_state()

    async def async_turn_off(self, **kwargs):
        self._attr_is_on = False
        await self.async_update_ha_state()

async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([ZteRebootSwitch(coordinator)], True)
