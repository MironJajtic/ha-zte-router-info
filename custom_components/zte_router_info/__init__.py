from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, PLATFORMS
from .coordinator import ZteApi, ZteCoordinator


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ip = entry.data["ip_address"]
    password = entry.data["password"]
    username = entry.data.get("username", "admin")  # Default to "admin"
    autodiscovery = entry.data.get("autodiscovery", False)
    update_interval = entry.data.get("update_interval", 30)

    api = ZteApi(ip, password, username)
    coordinator = ZteCoordinator(
        hass, api, autodiscovery=autodiscovery, update_interval=update_interval)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
        if coordinator:
            await coordinator.api.async_close()
    return unload_ok
