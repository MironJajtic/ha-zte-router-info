from __future__ import annotations
import voluptuous as vol
from homeassistant import config_entries
from .const import DOMAIN
from .coordinator import ZteApi

class ZteRouterInfoConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            ip = user_input["ip_address"]
            password = user_input["password"]
            autodiscovery = user_input.get("autodiscovery", False)
            update_interval = user_input.get("update_interval", 30)

            try:
                update_interval = int(update_interval)
                if update_interval < 5:
                    update_interval = 5
            except Exception:
                errors["base"] = "invalid_update_interval"
                update_interval = 30

            await self.async_set_unique_id(ip)
            self._abort_if_unique_id_configured()

            api = ZteApi(ip, password)
            ok = await api.test_and_login()
            await api.async_close()

            if ok:
                return self.async_create_entry(
                    title=f"ZTE Router ({ip})",
                    data={
                        "ip_address": ip,
                        "password": password,
                        "autodiscovery": autodiscovery,
                        "update_interval": update_interval,
                    },
                )
            errors["base"] = "cannot_connect"

        data_schema = vol.Schema({
            vol.Required("ip_address", default="192.168.8.1"): str,
            vol.Required("password"): str,
            vol.Optional("autodiscovery", default=False): bool,
            vol.Optional("update_interval", default=30): int,
        })
        return self.async_show_form(step_id="user", data_schema=data_schema, errors=errors)
