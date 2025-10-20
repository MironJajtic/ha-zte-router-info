from __future__ import annotations
from datetime import timedelta
import logging
import aiohttp
import async_timeout
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

_LOGGER = logging.getLogger(__name__)

STATUS_QUERIES = [
    "isTest=false&cmd=network_type,rssi,lte_rsrp,sinr,ZCELLINFO_band,Z_PCI,cell_id,wan_lte_ca&multi_data=1",
    "isTest=false&cmd=modem_main_state,signalbar,network_provider_fullname,lan_ipaddr,realtime_tx_thrpt,realtime_rx_thrpt,monthly_rx_bytes,monthly_tx_bytes,cr_version,wifi_chip1_ssid1_ssid&multi_data=1",
    "isTest=false&cmd=wan_ipaddr",
    "isTest=false&cmd=sms_capacity_info"
]

class ZteApi:
    def __init__(self, host: str, password: str):
        self._host = host
        self._password = password
        self._session = aiohttp.ClientSession()
        self._base_get = f"http://{host}/goform/goform_get_cmd_process"
        self._base_set = f"http://{host}/goform/goform_set_cmd_process"
        self._logged_in = False

    async def async_close(self):
        await self._session.close()

    async def login(self) -> bool:
        try:
            payload = f"isTest=false&goformId=LOGIN&password={self._password}"
            async with async_timeout.timeout(10):
                async with self._session.post(self._base_set, data=payload) as resp:
                    if resp.status == 200:
                        self._logged_in = True
                        return True
        except Exception as e:
            _LOGGER.debug("Login exception: %s", e)
        self._logged_in = False
        return False

    async def test_and_login(self) -> bool:
        try:
            async with async_timeout.timeout(5):
                async with self._session.get(self._base_get) as resp:
                    if resp.status != 200:
                        return False
        except Exception:
            return False
        return await self.login()

    async def fetch_all(self) -> dict:
        if not self._logged_in:
            await self.login()
        data = {}
        for q in STATUS_QUERIES:
            url = f"{self._base_get}?{q}"
            try:
                async with async_timeout.timeout(10):
                    async with self._session.get(url) as resp:
                        if resp.status != 200:
                            continue
                        try:
                            chunk = await resp.json(content_type=None)
                            if isinstance(chunk, dict):
                                data.update(chunk)
                        except Exception:
                            pass
            except Exception as e:
                _LOGGER.debug("Fetch error from %s: %s", url, e)
        if not any(v not in ("", None) for v in data.values()):
            await self.login()
            return await self.fetch_all()
        return data

class ZteCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, api: ZteApi, autodiscovery: bool = False, update_interval: int = 30):
        super().__init__(
            hass,
            _LOGGER,
            name="ZTE Router Info",
            update_interval=timedelta(seconds=update_interval),
        )
        self.api = api
        self.autodiscovery = autodiscovery

    async def _async_update_data(self):
        try:
            return await self.api.fetch_all()
        except Exception as err:
            raise UpdateFailed(f"Update failed: {err}") from err
