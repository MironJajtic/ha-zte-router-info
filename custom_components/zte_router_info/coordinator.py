from __future__ import annotations
from datetime import timedelta
import logging
import aiohttp
import async_timeout
import hashlib
import re
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
        self._session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar())
        self._base_get = f"http://{host}/goform/goform_get_cmd_process"
        self._base_set = f"http://{host}/goform/goform_set_cmd_process"
        self._logged_in = False

    async def async_close(self):
        await self._session.close()

    async def _fetch_token(self) -> str | None:
        """Fetch login token from index page."""
        try:
            async with async_timeout.timeout(5):
                async with self._session.get(f"http://{self._host}/") as resp:
                    if resp.status != 200:
                        return None
                    html = await resp.text()
                    # Match 'var token = "abcd1234";' or similar
                    m = re.search(r'var\\s+token\\s*=\\s*"(.*?)"', html)
                    if m:
                        return m.group(1)
        except Exception as e:
            _LOGGER.debug("Token fetch failed: %s", e)
        return None

    async def _login_hashed(self, token: str) -> bool:
        """Login using SHA256(password+token)."""
        hashed_pw = hashlib.sha256((self._password + token).encode()).hexdigest()
        payload = f"isTest=false&goformId=LOGIN&password={hashed_pw}"
        try:
            async with async_timeout.timeout(10):
                async with self._session.post(self._base_set, data=payload) as resp:
                    text = await resp.text()
                    if resp.status == 200 and "OK" in text or "success" in text or "0" in text:
                        self._logged_in = True
                        return True
        except Exception as e:
            _LOGGER.debug("Hashed login failed: %s", e)
        return False

    async def _login_plain(self) -> bool:
        """Fallback: plain password login."""
        payload = f"isTest=false&goformId=LOGIN&password={self._password}"
        try:
            async with async_timeout.timeout(10):
                async with self._session.post(self._base_set, data=payload) as resp:
                    text = await resp.text()
                    if resp.status == 200 and ("OK" in text or "success" in text or "0" in text):
                        self._logged_in = True
                        return True
        except Exception as e:
            _LOGGER.debug("Plain login failed: %s", e)
        return False

    async def login(self) -> bool:
        """Auto-detect login method."""
        # Try hashed first
        token = await self._fetch_token()
        if token:
            if await self._login_hashed(token):
                _LOGGER.debug("ZTE login (hashed) succeeded")
                return True
        # Try plain
        if await self._login_plain():
            _LOGGER.debug("ZTE login (plain) succeeded")
            return True
        _LOGGER.warning("ZTE login failed using both methods")
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
                            # Non-JSON or empty
                            pass
            except Exception as e:
                _LOGGER.debug("Fetch error from %s: %s", url, e)

        # Retry once if all empty
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
