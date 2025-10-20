
from __future__ import annotations
from datetime import timedelta
import logging
import aiohttp
import async_timeout
import hashlib
import json

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

_LOGGER = logging.getLogger(__name__)

# Primary signal/CA metrics endpoint (from user's router)
PRIMARY_CMD = (
    "isTest=false&cmd="
    "network_type,rssi,rscp,lte_rsrp,Z5g_snr,Z5g_rsrp,ZCELLINFO_band,Z5g_dlEarfcn,"
    "lte_ca_pcell_arfcn,lte_ca_pcell_band,lte_ca_scell_band,lte_ca_pcell_bandwidth,"
    "lte_ca_scell_info,lte_ca_scell_bandwidth,wan_lte_ca,Z_PCI,Z5g_CELL_ID,Z5g_SINR,"
    "cell_id,wan_lte_ca,lte_ca_pcell_band,lte_ca_pcell_bandwidth,lte_ca_scell_band,"
    "lte_ca_scell_bandwidth,lte_ca_pcell_arfcn,lte_ca_scell_arfcn,lte_multi_ca_scell_info,"
    "ZCELLINFO_band,Z5g_PCI,Z5g_CELLINFO_band,Z5g_CELL_ID,sinr,ecio,Z_dl_earfcn,Z5g_dlEarfcn"
    "&multi_data=1"
)

# Some general status pages that often exist on ZTE firmwares
STATUS_QUERIES = [
    PRIMARY_CMD,
    "isTest=false&cmd=modem_main_state,signalbar,network_provider_fullname,lan_ipaddr,"
    "realtime_tx_thrpt,realtime_rx_thrpt,monthly_rx_bytes,monthly_tx_bytes,cr_version,"
    "wifi_chip1_ssid1_ssid&multi_data=1",
    "isTest=false&cmd=wan_ipaddr",
    "isTest=false&cmd=sms_capacity_info",
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

    async def _get_ld(self) -> str:
        """Fetch LD challenge token (may be empty on some firmwares)."""
        url = f"{self._base_get}?isTest=false&cmd=LD"
        try:
            async with async_timeout.timeout(8):
                async with self._session.get(url) as resp:
                    if resp.status != 200:
                        return ""
                    text = await resp.text()
                    try:
                        data = json.loads(text)
                        ld = data.get("LD", "") or ""
                        return str(ld).strip()
                    except Exception:
                        return ""
        except Exception as e:
            _LOGGER.debug("Failed to fetch LD token: %s", e)
            return ""

    async def _login_adaptive(self) -> bool:
        """Login supporting MF297D2-style LD hashing and plain SHA256(password)."""
        # Compute base hash of password
        hash1 = hashlib.sha256(self._password.encode()).hexdigest().upper()
        ld = await self._get_ld()

        # If LD present, do double-hash; otherwise try single SHA256
        if ld:
            to_send = hashlib.sha256((hash1 + ld).encode()).hexdigest().upper()
        else:
            to_send = hash1

        payload = f"isTest=false&goformId=LOGIN&password={to_send}"
        try:
            async with async_timeout.timeout(10):
                async with self._session.post(self._base_set, data=payload) as resp:
                    text = await resp.text()
                    if resp.status == 200 and any(x in text for x in ('"0"', 'OK', 'success')):
                        self._logged_in = True
                        _LOGGER.debug("ZTE login succeeded (LD=%s)", "present" if ld else "empty")
                        return True
                    _LOGGER.debug("ZTE login response: %s", text)
        except Exception as e:
            _LOGGER.debug("Login POST failed: %s", e)

        # Final fallback: send plain password (a few odd firmwares accept this)
        payload_plain = f"isTest=false&goformId=LOGIN&password={self._password}"
        try:
            async with async_timeout.timeout(10):
                async with self._session.post(self._base_set, data=payload_plain) as resp:
                    text = await resp.text()
                    if resp.status == 200 and any(x in text for x in ('"0"', 'OK', 'success')):
                        self._logged_in = True
                        _LOGGER.debug("ZTE login succeeded (plain password fallback)")
                        return True
                    _LOGGER.debug("ZTE login plain response: %s", text)
        except Exception as e:
            _LOGGER.debug("Plain login POST failed: %s", e)

        return False

    async def test_and_login(self) -> bool:
        # Touch the GET endpoint to verify router is reachable
        try:
            async with async_timeout.timeout(5):
                async with self._session.get(self._base_get) as resp:
                    if resp.status != 200:
                        return False
        except Exception:
            return False
        return await self._login_adaptive()

    async def fetch_all(self) -> dict:
        """Fetch and merge several status dicts. Requires prior successful login."""
        if not self._logged_in:
            ok = await self._login_adaptive()
            if not ok:
                return {}

        merged: dict = {}
        for q in STATUS_QUERIES:
            url = f"{self._base_get}?{q}"
            try:
                async with async_timeout.timeout(10):
                    async with self._session.get(url) as resp:
                        if resp.status != 200:
                            continue
                        # Some endpoints return JSON, others plain text
                        try:
                            chunk = await resp.json(content_type=None)
                            if isinstance(chunk, dict):
                                merged.update(chunk)
                        except Exception:
                            text = await resp.text()
                            # best-effort: ignore non-JSON
                            _LOGGER.debug("Non-JSON from %s: %s", url, text[:120])
            except Exception as e:
                _LOGGER.debug("Fetch error from %s: %s", url, e)

        # If all values are empty, retry once after re-login
        if not any(v not in ("", None) for v in merged.values()):
            _LOGGER.debug("All values empty, retrying after re-login")
            self._logged_in = False
            if await self._login_adaptive():
                return await self.fetch_all()
        return merged


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
