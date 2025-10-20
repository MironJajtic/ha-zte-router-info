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
        # keep cookies across requests
        self._session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar())
        self._base_get = f"http://{host}/goform/goform_get_cmd_process"
        self._base_set = f"http://{host}/goform/goform_set_cmd_process"
        self._root_url = f"http://{host}/"
        self._logged_in = False

    async def async_close(self):
        await self._session.close()

    async def _initial_visit(self):
        """
        Perform an initial GET to the root page to allow the router
        to set initial cookies (SessionID, zsidn, etc.).
        """
        try:
            async with async_timeout.timeout(6):
                async with self._session.get(self._root_url) as resp:
                    # We don't need the content, just the cookies
                    _LOGGER.debug("Visited root page, status=%s", resp.status)
        except Exception as e:
            _LOGGER.debug("Initial visit failed: %s", e)

    async def _get_ld(self) -> str:
        """
        Fetch LD token used in some ZTE firmwares. May be empty.
        """
        url = f"{self._base_get}?isTest=false&cmd=LD"
        try:
            async with async_timeout.timeout(6):
                async with self._session.get(url) as resp:
                    if resp.status != 200:
                        return ""
                    txt = await resp.text()
                    try:
                        data = json.loads(txt)
                        ld = data.get("LD", "") or ""
                        return str(ld).strip()
                    except Exception:
                        return ""
        except Exception as e:
            _LOGGER.debug("Failed to fetch LD: %s", e)
            return ""

    async def _post_login(self, payload: str) -> tuple[bool, str]:
        """
        Post a login payload and return (success, raw_text)
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Origin": self._root_url.rstrip("/"),
            "Referer": self._root_url,
            "X-Requested-With": "XMLHttpRequest",
        }
        try:
            async with async_timeout.timeout(10):
                async with self._session.post(self._base_set, data=payload, headers=headers) as resp:
                    text = await resp.text()
                    _LOGGER.debug(
                        "Login POST status=%s, response=%s", resp.status, text[:400])
                    # JSON-formatted result commonly contains result:"0" on success
                    if resp.status == 200:
                        if "\"0\"" in text or '"result":0' in text or "OK" in text or "success" in text:
                            return True, text
                    return False, text
        except Exception as e:
            _LOGGER.debug("Login POST exception: %s", e)
            return False, str(e)

    async def _login_adaptive(self) -> bool:
        """
        Attempt login using the exact sequence observed in the web UI:
        1) initial visit to populate cookies
        2) fetch LD token (may be empty)
        3) compute SHA256(SHA256(password).upper() + LD).upper()
           (if LD empty, this becomes SHA256(SHA256(password).upper()).upper())
        4) POST with proper headers
        Falls back to single-sha and plain as last resorts.
        """
        # 1) initial visit to root to get cookies similar to browser
        await self._initial_visit()

        # 2) get LD (may be "")
        ld = await self._get_ld()
        _LOGGER.debug("LD token (may be empty): '%s'", ld)

        # 3) compute hash exactly like the UI (double-hash pattern)
        try:
            step1 = hashlib.sha256(self._password.encode()).hexdigest().upper()
            # double-hash with LD appended (LD may be "")
            send_hash = hashlib.sha256(
                (step1 + ld).encode()).hexdigest().upper()
        except Exception as e:
            _LOGGER.error("Hash computation failed: %s", e)
            return False

        payload = f"isTest=false&goformId=LOGIN&password={send_hash}"
        ok, resp_text = await self._post_login(payload)
        if ok:
            self._logged_in = True
            _LOGGER.debug(
                "Login success using double-hash (LD present=%s)", bool(ld))
            return True

        _LOGGER.debug("Double-hash login failed, trying fallback single-sha")

        # Fallback single SHA256(password).upper()
        try:
            single_hash = hashlib.sha256(
                self._password.encode()).hexdigest().upper()
            payload2 = f"isTest=false&goformId=LOGIN&password={single_hash}"
            ok2, t2 = await self._post_login(payload2)
            if ok2:
                self._logged_in = True
                _LOGGER.debug("Login success using single-sha fallback")
                return True
        except Exception as e:
            _LOGGER.debug("Single-sha fallback exception: %s", e)

        # Last resort: try plain password
        payload_plain = f"isTest=false&goformId=LOGIN&password={self._password}"
        ok3, t3 = await self._post_login(payload_plain)
        if ok3:
            self._logged_in = True
            _LOGGER.debug("Login success using plain password fallback")
            return True

        _LOGGER.warning("All login attempts failed. Last responses: double='%s' single='%s' plain='%s'",
                        resp_text[:200], t2[:200] if 't2' in locals() else "", t3[:200] if 't3' in locals() else "")
        return False

    async def test_and_login(self) -> bool:
        # quick reachability check
        try:
            async with async_timeout.timeout(5):
                async with self._session.get(self._base_get) as resp:
                    if resp.status != 200:
                        _LOGGER.debug(
                            "Base GET not reachable, status=%s", resp.status)
                        return False
        except Exception:
            _LOGGER.debug("Base GET reachability check failed")
            return False

        return await self._login_adaptive()

    async def fetch_all(self) -> dict:
        """
        Fetch all configured status queries and merge results.
        Requires login (will attempt adaptive login if not logged).
        """
        if not self._logged_in:
            ok = await self._login_adaptive()
            if not ok:
                _LOGGER.debug("Not logged in, fetch_all returns empty dict")
                return {}

        merged: dict = {}
        for q in STATUS_QUERIES:
            url = f"{self._base_get}?{q}"
            try:
                async with async_timeout.timeout(10):
                    async with self._session.get(url) as resp:
                        if resp.status != 200:
                            _LOGGER.debug(
                                "Status query %s returned %s", url, resp.status)
                            continue
                        try:
                            chunk = await resp.json(content_type=None)
                            if isinstance(chunk, dict):
                                merged.update(chunk)
                        except Exception:
                            text = await resp.text()
                            _LOGGER.debug(
                                "Non-JSON response for %s: %s", url, text[:200])
            except Exception as e:
                _LOGGER.debug("Error fetching %s: %s", url, e)

        # If router returns only empty values, try re-login once
        if not any(v not in ("", None) for v in merged.values()):
            _LOGGER.debug(
                "Merged data empty, retrying: clearing login and reattempting")
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
