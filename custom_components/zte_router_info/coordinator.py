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
        # Create session with proper timeout and connector
        timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)
        connector = aiohttp.TCPConnector(force_close=True, limit=10)
        self._session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(),
            timeout=timeout,
            connector=connector
        )
        self._base_get = f"http://{host}/goform/goform_get_cmd_process"
        self._base_set = f"http://{host}/goform/goform_set_cmd_process"
        self._root_url = f"http://{host}/"
        self._logged_in = False
        self._ld_token = ""

    async def async_close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _initial_visit(self):
        """
        Perform an initial GET to the root page to allow the router
        to set initial cookies (SessionID, zsidn, etc.).
        """
        try:
            async with async_timeout.timeout(10):
                async with self._session.get(self._root_url) as resp:
                    await resp.text()  # Read the response to ensure cookies are set
                    _LOGGER.debug("Initial visit status=%s, cookies=%s",
                                  resp.status, self._session.cookie_jar.filter_cookies(self._root_url))
        except Exception as e:
            _LOGGER.debug("Initial visit failed: %s", e)

    async def _get_ld(self) -> str:
        """
        Fetch LD token used in some ZTE firmwares. May be empty.
        """
        url = f"{self._base_get}?isTest=false&cmd=LD"
        try:
            async with async_timeout.timeout(10):
                async with self._session.get(url) as resp:
                    if resp.status != 200:
                        _LOGGER.debug(
                            "LD fetch returned status %s", resp.status)
                        return ""
                    txt = await resp.text()
                    _LOGGER.debug("LD response: %s", txt[:200])
                    try:
                        data = json.loads(txt)
                        ld = data.get("LD", "") or ""
                        return str(ld).strip()
                    except Exception as e:
                        _LOGGER.debug("LD JSON parse failed: %s", e)
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
            async with async_timeout.timeout(15):
                async with self._session.post(self._base_set, data=payload, headers=headers) as resp:
                    text = await resp.text()
                    _LOGGER.debug(
                        "Login POST status=%s, response=%s", resp.status, text[:400])

                    # Check for various success indicators
                    if resp.status == 200:
                        # Try to parse as JSON
                        try:
                            json_data = json.loads(text)
                            # Check for result field
                            result = json_data.get("result")
                            if result == "0" or result == 0:
                                return True, text
                            # Some routers return empty dict on success
                            if not json_data or json_data == {}:
                                return True, text
                        except json.JSONDecodeError:
                            pass

                        # Check for text-based success indicators
                        text_lower = text.lower()
                        if any(s in text_lower for s in ['"result":"0"', '"result":0', 'success', 'ok']):
                            return True, text

                        # If response is very short or empty, might be success
                        if len(text.strip()) < 5:
                            return True, text

                    return False, text
        except Exception as e:
            _LOGGER.error("Login POST exception: %s", e)
            return False, str(e)

    async def _login_adaptive(self) -> bool:
        """
        Attempt login using multiple methods:
        1) Initial visit to get cookies
        2) Fetch LD token
        3) Try double-hash with LD: SHA256(SHA256(password).upper() + LD).upper()
        4) Fallback to single-hash: SHA256(password).upper()
        5) Fallback to plain password
        """
        # Clear any previous login state
        self._logged_in = False
        self._ld_token = ""

        # 1) Initial visit to root to get cookies
        await self._initial_visit()

        # Small delay to let cookies settle
        import asyncio
        await asyncio.sleep(0.5)

        # 2) Get LD token (may be "")
        self._ld_token = await self._get_ld()
        _LOGGER.debug("LD token retrieved: '%s' (length: %d)",
                      self._ld_token if self._ld_token else "<empty>",
                      len(self._ld_token))

        # 3) Try double-hash with LD
        try:
            step1 = hashlib.sha256(self._password.encode()).hexdigest().upper()
            # Double-hash with LD appended (LD may be empty string)
            send_hash = hashlib.sha256(
                (step1 + self._ld_token).encode()).hexdigest().upper()
            _LOGGER.debug(
                "Trying double-hash login (hash: %s...)", send_hash[:16])

            payload = f"isTest=false&goformId=LOGIN&password={send_hash}"
            ok, resp_text = await self._post_login(payload)
            if ok:
                self._logged_in = True
                _LOGGER.info("Login SUCCESS using double-hash method (LD=%s)",
                             "present" if self._ld_token else "empty")
                return True
            _LOGGER.debug(
                "Double-hash login failed, response: %s", resp_text[:200])
        except Exception as e:
            _LOGGER.error("Double-hash computation failed: %s", e)

        # 4) Fallback: single SHA256(password).upper()
        try:
            single_hash = hashlib.sha256(
                self._password.encode()).hexdigest().upper()
            _LOGGER.debug(
                "Trying single-hash login (hash: %s...)", single_hash[:16])

            payload2 = f"isTest=false&goformId=LOGIN&password={single_hash}"
            ok2, t2 = await self._post_login(payload2)
            if ok2:
                self._logged_in = True
                _LOGGER.info("Login SUCCESS using single-hash fallback")
                return True
            _LOGGER.debug("Single-hash login failed, response: %s", t2[:200])
        except Exception as e:
            _LOGGER.debug("Single-hash fallback exception: %s", e)

        # 5) Last resort: try plain password
        _LOGGER.debug("Trying plain password login")
        payload_plain = f"isTest=false&goformId=LOGIN&password={self._password}"
        ok3, t3 = await self._post_login(payload_plain)
        if ok3:
            self._logged_in = True
            _LOGGER.info("Login SUCCESS using plain password fallback")
            return True

        _LOGGER.error("All login attempts FAILED. Double-hash response: %s, Single-hash: %s, Plain: %s",
                      resp_text[:100] if 'resp_text' in locals() else "N/A",
                      t2[:100] if 't2' in locals() else "N/A",
                      t3[:100] if 't3' in locals() else "N/A")
        return False

    async def test_and_login(self) -> bool:
        """Test connection and attempt login"""
        # Quick reachability check
        try:
            async with async_timeout.timeout(10):
                async with self._session.get(self._root_url) as resp:
                    if resp.status not in (200, 302, 303):
                        _LOGGER.error(
                            "Router not reachable, status=%s", resp.status)
                        return False
                    _LOGGER.debug("Router reachable, status=%s", resp.status)
        except Exception as e:
            _LOGGER.error("Router reachability check failed: %s", e)
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
                _LOGGER.error("Not logged in, fetch_all returns empty dict")
                return {}

        merged: dict = {}
        for q in STATUS_QUERIES:
            url = f"{self._base_get}?{q}"
            try:
                async with async_timeout.timeout(15):
                    async with self._session.get(url) as resp:
                        if resp.status != 200:
                            _LOGGER.debug(
                                "Status query returned %s for: %s", resp.status, url[:100])
                            continue
                        try:
                            chunk = await resp.json(content_type=None)
                            if isinstance(chunk, dict):
                                merged.update(chunk)
                        except Exception as e:
                            text = await resp.text()
                            _LOGGER.debug("Non-JSON response for query: %s, text: %s",
                                          url[:100], text[:200])
            except Exception as e:
                _LOGGER.debug("Error fetching %s: %s", url[:100], e)

        # If router returns only empty values, try re-login once
        if not any(v not in ("", None, []) for v in merged.values()):
            _LOGGER.warning("Merged data appears empty, attempting re-login")
            self._logged_in = False
            if await self._login_adaptive():
                # Recursive call but only once
                return await self.fetch_all()

        _LOGGER.debug("Fetched %d data points", len(merged))
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
            data = await self.api.fetch_all()
            if not data:
                _LOGGER.warning("No data received from router")
            return data
        except Exception as err:
            _LOGGER.error("Update failed: %s", err)
            raise UpdateFailed(f"Update failed: {err}") from err
