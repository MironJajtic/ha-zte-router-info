from __future__ import annotations
from datetime import timedelta
import logging
import aiohttp
import async_timeout
import hashlib
import json
import asyncio

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
        # Create session without custom timeout first
        self._session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar()
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
        """Visit root page to get initial cookies"""
        try:
            _LOGGER.warning(
                "=== STEP 1: Initial visit to %s ===", self._root_url)
            async with async_timeout.timeout(10):
                async with self._session.get(self._root_url) as resp:
                    text = await resp.text()
                    cookies = self._session.cookie_jar.filter_cookies(
                        self._root_url)
                    _LOGGER.warning("Initial visit: status=%s, cookies=%s, content_length=%d",
                                    resp.status, dict(cookies), len(text))
                    return resp.status == 200
        except Exception as e:
            _LOGGER.error("Initial visit FAILED: %s", e, exc_info=True)
            return False

    async def _get_ld(self) -> str:
        """Fetch LD token"""
        url = f"{self._base_get}?isTest=false&cmd=LD"
        try:
            _LOGGER.warning("=== STEP 2: Fetching LD token from %s ===", url)
            async with async_timeout.timeout(10):
                async with self._session.get(url) as resp:
                    text = await resp.text()
                    _LOGGER.warning(
                        "LD fetch: status=%s, response='%s'", resp.status, text)

                    if resp.status != 200:
                        return ""

                    try:
                        data = json.loads(text)
                        ld = data.get("LD", "") or ""
                        _LOGGER.warning(
                            "LD token parsed: '%s' (length: %d)", ld, len(ld))
                        return str(ld).strip()
                    except Exception as e:
                        _LOGGER.warning(
                            "LD JSON parse failed: %s, treating as empty", e)
                        return ""
        except Exception as e:
            _LOGGER.error("LD fetch FAILED: %s", e, exc_info=True)
            return ""

    async def _post_login(self, payload: str, method_name: str) -> tuple[bool, str]:
        """Post a login payload"""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Origin": self._root_url.rstrip("/"),
            "Referer": self._root_url,
            "X-Requested-With": "XMLHttpRequest",
        }

        try:
            _LOGGER.warning("=== Attempting %s login ===", method_name)
            _LOGGER.warning("POST URL: %s", self._base_set)
            _LOGGER.warning("Payload: %s", payload)
            _LOGGER.warning("Headers: %s", headers)

            async with async_timeout.timeout(15):
                async with self._session.post(self._base_set, data=payload, headers=headers) as resp:
                    text = await resp.text()
                    _LOGGER.warning("%s login response: status=%s, text='%s'",
                                    method_name, resp.status, text)

                    if resp.status != 200:
                        _LOGGER.warning(
                            "%s login: HTTP status not 200", method_name)
                        return False, text

                    # Try JSON parse
                    try:
                        json_data = json.loads(text)
                        _LOGGER.warning(
                            "%s login: parsed JSON = %s", method_name, json_data)

                        result = json_data.get("result")
                        if result is not None:
                            _LOGGER.warning("%s login: result field = %s (type: %s)",
                                            method_name, result, type(result))
                            if str(result) == "0" or result == 0:
                                _LOGGER.warning(
                                    "%s login: SUCCESS via result=0", method_name)
                                return True, text
                            else:
                                _LOGGER.warning(
                                    "%s login: FAILED, result=%s", method_name, result)
                                return False, text

                        # Empty dict might mean success
                        if not json_data or json_data == {}:
                            _LOGGER.warning(
                                "%s login: SUCCESS via empty JSON", method_name)
                            return True, text

                    except json.JSONDecodeError as e:
                        _LOGGER.warning(
                            "%s login: Not JSON - %s", method_name, e)

                    # Check text-based indicators
                    text_lower = text.lower()
                    success_indicators = [
                        '"result":"0"', '"result":0', 'success', '"success"', 'ok', '"ok"']
                    for indicator in success_indicators:
                        if indicator in text_lower:
                            _LOGGER.warning("%s login: SUCCESS via text indicator '%s'",
                                            method_name, indicator)
                            return True, text

                    # Empty/very short response
                    if len(text.strip()) < 5:
                        _LOGGER.warning(
                            "%s login: SUCCESS via empty response", method_name)
                        return True, text

                    _LOGGER.warning(
                        "%s login: FAILED - no success indicator found", method_name)
                    return False, text

        except Exception as e:
            _LOGGER.error("%s login EXCEPTION: %s",
                          method_name, e, exc_info=True)
            return False, str(e)

    async def _login_adaptive(self) -> bool:
        """Try multiple login methods"""
        _LOGGER.warning("========================================")
        _LOGGER.warning("=== STARTING LOGIN PROCESS ===")
        _LOGGER.warning("Host: %s", self._host)
        _LOGGER.warning("Password length: %d", len(self._password))
        _LOGGER.warning("========================================")

        self._logged_in = False
        self._ld_token = ""

        # Step 1: Initial visit
        if not await self._initial_visit():
            _LOGGER.error("Initial visit failed, aborting login")
            return False

        await asyncio.sleep(0.5)

        # Step 2: Get LD
        self._ld_token = await self._get_ld()

        await asyncio.sleep(0.3)

        # Step 3: Try double-hash with LD
        try:
            step1 = hashlib.sha256(self._password.encode()).hexdigest().upper()
            send_hash = hashlib.sha256(
                (step1 + self._ld_token).encode()).hexdigest().upper()

            _LOGGER.warning("=== STEP 3: Double-hash method ===")
            _LOGGER.warning("SHA256(password) = %s...", step1[:20])
            _LOGGER.warning("LD token = '%s'",
                            self._ld_token if self._ld_token else "<empty>")
            _LOGGER.warning("SHA256(hash+LD) = %s...", send_hash[:20])

            payload = f"isTest=false&goformId=LOGIN&password={send_hash}"
            ok, resp = await self._post_login(payload, "DOUBLE-HASH")
            if ok:
                self._logged_in = True
                _LOGGER.warning(
                    "✓✓✓ LOGIN SUCCESSFUL - DOUBLE-HASH METHOD ✓✓✓")
                return True
        except Exception as e:
            _LOGGER.error("Double-hash failed: %s", e, exc_info=True)

        # Step 4: Single hash
        try:
            single_hash = hashlib.sha256(
                self._password.encode()).hexdigest().upper()
            _LOGGER.warning("=== STEP 4: Single-hash method ===")
            _LOGGER.warning("SHA256(password) = %s...", single_hash[:20])

            payload = f"isTest=false&goformId=LOGIN&password={single_hash}"
            ok, resp = await self._post_login(payload, "SINGLE-HASH")
            if ok:
                self._logged_in = True
                _LOGGER.warning(
                    "✓✓✓ LOGIN SUCCESSFUL - SINGLE-HASH METHOD ✓✓✓")
                return True
        except Exception as e:
            _LOGGER.error("Single-hash failed: %s", e, exc_info=True)

        # Step 5: Plain password
        try:
            _LOGGER.warning("=== STEP 5: Plain password method ===")
            _LOGGER.warning("Using plain password: %s",
                            "*" * len(self._password))

            payload = f"isTest=false&goformId=LOGIN&password={self._password}"
            ok, resp = await self._post_login(payload, "PLAIN")
            if ok:
                self._logged_in = True
                _LOGGER.warning(
                    "✓✓✓ LOGIN SUCCESSFUL - PLAIN PASSWORD METHOD ✓✓✓")
                return True
        except Exception as e:
            _LOGGER.error("Plain password failed: %s", e, exc_info=True)

        _LOGGER.error("========================================")
        _LOGGER.error("=== ALL LOGIN METHODS FAILED ===")
        _LOGGER.error("========================================")
        return False

    async def test_and_login(self) -> bool:
        """Test connection and login"""
        try:
            _LOGGER.warning("=== TESTING CONNECTION TO %s ===", self._root_url)
            async with async_timeout.timeout(10):
                async with self._session.get(self._root_url) as resp:
                    _LOGGER.warning("Connection test: status=%s", resp.status)
                    if resp.status not in (200, 302, 303):
                        _LOGGER.error(
                            "Router not reachable, unexpected status=%s", resp.status)
                        return False
        except Exception as e:
            _LOGGER.error("Connection test FAILED: %s", e, exc_info=True)
            return False

        return await self._login_adaptive()

    async def fetch_all(self) -> dict:
        """Fetch all status data"""
        if not self._logged_in:
            _LOGGER.warning("Not logged in, attempting login before fetch")
            ok = await self._login_adaptive()
            if not ok:
                _LOGGER.error("Login failed, returning empty data")
                return {}

        merged: dict = {}
        for i, q in enumerate(STATUS_QUERIES, 1):
            url = f"{self._base_get}?{q}"
            try:
                async with async_timeout.timeout(15):
                    async with self._session.get(url) as resp:
                        if resp.status != 200:
                            _LOGGER.warning("Query %d/%d returned status %s",
                                            i, len(STATUS_QUERIES), resp.status)
                            continue
                        try:
                            chunk = await resp.json(content_type=None)
                            if isinstance(chunk, dict):
                                merged.update(chunk)
                                _LOGGER.debug("Query %d/%d: got %d fields",
                                              i, len(STATUS_QUERIES), len(chunk))
                        except Exception as e:
                            text = await resp.text()
                            _LOGGER.warning(
                                "Query %d/%d non-JSON: %s", i, len(STATUS_QUERIES), text[:200])
            except Exception as e:
                _LOGGER.warning("Query %d/%d error: %s",
                                i, len(STATUS_QUERIES), e)

        if not any(v not in ("", None, []) for v in merged.values()):
            _LOGGER.warning("Data appears empty, attempting re-login")
            self._logged_in = False
            if await self._login_adaptive():
                return await self.fetch_all()

        _LOGGER.info("Fetched %d total data points", len(merged))
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
            _LOGGER.error("Update failed: %s", err, exc_info=True)
            raise UpdateFailed(f"Update failed: {err}") from err
