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
    def __init__(self, host: str, password: str, username: str = "admin"):
        self._host = host
        self._password = password
        self._username = username
        self._session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar())
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
            _LOGGER.debug("Initial visit to %s", self._root_url)
            async with async_timeout.timeout(10):
                async with self._session.get(self._root_url) as resp:
                    await resp.text()
                    _LOGGER.debug("Initial visit: status=%s", resp.status)
                    return resp.status == 200
        except Exception as e:
            _LOGGER.error("Initial visit failed: %s", e)
            return False

    async def _get_ld(self) -> str:
        """Fetch LD token"""
        url = f"{self._base_get}?isTest=false&cmd=LD"
        try:
            async with async_timeout.timeout(10):
                async with self._session.get(url) as resp:
                    text = await resp.text()
                    _LOGGER.debug(
                        "LD fetch: status=%s, response='%s'", resp.status, text)

                    if resp.status != 200:
                        return ""

                    try:
                        data = json.loads(text)
                        ld = data.get("LD", "") or ""
                        _LOGGER.debug("LD token: '%s'",
                                      ld if ld else "<empty>")
                        return str(ld).strip()
                    except Exception:
                        return ""
        except Exception as e:
            _LOGGER.debug("LD fetch failed: %s", e)
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
            _LOGGER.debug("Attempting %s login", method_name)
            _LOGGER.debug("Payload: %s", payload.replace(
                self._password, "***"))

            async with async_timeout.timeout(15):
                async with self._session.post(self._base_set, data=payload, headers=headers) as resp:
                    text = await resp.text()
                    _LOGGER.debug("%s response: status=%s, text='%s'",
                                  method_name, resp.status, text)

                    if resp.status != 200:
                        return False, text

                    # Parse JSON response
                    try:
                        json_data = json.loads(text)
                        result = json_data.get("result")

                        if result is not None:
                            if str(result) == "0" or result == 0:
                                _LOGGER.info("%s login SUCCESS", method_name)
                                return True, text
                            else:
                                _LOGGER.debug(
                                    "%s login FAILED, result=%s", method_name, result)
                                return False, text

                        # Empty dict might mean success
                        if not json_data or json_data == {}:
                            _LOGGER.info(
                                "%s login SUCCESS (empty response)", method_name)
                            return True, text

                    except json.JSONDecodeError:
                        pass

                    # Check text-based success indicators
                    text_lower = text.lower()
                    success_indicators = ['"result":"0"',
                                          '"result":0', 'success', 'ok']
                    for indicator in success_indicators:
                        if indicator in text_lower:
                            _LOGGER.info(
                                "%s login SUCCESS (text indicator)", method_name)
                            return True, text

                    # Very short/empty response might be success
                    if len(text.strip()) < 5:
                        _LOGGER.info("%s login SUCCESS (empty)", method_name)
                        return True, text

                    return False, text

        except Exception as e:
            _LOGGER.error("%s login exception: %s", method_name, e)
            return False, str(e)

    async def _login_adaptive(self) -> bool:
        """Try multiple login methods with username"""
        _LOGGER.debug(
            "Starting login process for host=%s, username=%s", self._host, self._username)

        self._logged_in = False
        self._ld_token = ""

        # Step 1: Initial visit
        if not await self._initial_visit():
            _LOGGER.error("Initial visit failed")
            return False

        await asyncio.sleep(0.5)

        # Step 2: Get LD token
        self._ld_token = await self._get_ld()
        await asyncio.sleep(0.3)

        # Step 3: Double-hash with LD + username
        try:
            step1 = hashlib.sha256(self._password.encode()).hexdigest().upper()
            send_hash = hashlib.sha256(
                (step1 + self._ld_token).encode()).hexdigest().upper()

            _LOGGER.debug("Trying double-hash with username")
            payload = f"isTest=false&goformId=LOGIN&username={self._username}&password={send_hash}"
            ok, _ = await self._post_login(payload, "DOUBLE-HASH+USERNAME")
            if ok:
                self._logged_in = True
                return True
        except Exception as e:
            _LOGGER.debug("Double-hash with username failed: %s", e)

        # Step 4: Single hash + username
        try:
            single_hash = hashlib.sha256(
                self._password.encode()).hexdigest().upper()
            _LOGGER.debug("Trying single-hash with username")

            payload = f"isTest=false&goformId=LOGIN&username={self._username}&password={single_hash}"
            ok, _ = await self._post_login(payload, "SINGLE-HASH+USERNAME")
            if ok:
                self._logged_in = True
                return True
        except Exception as e:
            _LOGGER.debug("Single-hash with username failed: %s", e)

        # Step 5: Plain password + username
        try:
            _LOGGER.debug("Trying plain password with username")
            payload = f"isTest=false&goformId=LOGIN&username={self._username}&password={self._password}"
            ok, _ = await self._post_login(payload, "PLAIN+USERNAME")
            if ok:
                self._logged_in = True
                return True
        except Exception as e:
            _LOGGER.debug("Plain with username failed: %s", e)

        # Step 6: Try without username (backwards compatibility)
        try:
            single_hash = hashlib.sha256(
                self._password.encode()).hexdigest().upper()
            _LOGGER.debug("Trying single-hash WITHOUT username (fallback)")

            payload = f"isTest=false&goformId=LOGIN&password={single_hash}"
            ok, _ = await self._post_login(payload, "SINGLE-HASH-NO-USER")
            if ok:
                self._logged_in = True
                return True
        except Exception as e:
            _LOGGER.debug("Fallback without username failed: %s", e)

        _LOGGER.error("All login methods failed")
        return False

    async def test_and_login(self) -> bool:
        """Test connection and login"""
        try:
            async with async_timeout.timeout(10):
                async with self._session.get(self._root_url) as resp:
                    if resp.status not in (200, 302, 303):
                        _LOGGER.error(
                            "Router not reachable, status=%s", resp.status)
                        return False
        except Exception as e:
            _LOGGER.error("Connection test failed: %s", e)
            return False

        return await self._login_adaptive()

    async def fetch_all(self) -> dict:
        """Fetch all status data"""
        if not self._logged_in:
            ok = await self._login_adaptive()
            if not ok:
                _LOGGER.error("Not logged in, cannot fetch data")
                return {}

        merged: dict = {}
        for i, q in enumerate(STATUS_QUERIES, 1):
            url = f"{self._base_get}?{q}"
            try:
                async with async_timeout.timeout(15):
                    async with self._session.get(url) as resp:
                        if resp.status != 200:
                            _LOGGER.debug("Query %d/%d: status %s",
                                          i, len(STATUS_QUERIES), resp.status)
                            continue
                        try:
                            chunk = await resp.json(content_type=None)
                            if isinstance(chunk, dict):
                                merged.update(chunk)
                                _LOGGER.debug(
                                    "Query %d/%d: got %d fields", i, len(STATUS_QUERIES), len(chunk))
                        except Exception:
                            text = await resp.text()
                            _LOGGER.debug("Query %d/%d non-JSON: %s",
                                          i, len(STATUS_QUERIES), text[:100])
            except Exception as e:
                _LOGGER.debug("Query %d/%d error: %s",
                              i, len(STATUS_QUERIES), e)

        # Retry if data is empty
        if not any(v not in ("", None, []) for v in merged.values()):
            _LOGGER.warning("Data appears empty, retrying login")
            self._logged_in = False
            if await self._login_adaptive():
                return await self.fetch_all()

        _LOGGER.info("Fetched %d data points", len(merged))
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
