from __future__ import annotations
from datetime import timedelta
import logging
import aiohttp
import async_timeout
import hashlib
import json
import asyncio
import time

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
    # Basic info
    "isTest=false&cmd=network_type",
    "isTest=false&cmd=rssi",
    "isTest=false&cmd=rscp",
    "isTest=false&cmd=lte_rsrp",
    "isTest=false&cmd=sinr",
    "isTest=false&cmd=signalbar",
    "isTest=false&cmd=cell_id",
    "isTest=false&cmd=network_provider_fullname",

    # Network info
    "isTest=false&cmd=lan_ipaddr",
    "isTest=false&cmd=wan_ipaddr",
    "isTest=false&cmd=modem_main_state",

    # Bandwidth/throughput
    "isTest=false&cmd=realtime_tx_thrpt",
    "isTest=false&cmd=realtime_rx_thrpt",
    "isTest=false&cmd=monthly_rx_bytes",
    "isTest=false&cmd=monthly_tx_bytes",

    # Device info
    "isTest=false&cmd=cr_version",
    "isTest=false&cmd=wifi_chip1_ssid1_ssid",

    # LTE Advanced info
    "isTest=false&cmd=wan_lte_ca",
    "isTest=false&cmd=ZCELLINFO_band",
    "isTest=false&cmd=lte_ca_pcell_band",
    "isTest=false&cmd=lte_ca_scell_band",
    "isTest=false&cmd=lte_ca_pcell_bandwidth",
    "isTest=false&cmd=lte_ca_scell_bandwidth",
]


class ZteApi:
    def __init__(self, host: str, password: str):
        self._host = host
        self._password = password
        # Create session with persistent cookie jar - this is critical!
        self._session = aiohttp.ClientSession(
            # unsafe=True to allow cookies for IP addresses
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )
        self._base_get = f"http://{host}/goform/goform_get_cmd_process"
        self._base_set = f"http://{host}/goform/goform_set_cmd_process"
        self._root_url = f"http://{host}/"
        self._logged_in = False

    async def async_close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _get_ld_with_timestamp(self) -> str:
        """Fetch LD token with timestamp like browser does"""
        timestamp = int(time.time() * 1000)  # Unix timestamp in milliseconds
        url = f"{self._base_get}?isTest=false&cmd=LD&_={timestamp}"

        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Referer": self._root_url,
            "X-Requested-With": "XMLHttpRequest",
        }

        try:
            _LOGGER.debug("Fetching LD token from: %s", url)
            async with async_timeout.timeout(10):
                async with self._session.get(url, headers=headers) as resp:
                    text = await resp.text()
                    _LOGGER.debug(
                        "LD response: status=%s, text='%s'", resp.status, text)

                    # Check cookies after LD fetch
                    cookies = self._session.cookie_jar.filter_cookies(
                        self._root_url)
                    _LOGGER.debug("Cookies after LD fetch: %s", dict(cookies))

                    if resp.status != 200:
                        _LOGGER.error(
                            "LD fetch failed with status %s", resp.status)
                        return ""

                    try:
                        data = json.loads(text)
                        ld = data.get("LD", "")
                        if ld:
                            _LOGGER.info(
                                "LD token retrieved successfully (length: %d)", len(ld))
                        else:
                            _LOGGER.warning("LD token is empty")
                        return str(ld).strip()
                    except Exception as e:
                        _LOGGER.error("Failed to parse LD JSON: %s", e)
                        return ""
        except Exception as e:
            _LOGGER.error("LD fetch exception: %s", e)
            return ""

    async def _login_with_ld(self, ld_token: str) -> bool:
        """
        Login using double-hash method with LD token.
        Formula: SHA256(SHA256(password).upper() + LD).upper()
        """
        try:
            # Step 1: SHA256(password).upper()
            step1 = hashlib.sha256(self._password.encode()).hexdigest().upper()

            # Step 2: SHA256(step1 + LD).upper()
            combined = step1 + ld_token
            final_hash = hashlib.sha256(combined.encode()).hexdigest().upper()

            _LOGGER.debug("Login hash: SHA256(password)=%s..., LD_len=%d, final=%s...",
                          step1[:16], len(ld_token), final_hash[:16])

            # Prepare payload - NO USERNAME, only password
            payload = f"isTest=false&goformId=LOGIN&password={final_hash}"

            headers = {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Referer": self._root_url,
                "Origin": self._root_url.rstrip("/"),
                "X-Requested-With": "XMLHttpRequest",
            }

            _LOGGER.debug("Posting login to: %s", self._base_set)
            _LOGGER.debug("Login payload: %s", payload)

            # Check cookies before login
            cookies = self._session.cookie_jar.filter_cookies(self._root_url)
            _LOGGER.debug("Cookies before login POST: %s", dict(cookies))

            async with async_timeout.timeout(15):
                async with self._session.post(self._base_set, data=payload, headers=headers) as resp:
                    text = await resp.text()
                    _LOGGER.debug(
                        "Login response: status=%s, text='%s'", resp.status, text)

                    # Check cookies after login
                    cookies_after = self._session.cookie_jar.filter_cookies(
                        self._root_url)
                    _LOGGER.debug("Cookies after login: %s",
                                  dict(cookies_after))

                    if resp.status != 200:
                        _LOGGER.error(
                            "Login failed with HTTP status %s", resp.status)
                        return False

                    try:
                        data = json.loads(text)
                        result = data.get("result")

                        if result == "0" or result == 0:
                            _LOGGER.info("✓ Login successful!")
                            return True
                        else:
                            _LOGGER.error(
                                "Login failed with result='%s'", result)
                            return False
                    except json.JSONDecodeError:
                        _LOGGER.error(
                            "Login response is not valid JSON: %s", text)
                        return False

        except Exception as e:
            _LOGGER.error("Login exception: %s", e)
            return False

    async def test_and_login(self) -> bool:
        """Test connection and perform login sequence"""
        try:
            _LOGGER.debug("=== Starting login sequence ===")

            # Step 1: Visit root page to get initial zsidn cookie
            _LOGGER.debug("Step 1: Visiting root page to establish session")
            async with async_timeout.timeout(10):
                async with self._session.get(self._root_url) as resp:
                    await resp.text()  # Read response to ensure cookies are set
                    _LOGGER.debug("Root page visit: status=%s", resp.status)

                    # Check if we got the zsidn cookie
                    cookies = self._session.cookie_jar.filter_cookies(
                        self._root_url)
                    cookie_dict = dict(cookies)
                    _LOGGER.debug("Cookies after root visit: %s", cookie_dict)

                    if resp.status not in (200, 302, 303):
                        _LOGGER.error(
                            "Router not reachable, status=%s", resp.status)
                        return False

                    # Check if zsidn cookie was set
                    if 'zsidn' not in cookie_dict:
                        _LOGGER.warning(
                            "zsidn cookie not set after root visit")

            # Small delay to let cookies settle
            await asyncio.sleep(0.5)

            # Step 2: Get LD token (this also refreshes the zsidn cookie)
            _LOGGER.debug("Step 2: Fetching LD token")
            ld_token = await self._get_ld_with_timestamp()

            if not ld_token:
                _LOGGER.error("Failed to get LD token")
                return False

            # Small delay before login
            await asyncio.sleep(0.3)

            # Step 3: Login with LD token
            _LOGGER.debug("Step 3: Attempting login")
            success = await self._login_with_ld(ld_token)

            if success:
                self._logged_in = True
                _LOGGER.info("Login sequence completed successfully")

                # Step 4: Wait a bit after login for session to fully establish
                await asyncio.sleep(0.5)

                # Verify cookies are still present
                cookies = self._session.cookie_jar.filter_cookies(
                    self._root_url)
                _LOGGER.debug("Cookies after login: %s", dict(cookies))

                # Step 5: Test a simple query to verify data access
                test_url = f"{self._base_get}?isTest=false&cmd=rssi"
                headers = {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Referer": self._root_url,
                    "X-Requested-With": "XMLHttpRequest",
                }
                try:
                    async with async_timeout.timeout(10):
                        async with self._session.get(test_url, headers=headers) as resp:
                            test_data = await resp.text()
                            _LOGGER.debug(
                                "Post-login test query response: %s", test_data)
                except Exception as e:
                    _LOGGER.debug("Post-login test query failed: %s", e)
            else:
                _LOGGER.error("Login sequence failed")

            return success

        except Exception as e:
            _LOGGER.error("test_and_login exception: %s", e)
            return False

    async def fetch_all(self, retry_count: int = 0) -> dict:
        """Fetch all status data"""
        if not self._logged_in:
            _LOGGER.warning("Not logged in, attempting login")
            ok = await self.test_and_login()
            if not ok:
                _LOGGER.error("Login failed, cannot fetch data")
                return {}

        merged: dict = {}

        # Add proper headers like browser
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Referer": self._root_url,
            "X-Requested-With": "XMLHttpRequest",
        }

        for i, q in enumerate(STATUS_QUERIES, 1):
            url = f"{self._base_get}?{q}"
            try:
                async with async_timeout.timeout(15):
                    async with self._session.get(url, headers=headers) as resp:
                        if resp.status != 200:
                            _LOGGER.warning(
                                "Query %d/%d: HTTP %s", i, len(STATUS_QUERIES), resp.status)
                            continue

                        text = await resp.text()
                        _LOGGER.debug("Query %d/%d response: %s",
                                      i, len(STATUS_QUERIES), text[:200])

                        try:
                            chunk = json.loads(text)
                            if isinstance(chunk, dict):
                                _LOGGER.debug("Query %d/%d: got %d fields",
                                              i, len(STATUS_QUERIES), len(chunk))
                                merged.update(chunk)
                        except Exception as e:
                            _LOGGER.debug("Query %d/%d JSON parse failed: %s",
                                          i, len(STATUS_QUERIES), e)
            except Exception as e:
                _LOGGER.error("Query %d/%d error: %s",
                              i, len(STATUS_QUERIES), e)

        # Check if data is valid
        valid_values = [v for v in merged.values() if v not in ("", None, [])]
        if not valid_values and retry_count < 1:
            _LOGGER.warning(
                "Received empty data, session may have expired - retrying login once")
            self._logged_in = False
            if await self.test_and_login():
                # Try fetching again after re-login, but only once
                return await self.fetch_all(retry_count=retry_count + 1)
            else:
                _LOGGER.error("Re-login failed, returning empty data")
                return {}
        elif not valid_values:
            _LOGGER.error(
                "Still receiving empty data after retry - check router compatibility")
            return merged

        _LOGGER.info("Successfully fetched %d data points", len(merged))
        return merged


class ZteCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, api: ZteApi, config_entry, autodiscovery: bool = False, update_interval: int = 30):
        super().__init__(
            hass,
            _LOGGER,
            name="ZTE Router Info",
            update_interval=timedelta(seconds=update_interval),
        )
        self.api = api
        self.config_entry = config_entry
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
