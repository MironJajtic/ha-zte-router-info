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
    # Main status query (similar to what web UI uses)
    "isTest=false&cmd=modem_main_state,signalbar,network_type,network_provider_fullname,"
    "ppp_status,simcard_roam,lan_ipaddr,wifi_onoff_state,wifi_chip1_ssid1_ssid,"
    "realtime_tx_bytes,realtime_rx_bytes,realtime_time,realtime_tx_thrpt,realtime_rx_thrpt,"
    "monthly_rx_bytes,monthly_tx_bytes,monthly_time,wan_lte_ca,sms_unread_num,"
    "battery_charging,battery_vol_percent,battery_value,battery_pers,"
    "wifi_chip1_ssid1_access_sta_num,wifi_chip2_ssid1_access_sta_num&multi_data=1",
    
    # LTE signal details (with multi_data)
    "isTest=false&cmd=network_type,rssi,rscp,lte_rsrp,ZCELLINFO_band,"
    "lte_ca_pcell_arfcn,lte_ca_pcell_band,lte_ca_scell_band,"
    "lte_ca_pcell_bandwidth,lte_ca_scell_info,lte_ca_scell_bandwidth,"
    "wan_lte_ca,Z_PCI,cell_id,sinr,ecio,Z_dl_earfcn,"
    "lte_ca_pcell_arfcn,lte_ca_scell_arfcn&multi_data=1",
    
    # Device info
    "isTest=false&cmd=cr_version,wan_ipaddr&multi_data=1",
    
    # SMS info
    "isTest=false&cmd=sms_capacity_info",
]


class ZteApi:
    def __init__(self, host: str, password: str):
        self._host = host
        self._password = password
        # Create session with persistent cookie jar - this is critical!
        self._session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True)  # unsafe=True to allow cookies for IP addresses
        )
        self._base_get = f"http://{host}/goform/goform_get_cmd_process"
        self._base_set = f"http://{host}/goform/goform_set_cmd_process"
        self._root_url = f"http://{host}/"
        self._logged_in = False
        self._login_time = 0  # Track when we last logged in

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
                    _LOGGER.debug("LD response: status=%s, text='%s'", resp.status, text)
                    
                    # Check cookies after LD fetch
                    cookies = self._session.cookie_jar.filter_cookies(self._root_url)
                    _LOGGER.debug("Cookies after LD fetch: %s", dict(cookies))
                    
                    if resp.status != 200:
                        _LOGGER.error("LD fetch failed with status %s", resp.status)
                        return ""
                    
                    try:
                        data = json.loads(text)
                        ld = data.get("LD", "")
                        if ld:
                            _LOGGER.info("LD token retrieved successfully (length: %d)", len(ld))
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
        """Login using double-hash method with LD token"""
        try:
            step1 = hashlib.sha256(self._password.encode()).hexdigest().upper()
            combined = step1 + ld_token
            final_hash = hashlib.sha256(combined.encode()).hexdigest().upper()
            
            payload = f"isTest=false&goformId=LOGIN&password={final_hash}"
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Referer": self._root_url,
                "Origin": self._root_url.rstrip("/"),
                "X-Requested-With": "XMLHttpRequest",
            }
            
            async with async_timeout.timeout(15):
                async with self._session.post(self._base_set, data=payload, headers=headers) as resp:
                    text = await resp.text()
                    
                    if resp.status != 200:
                        _LOGGER.error("Login failed with HTTP status %s", resp.status)
                        return False
                    
                    try:
                        data = json.loads(text)
                        result = data.get("result")
                        
                        if result == "0" or result == 0:
                            return True
                        else:
                            _LOGGER.error("Login failed with result='%s'", result)
                            return False
                    except json.JSONDecodeError:
                        _LOGGER.error("Login response is not valid JSON: %s", text)
                        return False
                        
        except Exception as e:
            _LOGGER.error("Login exception: %s", e)
            return False

    async def test_and_login(self) -> bool:
        """Test connection and perform login sequence"""
        try:
            # Step 1: Visit root page
            async with async_timeout.timeout(10):
                async with self._session.get(self._root_url) as resp:
                    await resp.text()
                    
                    if resp.status not in (200, 302, 303):
                        _LOGGER.error("Router not reachable, status=%s", resp.status)
                        return False
            
            await asyncio.sleep(0.5)
            
            # Step 2: Get LD token
            ld_token = await self._get_ld_with_timestamp()
            
            if not ld_token:
                _LOGGER.error("Failed to get LD token")
                return False
            
            await asyncio.sleep(0.3)
            
            # Step 3: Login
            success = await self._login_with_ld(ld_token)
            
            if success:
                self._logged_in = True
                self._login_time = time.time()
                _LOGGER.info("Login successful")
                await asyncio.sleep(0.5)
            else:
                _LOGGER.error("Login failed")
            
            return success
            
        except Exception as e:
            _LOGGER.error("Login sequence exception: %s", e)
            return False

    async def fetch_all(self, retry_count: int = 0) -> dict:
        """Fetch all status data"""
        # Check if session might have expired (after 5 minutes, force re-login)
        if self._logged_in and time.time() - self._login_time > 300:
            _LOGGER.info("Session expired, re-authenticating")
            self._logged_in = False
        
        if not self._logged_in:
            ok = await self.test_and_login()
            if not ok:
                _LOGGER.error("Authentication failed")
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
                            _LOGGER.warning("Query %d/%d failed: HTTP %s", i, len(STATUS_QUERIES), resp.status)
                            continue
                        
                        text = await resp.text()
                        
                        try:
                            chunk = json.loads(text)
                            if isinstance(chunk, dict):
                                # Filter out empty values to merge only actual data
                                non_empty = {k: v for k, v in chunk.items() if v not in ("", None, [])}
                                merged.update(non_empty)
                        except Exception as e:
                            _LOGGER.warning("Query %d/%d JSON parse failed: %s", i, len(STATUS_QUERIES), e)
            except Exception as e:
                _LOGGER.error("Query %d/%d error: %s", i, len(STATUS_QUERIES), e)

        # Check if data is valid
        valid_values = [v for v in merged.values() if v not in ("", None, [])]
        if not valid_values and retry_count < 1:
            _LOGGER.warning("No data received, retrying with fresh login")
            self._logged_in = False
            if await self.test_and_login():
                return await self.fetch_all(retry_count=retry_count + 1)
            else:
                _LOGGER.error("Re-authentication failed")
                return {}
        elif len(valid_values) < 10 and retry_count < 1:
            _LOGGER.warning("Insufficient data (%d fields), session may be expired, re-authenticating", len(valid_values))
            self._logged_in = False
            if await self.test_and_login():
                return await self.fetch_all(retry_count=retry_count + 1)

        _LOGGER.info("Fetched %d data points", len(merged))
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
            return data
        except Exception as err:
            _LOGGER.error("Update failed: %s", err)
            raise UpdateFailed(f"Update failed: {err}") from err