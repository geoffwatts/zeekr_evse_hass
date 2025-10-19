"""Data coordinator for Zeekr charger integration."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

# Import locally to avoid import issues during config flow
# from .lib import ZeekrBleClient
from .const import DEFAULT_SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)



class ZeekrChargerCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Data coordinator for Zeekr charger."""

    def __init__(
        self,
        hass: HomeAssistant,
        client,  # ZeekrBleClient
        update_interval: timedelta = timedelta(seconds=DEFAULT_SCAN_INTERVAL),
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name="Zeekr Charger",
            update_interval=update_interval,
        )
        self.client = client
        self._heartbeat_task: asyncio.Task | None = None
        self._static_data_fetched = False
        self._last_connection_state = False

    def reset_static_data_flag(self) -> None:
        """Reset the static data flag when reconnecting."""
        self._static_data_fetched = False
    
    async def force_refresh_static_data(self) -> None:
        """Force refresh all static data including WiFi configuration."""
        self._static_data_fetched = False
        await self.async_request_refresh()

    async def _async_update_data(self) -> dict[str, Any]:
        """Update data from the charger."""
        if not self.client.is_connected:
            # Don't raise UpdateFailed - let the coordinator retry and trigger reconnection
            # Return last known data or empty data to avoid breaking the integration
            return self.data or {
                "connected": False,
                "heartbeat_state": {},
                "heartbeat_stats": {"total_heartbeats": 0},
                "telemetry": {},
                "current_config": {},
                "power_status": {},
                "basic_info": {},
                "protection_info": {},
                "wifi_config": {},
                "wifi_status": {},
            }

        try:
            
            # Check if we just reconnected (connection state changed from False to True)
            current_connection_state = self.client.is_connected
            if current_connection_state and not self._last_connection_state:
                self._static_data_fetched = False
            self._last_connection_state = current_connection_state
            
            # Fetch static data only once when we first connect
            if not self._static_data_fetched:
                
                # Query charger basic information (for serial, model, production date, etc.)
                try:
                    basic_info = await self.client.query_charger_basic_info()
                except Exception as e:
                    basic_info = {}
                
                # Query charger protection information (for safety sensors)
                try:
                    protection_info = await self.client.query_charger_protection_info()
                except Exception as e:
                    protection_info = {}
                
                # Query WiFi configuration (for WiFi status)
                try:
                    wifi_config = await self.client.query_wifi_config()
                except Exception as e:
                    wifi_config = {}
                
                # Query WiFi status (for SSID, password, etc.)
                try:
                    wifi_status = await self.client.query_wifi_status()
                except Exception as e:
                    wifi_status = {}
                
                # Query network status (for error codes and detailed status)
                try:
                    network_status = await self.client.query_network_status()
                    # Merge network status into wifi_status for the sensors
                    if network_status:
                        wifi_status.update(network_status)
                except Exception as e:
                    pass  # Ignore errors during static data fetch
                
                self._static_data_fetched = True
            else:
                basic_info = self.data.get("basic_info", {}) if self.data else {}
                protection_info = self.data.get("protection_info", {}) if self.data else {}
                wifi_config = self.data.get("wifi_config", {}) if self.data else {}
                wifi_status = self.data.get("wifi_status", {}) if self.data else {}
            
            # Query dynamic data every update cycle
            
            # Query home current configuration (for capacity info)
            current_config = await self.client.query_home_current_config()
            if current_config:
                pass  # current_config available
            else:
                pass  # no current_config
            
            # Query power status to get home limit and configured limit (fire and forget like auth demo)
            await self.client.query_power_status()  # Fire and forget - response handled by notification handler
            power_status = self.client.get_last_power_status()  # Get the last received power status
            
            # Query charge mode to get current charge mode setting
            charge_mode = await self.client.query_charge_mode()
            
            
            # Get car connection state from heartbeat data
            heartbeat_state = self.client.get_car_connection_state()
            heartbeat_stats = self.client.get_heartbeat_stats()
            telemetry = self.client.get_last_telemetry()
            session_energy_offset = self.client.get_session_energy_offset()
            conn_status = self.client.get_connection_status()
            telemetry_dict: dict[str, Any] = {}
            if telemetry:
                session_energy = telemetry.session_energy_kwh
                if session_energy_offset is not None:
                    session_energy = max(0.0, session_energy - session_energy_offset)
                telemetry_dict = {
                    **telemetry.__dict__,
                    "voltage_v": round(telemetry.voltage_v, 1),
                    "current_a": round(telemetry.current_a, 1),
                    "session_energy_kwh": round(session_energy, 4),
                    "session_energy_kwh_raw": round(telemetry.session_energy_kwh, 4),
                    "session_runtime_seconds": telemetry.session_runtime_seconds,
                }
                # Prefer the runtime derived from the BLE session tracker when available
                session_runtime = conn_status.get("charging_session_duration")
                if (
                    telemetry.session_runtime_seconds == 0
                    and conn_status.get("charging_session_active")
                    and session_runtime is not None
                ):
                    telemetry_dict["session_runtime_seconds"] = int(session_runtime)
            
            # Send heartbeat to keep session alive
            await self.client.send_heartbeat()
            
            # Combine data
            data = {
                "current_config": current_config.__dict__ if current_config else {},
                "power_status": power_status.__dict__ if power_status else {},
                "basic_info": basic_info or {},
                "protection_info": protection_info or {},
                "wifi_config": wifi_config or {},
                "wifi_status": wifi_status or {},
                "heartbeat_state": heartbeat_state.__dict__,
                "heartbeat_stats": heartbeat_stats,
                "telemetry": telemetry_dict,
                "last_heartbeat_time": heartbeat_state.timestamp,
                "connected": self.client.is_connected,
                "session_token": self.client.session_token.hex() if self.client.session_token else None,
                "charge_mode": charge_mode,
            }
            
            return data

        except Exception as exc:
            raise UpdateFailed(f"Failed to update charger data: {exc}") from exc

    async def async_start_heartbeat(self) -> None:
        """Start the heartbeat task."""
        if self._heartbeat_task and not self._heartbeat_task.done():
            return
        
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def async_stop_heartbeat(self) -> None:
        """Stop the heartbeat task."""
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        self._heartbeat_task = None

    async def _heartbeat_loop(self) -> None:
        """Heartbeat loop to keep the session alive."""
        while True:
            try:
                if self.client.is_connected:
                    try:
                        await self.client.send_heartbeat()
                    except Exception as exc:
                        # The BLE client will handle reconnection automatically
                        pass
                
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
            except asyncio.CancelledError:
                break
            except Exception as exc:
                await asyncio.sleep(10)  # Wait before retrying

    async def async_shutdown(self) -> None:
        """Shutdown the coordinator."""
        await self.async_stop_heartbeat()
        if self.client:
            await self.client.async_disconnect()

    def get_connection_status(self) -> dict[str, Any]:
        """Get detailed connection status from the BLE client."""
        if self.client:
            return self.client.get_connection_status()
        return {"connected": False, "error": "No client available"}

    async def force_reconnect(self) -> bool:
        """Force an immediate reconnection attempt."""
        if self.client:
            success = await self.client.force_reconnect()
            if success:
                # Reset static data flag to fetch fresh data after reconnection
                self.reset_static_data_flag()
            return success
        return False

    def set_reconnection_config(self, max_attempts: int = None, initial_delay: float = None, max_delay: float = None) -> None:
        """Configure reconnection behavior."""
        if self.client:
            self.client.set_reconnection_config(max_attempts, initial_delay, max_delay)
