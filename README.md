# ZTE Router Info (MF297D2 and similar)

[![Build and Release](https://github.com/MironJajtic/ha-zte-router-info/actions/workflows/release.yml/badge.svg)](https://github.com/MironJajtic/ha-zte-router-info/actions/workflows/release.yml)
[![GitHub release](https://img.shields.io/github/release/MironJajtic/ha-zte-router-info.svg)](https://github.com/MironJajtic/ha-zte-router-info/releases/)
![GitHub License](https://img.shields.io/github/license/MironJajtic/ha-zte-router-info)
![GitHub Stars](https://img.shields.io/github/stars/MironJajtic/ha-zte-router-info)

![Contributors](https://img.shields.io/github/contributors/MironJajtic/ha-zte-router-info)
![Maintenance](https://img.shields.io/maintenance/yes/2025)
![Last Commit](https://img.shields.io/github/last-commit/MironJajtic/ha-zte-router-info)
![Commit Activity](https://img.shields.io/github/commit-activity/y/MironJajtic/ha-zte-router-info)
![Installation Count](https://img.shields.io/badge/dynamic/json?color=41BDF5&logo=home-assistant&label=integration%20usage&suffix=%20installs&cacheSeconds=15600&url=https://analytics.home-assistant.io/custom_integrations.json&query=$.zte_router_info.total)


# ZTE Router Info (MF297D2 and similar)

A lightweight Home Assistant integration that exposes LTE radio metrics, throughput, version,
SSID, WAN/LAN IP (when available) for ZTE routers like **MF297D2**, with a reboot switch.
It supports **hybrid autodiscovery mode** — automatically adds all JSON fields from the router as sensors.

## Installation (HACS)

1. In HACS → Integrations → **Custom repositories** add:
   `https://github.com/MironJajtic/ha-zte-router-info` (category: Integration)
2. Install **ZTE Router Info**.
3. Restart Home Assistant.
4. Go to **Settings → Devices & Services → Add Integration → ZTE Router Info**.

## Configuration

- **IP address** (default `192.168.8.1`)
- **Admin password** (required; router must be logged in for data to populate)

## Entities

- RSSI, RSRP, SINR, LTE Band, PCI, Cell ID, Carrier Aggregation, Signal Bars
- Provider, LAN IP, WAN IP (if firmware exposes `wan_ipaddr`)
- TX/RX Throughput (kbps), Monthly TX/RX bytes
- Firmware version, SSID
- **Switch**: Router Reboot
- Optional autodiscovery of all metrics
- Configurable via UI (router IP, password, refresh interval)

Tested with MF297D2 (A1 HR firmware). Other ZTE models using the same `goform_*` API should work.
