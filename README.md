# Zeekr Charger – Home Assistant Integration

A custom Home Assistant integration that connects your Zeekr EVSE wallbox (and maybe Raedian wallboxes) over **Bluetooth Low Energy (BLE)** for live monitoring and control.

> ⚠️ High voltage equipment can be dangerous. Use at your own risk. Validate limits with a licensed electrician. Never exceed your circuit/breaker rating.

## What you get

* **BLE (local) control**
  Works with Home Assistant’s BLE stack (including BLE proxies). No cloud required.
* **Live metrics**
  Charging status, plug state, requested/actual current, instantaneous power, and session energy (where available).
* **Controls**

  * Start / stop charging
  * Set charging current (great for solar tracking and tariff juggling)

## Supported hardware / status

* Tested on: **Single-phase 7 kW Zeekr branded** unit.
* Tested on my 009, where it responds to changes in the charge rate within a second or so, start charging in about 3 seconds, and stop charging instantly.  Charger state goes to suspended_ev when you hit your in-car charge limit.
* Likely compatible: Other Raedian variants using the same BLE protocol.
* Not tested: 11 kW/3-phase models (dealer wouldn't swap mine, unfortunately)
* Firmware: Works with stock firmware; **OCPP current control is not supported** by the charger, so this integration uses BLE instead.
* NB: You can use the esphome bluetooth proxy https://esphome.io/projects/ to repeat BLE over WiFi if your homeassistant box isn't nearby your zeekr wallbox.

If you try a different model, please report your results in an issue.

## How it works (short version)

This integration talks directly to the charger over BLE using a reverse engineered protocol. Home Assistant acts as the BLE client; only one BLE client can be connected at a time. If the vendor app is connected, Home Assistant won’t be able to connect (and vice-versa).

## One-time vendor app setup (recommended)

Your manual won’t tell you this, but you’ll need the vendor apps to set installer-level options:

1. **NEMO Charge (iOS/Android)**

   * Pair with the charger (uses a PIN shown in-app/on sticker).
   * Set the **grid limit / max amps** for your installation (iOS currently exposes this; Android may not).
2. **Raedian app** (optional)

   * Lets you control the charger over the internet (separate from Home Assistant).
3. **Web portal** (optional): [http://ams.raedion.com/](http://ams.raedion.com/)

   * Provides cloud management and OCPP server settings.
   * Note: The Zeekr charger appears pinned to Raedian’s backend; **BLE OCPP config writes are rejected**.

> Nerd corner: The controller is an ESP32. In theory you could flash a community firmware, but this integration assumes stock firmware.

## Installation

### Option A — HACS (recommended)

1. In Home Assistant, install **HACS** if you haven’t already.
2. HACS → Integrations → **Custom repositories** → Add your repo URL (type: *Integration*).
3. Search **Zeekr Charger** in HACS and install.
4. **Restart Home Assistant**.

### Option B — Manual

1. Copy `custom_components/zeekr_charger/` into your Home Assistant `config/custom_components/` folder.
2. **Restart Home Assistant**.

## Setup in Home Assistant

1. **Settings → Devices & Services → Add Integration**
2. Search for **Zeekr Charger**.
3. Enter:

   * **Serial Number** (from the sticker inside the unit or manual cover)
   * **BLE MAC Address** *(optional)* to skip discovery
4. Finish—Home Assistant will discover and connect over BLE.

> Tip: If you don’t see your charger, ensure no vendor app is connected and you’re within BLE range (or have a BLE proxy).


## Solar-aware automation (example)

```yaml
# Example: follow solar surplus between 6–20 A
alias: EV – Track solar surplus
mode: single
trigger:
  - platform: state
    entity_id: sensor.solar_surplus_amps  # your own template/measurement
condition: []
action:
  - service: number.set_value
    target:
      entity_id: number.zeekr_charge_current
    data:
      value: "{{ [ [ states('sensor.solar_surplus_amps')|int, 20 ] | min, 6 ] | max }}"
```

## Troubleshooting

* **“Can’t connect” / flapping connection**

  * Ensure the NEMO/Raedian app is **closed** (force-quit). Only one BLE client can connect at a time.
  * Move the HA host or BLE proxy closer; walls and cars are BLE-unfriendly (although the radio in my Zeekr wallbox is really strong!)
  * Power-cycle the charger (breaker off/on) if it got stuck after vendor-app use.

* **Current won’t change**

  * Verify your **grid limit** in the NEMO app allows the requested amps.
  * Some firmwares clamp changes during certain states; try while Idle or early in a session.
  * Make sure your automations aren’t fighting each other.

* **11 kW / 3-phase units**

  * Not validated yet. Please open an issue with your model, firmware, and logs.  I do suspect that 3-phase chargers may need some changes to the code.

## Safety & responsibility

* Match your breaker/cable rating and local electrical code.
* If you enable solar-tracking automations, **cap the max amps** appropriately.
* This integration is provided **as-is** without warranty. You accept all risk.

## Contributing

PRs welcome! Good places to help:

* Add support for additional models/firmwares
* Improve entity coverage & diagnostics
* Docs and examples (especially 3-phase setups)
* State edge cases that I've missed

Please include logs (`logger:` set to `debug` for `custom_components.zeekr_charger`) when filing issues.

## License

MIT (see `LICENSE`). For personal/educational use; commercial deployments at your own risk.
