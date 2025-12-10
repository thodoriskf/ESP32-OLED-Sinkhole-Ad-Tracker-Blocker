# ESP32-OLED-Sinkhole-AdBlocker

**A lightweight, hardware-based DNS sinkhole running on the ESP32 with an integrated OLED dashboard.**

![Project Status](https://img.shields.io/badge/status-active-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue) ![Platform](https://img.shields.io/badge/platform-ESP32-orange)

## Overview
This project transforms a standard **ESP32 development board (specifically the version with an integrated 0.96" OLED)** into a dedicated DNS Sinkhole. Similar to a Pi-hole but for microcontrollers, it intercepts DNS requests on your local network. <img width="800" height="1542" alt="image" src="https://github.com/user-attachments/assets/62a8582e-a398-4500-8493-9354ceaf8398" />




The device checks domains against a blocklist, whitelist, and keyword list stored in the flash memory (SPIFFS). If a domain is blocked, it returns `NXDOMAIN` (Non-Existent Domain); otherwise, it forwards the request to a secure upstream provider (Quad9, https://quad9.net/).

## Key Features
* **OLED Live Status:** The integrated 0.96" screen displays real-time IP address, connection status, and total queries blocked.
* **Web Dashboard:** A responsive, locally hosted web interface (Vanilla JS & Chart.js) to view query statistics and manage settings.
* **Dynamic Blocking:** Supports Blocklists, Whitelists, and Keyword filtering managed via the web interface.
* **WiFiManager:** No hardcoded credentials. Connect to the `ESP32-AdBlock` hotspot on first boot to configure your WiFi.
* **mDNS Support:** Access the dashboard via `http://adblock.local` instead of remembering IP addresses.
* **Persistent Storage:** Uses SPIFFS file system to store configuration and list data even after power loss.

## Hardware Required
This code is optimized for **"esp32 dev kit"** style boards (often sold as IdeaSpark, Heltec, or generic ESP32 OLED boards).



* **MCU:** ESP32-WROOM-32
* **Display:** Integrated 0.96" SSD1306 OLED (I2C)
* **Pinout:** SDA (GPIO 21), SCL (GPIO 22)
* **USB to TTL:** CH340 Chipset

## Software Dependencies
Ensure the following libraries are installed in your Arduino IDE:

1.  **Adafruit GFX Library**
2.  **Adafruit SSD1306**
3.  **WiFiManager** (by tzapu)
4.  **ESP32 Built-in Libraries:**
    * 1. `WiFi.h`
    * 2. `WiFiUdp.h`
    * 3. `Wire.h`
    * 4. `SPIFFS.h`
    * 5. `WebServer.h`
    * 6. `Preferences.h`
    * 7. `ESPmDNS.h`

## Installation Guide

### 1. Driver Setup (Crucial)
Most cheap ESP32 OLED boards use the **CH340** USB-to-Serial chip. If your computer does not recognize the board (no COM port appears):
* Download and install the **CH340 / CH341 Drivers** for your OS (https://electropeak.com/learn/how-to-install-ch340-driver/).

### 2. Uploading the Code
1.  Open the `.ino` file in Arduino IDE.
2.  Select Board: **ESP32 DEV MODULE** (or generic ESP32 Dev KIT).
3.  Connect your board via USB.
4.  Click **Upload**.

### 3. Uploading the Filesystem (SPIFFS) - Do not skip!
The blocklists (`blocklist.txt`) live in the SPIFFS partition, not the code itself.

1.  **Arduino IDE 1.8:** Use the "ESP32 Sketch Data Upload" tool.
2.  **Arduino IDE 2.0+:** Install the specific SPIFFS plugin or use a CLI tool like `mkspiffs`.
3.  **Confirm:** Ensure the `data` folder inside your project directory is uploaded to the board.

## How to Use

### First Boot & Setup
When you power on the device for the first time, it does not know your WiFi credentials.
1.  **Look at the OLED Screen:** It should display `Connect to AP: ESP32-AdBlock`.
2.  **Connect:** On your phone/laptop, search for a WiFi network named **ESP32-AdBlock** and connect to it.
3.  **Captive Portal:** A window should automatically pop up. If not, open a browser and go to `192.168.4.1`.
4.  **Configure WiFi:** Click "Configure WiFi", select your home network, enter the password, and save.
5.  **Reboot:** The device will restart and connect to your home network. The OLED will now show its new **Local IP** (e.g., `192.168.1.50`).

### Client Configuration
1.  **Configure Client:** On your PC or Phone, go to Network Settings.
2.  **Set DNS:** Change the DNS server from "Automatic/DHCP" to **Manual**.
3.  **Enter IPv4:** Input the IP address displayed on the ESP32's OLED screen.
4.  **Enter IPv6:** `::1`
5.  **Browse:** The ESP32 will now filter ads and tracking domains.

## Troubleshooting

| Issue | Possible Cause | Solution |
| :--- | :--- | :--- |
| **Screen is black** | Wrong Reset Pin | In code, ensure `OLED_RESET` is set to `-1` (if no reset pin) or `16` (common for Heltec boards). |
| **Board not found in IDE** | Missing Drivers | Install **CH340** drivers. Try a different USB cable (some are power-only). |
| **"SPIFFS Mount Failed"** | No FS Uploaded | You uploaded the code but forgot to upload the **Data Folder**. See Installation Guide Step 3. |
| **Ads still showing** | DNS Caching | Your PC/Phone has cached the ad domains. Clear your OS DNS cache or reboot your device. |

### Pro Tip: Network vs. Cosmetic Blocking
For the ultimate ad-free experience, i recommend using this device alongside a browser extension like **uBlock Origin**.
* **ESP32 Sinkhole:** Blocks ads and telemetry/traacking on your entire network (Smart TVs, Phones).
* **uBlock Origin:** Cleans up empty ad slots ("cosmetic filtering") and blocks YouTube video ads, which DNS sinkholes cannot stop.

## Future Roadmap

* **Zero-RAM SD Card Lookup:** Implement a **Binary Search algorithm** to query massive blocklists (1M+ domains) directly from the SD card. This bypasses the ESP32's RAM limitations while maintaining millisecond-level latency.
* **DNS over TLS (DoT) Support:** Implement encryption on port 853. DoT is preferred over DoH for this embedded architecture as it provides privacy with significantly lower CPU/RAM overhead than the HTTP stack required for DoH.
* **Intelligent SD Card Storage:**
    * **Binary Search:** Enable fast O(log n) lookups on massive external lists (1M+ domains).
    * **Frequency-Based Caching:** Develop an algorithm to analyze blocked domain logs and auto-sort the most frequently blocked domains to the top of the list for faster access.
* **Migrate to LittleFS:** Move away from the deprecated SPIFFS for better file system performance.
* **Over-the-Air (OTA) Updates:** Allow firmware upgrades via the web interface without USB connection.
* **Live Log Viewer:** A real-time scrolling console on the dashboard to see exactly which domains are being blocked.
* **IPv6 Support:** Handle AAAA records to ensure ad blocking across modern network .
* **One-Click Bypass:** A specific local URL (e.g., `http://temporarily.allow`) that grants a N-second bypass for the requesting device,  without necessarily editing the  whitelist.
* **MQTT & Smart Home Integration:** Publish real-time blocking statistics (Total Blocked, Queries/sec) to MQTT brokers for seamless integration with Home Assistant dashboards.
* **Printable Case:** Full STL for a 3d printed case

## Credits & Acknowledgments
   This project relies heavily on the open-source community for its blocking logic.
   * **Blocklists:**
    * [StevenBlack/hosts](https://github.com/StevenBlack/hosts) (MIT License) - The primary source for ad/malware blocking.
    * [Firebog](https://firebog.net/) - A curated collection of blocklists used to expand coverage.
   * **Libraries:**
    * [WiFiManager](https://github.com/tzapu/WiFiManager) by tzapu
    * [Adafruit GFX](https://github.com/adafruit/Adafruit-GFX-Library) & [SSD1306](https://github.com/adafruit/Adafruit_SSD1306)

## Disclaimer
  This project  is provided for educational and privacy-enhancing purposes only. 
  * **Use at your own risk.** There is no responsibility for missed important emails, broken websites, or network interruptions caused by this device.
  * **Not a Firewall:** This device blocks DNS requests; it does not encrypt traffic or act as a security firewall. 
  * **Reliability:** As an embedded device with limited RAM, it may restart under heavy network load. It is not intended for enterprise environments.

## Support
  If you find this project useful, give it a **Star ⭐** on GitHub! 
  If you have issues, please [open an issue](https://github.com/thodoriskf/ESP32-OLED-Sinkhole-AdBlocker/issues) rather than emailing me directly.
