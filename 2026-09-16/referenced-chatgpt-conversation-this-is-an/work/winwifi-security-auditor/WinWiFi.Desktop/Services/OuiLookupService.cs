using System;
using System.Collections.Generic;

namespace WinWiFi.Services
{
    public static class OuiLookupService
    {
        // Offline Embedded IEEE OUI Lookup Dictionary (Top Wireless AP & Station Vendors)
        private static readonly Dictionary<string, string> OuiDatabase = new(StringComparer.OrdinalIgnoreCase)
        {
            // Cisco / Meraki
            { "00:00:0C", "Cisco Systems" },
            { "00:01:42", "Cisco Systems" },
            { "00:01:43", "Cisco Systems" },
            { "00:01:63", "Cisco Systems" },
            { "00:01:C7", "Cisco Systems" },
            { "00:02:16", "Cisco Systems" },
            { "00:02:17", "Cisco Systems" },
            { "00:02:4A", "Cisco Systems" },
            { "00:03:6B", "Cisco Systems" },
            { "00:04:4D", "Cisco Systems" },
            { "00:18:0A", "Cisco Meraki" },
            { "00:18:BA", "Cisco Systems" },
            { "00:26:0B", "Cisco Systems" },
            { "04:6C:9D", "Cisco Systems" },
            { "0C:75:BD", "Cisco Systems" },
            { "34:DB:FD", "Cisco Meraki" },
            { "58:97:1E", "Cisco Meraki" },
            { "70:81:05", "Cisco Systems" },
            { "88:15:44", "Cisco Meraki" },
            { "E0:55:3D", "Cisco Meraki" },

            // Aruba Networks / Hewlett Packard Enterprise
            { "00:0B:86", "Aruba Networks (HPE)" },
            { "00:1A:1E", "Aruba Networks (HPE)" },
            { "04:BD:70", "Aruba Networks (HPE)" },
            { "18:64:72", "Aruba Networks (HPE)" },
            { "20:A6:CD", "Aruba Networks (HPE)" },
            { "24:DE:C6", "Aruba Networks (HPE)" },
            { "40:E3:D6", "Aruba Networks (HPE)" },
            { "6C:F3:7F", "Aruba Networks (HPE)" },
            { "84:D4:7E", "Aruba Networks (HPE)" },
            { "94:B4:0F", "Aruba Networks (HPE)" },
            { "AC:A3:1E", "Aruba Networks (HPE)" },
            { "D8:C7:C8", "Aruba Networks (HPE)" },

            // Ubiquiti Networks (UniFi)
            { "00:15:6D", "Ubiquiti Networks" },
            { "00:27:22", "Ubiquiti Networks" },
            { "04:18:D6", "Ubiquiti Networks" },
            { "18:E8:29", "Ubiquiti Networks" },
            { "24:5A:4C", "Ubiquiti Networks" },
            { "44:D9:E7", "Ubiquiti Networks" },
            { "60:22:32", "Ubiquiti Networks" },
            { "68:72:51", "Ubiquiti Networks" },
            { "70:A7:41", "Ubiquiti Networks" },
            { "74:83:C2", "Ubiquiti Networks" },
            { "78:8A:20", "Ubiquiti Networks" },
            { "80:2A:A8", "Ubiquiti Networks" },
            { "B4:FB:E4", "Ubiquiti Networks" },
            { "DC:9F:DB", "Ubiquiti Networks" },
            { "E0:63:DA", "Ubiquiti Networks" },
            { "F4:92:BF", "Ubiquiti Networks" },

            // Ruckus Wireless / CommScope
            { "00:13:92", "Ruckus Wireless" },
            { "00:24:82", "Ruckus Wireless" },
            { "2C:E6:CC", "Ruckus Wireless" },
            { "58:93:96", "Ruckus Wireless" },
            { "5C:E2:8C", "Ruckus Wireless" },
            { "74:3E:2B", "Ruckus Wireless" },
            { "8C:0C:90", "Ruckus Wireless" },
            { "C0:8A:DE", "Ruckus Wireless" },

            // Apple
            { "00:03:93", "Apple" },
            { "00:05:02", "Apple" },
            { "00:0A:27", "Apple" },
            { "00:0A:95", "Apple" },
            { "00:0D:93", "Apple" },
            { "00:10:FA", "Apple" },
            { "00:14:51", "Apple" },
            { "00:16:CB", "Apple" },
            { "00:17:F2", "Apple" },
            { "00:19:E3", "Apple" },
            { "00:1B:63", "Apple" },
            { "00:1C:B3", "Apple" },
            { "00:1D:4F", "Apple" },
            { "00:1E:52", "Apple" },
            { "00:1E:C2", "Apple" },
            { "00:1F:5B", "Apple" },
            { "00:1F:F3", "Apple" },
            { "00:21:E9", "Apple" },
            { "00:22:41", "Apple" },
            { "00:23:12", "Apple" },
            { "00:23:32", "Apple" },
            { "00:23:6C", "Apple" },
            { "00:24:36", "Apple" },
            { "00:25:00", "Apple" },
            { "00:25:4B", "Apple" },
            { "00:25:BC", "Apple" },
            { "00:26:08", "Apple" },
            { "00:26:4A", "Apple" },
            { "00:26:B0", "Apple" },
            { "14:10:9F", "Apple" },
            { "14:20:5E", "Apple" },
            { "14:99:E2", "Apple" },
            { "28:CF:DA", "Apple" },
            { "3C:07:54", "Apple" },
            { "40:6C:8F", "Apple" },
            { "48:60:BC", "Apple" },
            { "50:BC:96", "Apple" },
            { "60:03:08", "Apple" },
            { "70:11:24", "Apple" },
            { "78:4F:43", "Apple" },
            { "88:66:5A", "Apple" },
            { "98:01:A7", "Apple" },
            { "A4:C3:61", "Apple" },
            { "AC:BC:32", "Apple" },
            { "BC:52:B7", "Apple" },
            { "C8:3C:85", "Apple" },
            { "DC:A9:04", "Apple" },
            { "E4:CE:8F", "Apple" },
            { "F0:18:98", "Apple" },

            // Intel
            { "00:02:B3", "Intel" },
            { "00:03:47", "Intel" },
            { "00:04:23", "Intel" },
            { "00:07:E9", "Intel" },
            { "00:0E:0C", "Intel" },
            { "00:13:02", "Intel" },
            { "00:13:E8", "Intel" },
            { "00:15:00", "Intel" },
            { "00:16:6F", "Intel" },
            { "00:16:76", "Intel" },
            { "00:18:DE", "Intel" },
            { "00:19:D1", "Intel" },
            { "00:1B:21", "Intel" },
            { "00:1C:C0", "Intel" },
            { "00:1D:E0", "Intel" },
            { "00:1E:64", "Intel" },
            { "00:1E:65", "Intel" },
            { "00:1E:67", "Intel" },
            { "00:21:5C", "Intel" },
            { "00:21:6A", "Intel" },
            { "00:22:FB", "Intel" },
            { "00:23:14", "Intel" },
            { "00:24:D7", "Intel" },
            { "04:D3:B0", "Intel" },
            { "34:13:E8", "Intel" },
            { "48:51:B7", "Intel" },
            { "58:91:CF", "Intel" },
            { "68:05:CA", "Intel" },
            { "7C:57:58", "Intel" },
            { "80:86:F2", "Intel" },
            { "88:B1:11", "Intel" },
            { "A4:4C:C8", "Intel" },
            { "B4:96:91", "Intel" },
            { "DC:71:96", "Intel" },

            // Samsung
            { "00:07:AB", "Samsung" },
            { "00:12:47", "Samsung" },
            { "00:15:99", "Samsung" },
            { "00:16:32", "Samsung" },
            { "00:17:C9", "Samsung" },
            { "00:18:AF", "Samsung" },
            { "00:1A:8A", "Samsung" },
            { "00:1D:25", "Samsung" },
            { "00:21:D1", "Samsung" },
            { "00:23:D6", "Samsung" },
            { "00:24:54", "Samsung" },
            { "00:26:37", "Samsung" },
            { "14:49:E0", "Samsung" },
            { "20:55:31", "Samsung" },
            { "38:0B:40", "Samsung" },
            { "48:44:F7", "Samsung" },
            { "50:85:69", "Samsung" },
            { "60:A1:0A", "Samsung" },
            { "84:25:19", "Samsung" },
            { "AC:5F:3E", "Samsung" },
            { "BC:44:86", "Samsung" },
            { "CC:B1:1A", "Samsung" },
            { "E8:50:8B", "Samsung" },

            // TP-Link
            { "00:1D:0F", "TP-Link" },
            { "00:25:86", "TP-Link" },
            { "14:CC:20", "TP-Link" },
            { "18:D6:C7", "TP-Link" },
            { "30:B5:C2", "TP-Link" },
            { "50:C7:BF", "TP-Link" },
            { "60:32:B1", "TP-Link" },
            { "74:DA:38", "TP-Link" },
            { "98:48:27", "TP-Link" },
            { "AC:84:C6", "TP-Link" },
            { "C0:06:C3", "TP-Link" },
            { "C4:E9:84", "TP-Link" },
            { "E8:48:B8", "TP-Link" },

            // Netgear
            { "00:09:5B", "Netgear" },
            { "00:0F:B5", "Netgear" },
            { "00:14:6C", "Netgear" },
            { "00:18:4D", "Netgear" },
            { "00:1B:2F", "Netgear" },
            { "00:1E:2A", "Netgear" },
            { "00:1F:33", "Netgear" },
            { "00:24:B2", "Netgear" },
            { "00:26:F2", "Netgear" },
            { "10:DA:43", "Netgear" },
            { "20:4E:7F", "Netgear" },
            { "28:C6:8E", "Netgear" },
            { "84:1B:5E", "Netgear" },
            { "9C:3D:CF", "Netgear" },
            { "C0:3F:0E", "Netgear" },

            // ASUS
            { "00:0C:6E", "ASUS" },
            { "00:11:D8", "ASUS" },
            { "00:15:F2", "ASUS" },
            { "00:18:F3", "ASUS" },
            { "00:1A:92", "ASUS" },
            { "00:1B:FC", "ASUS" },
            { "00:1D:60", "ASUS" },
            { "00:1E:8C", "ASUS" },
            { "00:22:15", "ASUS" },
            { "00:24:8C", "ASUS" },
            { "00:26:18", "ASUS" },
            { "04:D9:F5", "ASUS" },
            { "10:BF:48", "ASUS" },
            { "2C:FD:A1", "ASUS" },
            { "38:2C:4A", "ASUS" },
            { "50:46:5D", "ASUS" },
            { "74:D0:2B", "ASUS" },
            { "AC:22:0B", "ASUS" },

            // Google
            { "00:1A:11", "Google" },
            { "3C:5A:B4", "Google" },
            { "48:D6:D5", "Google" },
            { "54:60:09", "Google" },
            { "70:3E:AC", "Google" },
            { "94:EB:CD", "Google" },
            { "A4:77:33", "Google" },
            { "D8:6C:63", "Google" },
            { "F4:F5:DB", "Google" },

            // Amazon
            { "00:FC:8B", "Amazon Technologies" },
            { "18:74:2E", "Amazon Technologies" },
            { "34:D2:70", "Amazon Technologies" },
            { "40:B4:CD", "Amazon Technologies" },
            { "44:65:0D", "Amazon Technologies" },
            { "50:DC:E7", "Amazon Technologies" },
            { "68:37:E9", "Amazon Technologies" },
            { "74:C2:46", "Amazon Technologies" },
            { "AC:63:BE", "Amazon Technologies" },
            { "CC:A7:C1", "Amazon Technologies" },
            { "F0:D2:F1", "Amazon Technologies" },

            // Espressif (IoT / ESP8266 / ESP32)
            { "18:FE:34", "Espressif Inc (ESP8266/ESP32)" },
            { "24:0A:C4", "Espressif Inc (ESP8266/ESP32)" },
            { "24:62:AB", "Espressif Inc (ESP8266/ESP32)" },
            { "24:6F:28", "Espressif Inc (ESP8266/ESP32)" },
            { "24:B2:DE", "Espressif Inc (ESP8266/ESP32)" },
            { "2C:F4:32", "Espressif Inc (ESP8266/ESP32)" },
            { "30:AE:A4", "Espressif Inc (ESP8266/ESP32)" },
            { "3C:61:05", "Espressif Inc (ESP8266/ESP32)" },
            { "3C:71:BF", "Espressif Inc (ESP8266/ESP32)" },
            { "48:55:19", "Espressif Inc (ESP8266/ESP32)" },
            { "4C:11:AE", "Espressif Inc (ESP8266/ESP32)" },
            { "5C:CF:7F", "Espressif Inc (ESP8266/ESP32)" },
            { "60:01:94", "Espressif Inc (ESP8266/ESP32)" },
            { "68:C6:3A", "Espressif Inc (ESP8266/ESP32)" },
            { "84:0D:8E", "Espressif Inc (ESP8266/ESP32)" },
            { "84:F3:EB", "Espressif Inc (ESP8266/ESP32)" },
            { "90:97:D5", "Espressif Inc (ESP8266/ESP32)" },
            { "A4:CF:12", "Espressif Inc (ESP8266/ESP32)" },
            { "AC:D0:74", "Espressif Inc (ESP8266/ESP32)" },
            { "B4:E6:2D", "Espressif Inc (ESP8266/ESP32)" },
            { "BC:DD:C2", "Espressif Inc (ESP8266/ESP32)" },
            { "C4:4F:33", "Espressif Inc (ESP8266/ESP32)" },
            { "CC:50:E3", "Espressif Inc (ESP8266/ESP32)" },
            { "DC:4F:22", "Espressif Inc (ESP8266/ESP32)" },

            // MikroTik
            { "00:0C:42", "MikroTik" },
            { "2C:C8:1B", "MikroTik" },
            { "48:8F:5A", "MikroTik" },
            { "64:D1:54", "MikroTik" },
            { "74:4D:28", "MikroTik" },
            { "B8:69:F4", "MikroTik" },
            { "CC:2D:E0", "MikroTik" },
            { "D4:CA:6D", "MikroTik" },
            { "E4:8D:8C", "MikroTik" },

            // Huawei
            { "00:1E:10", "Huawei Technologies" },
            { "00:25:9E", "Huawei Technologies" },
            { "04:25:C5", "Huawei Technologies" },
            { "10:1B:54", "Huawei Technologies" },
            { "28:6E:D4", "Huawei Technologies" },
            { "40:4D:8E", "Huawei Technologies" },
            { "70:7B:E8", "Huawei Technologies" },
            { "9C:28:40", "Huawei Technologies" },
            { "AC:85:3D", "Huawei Technologies" },
            { "D4:6E:0E", "Huawei Technologies" },

            // Raspberry Pi
            { "B8:27:EB", "Raspberry Pi Foundation" },
            { "DC:A6:32", "Raspberry Pi Trading" },
            { "E4:5F:01", "Raspberry Pi Trading" },
            { "28:CD:C1", "Raspberry Pi Trading" }
        };

        public static string ResolveVendor(string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress) || macAddress.Length < 8)
            {
                return "Unknown";
            }

            // Standardize format to AA:BB:CC
            string clean = macAddress.Replace("-", ":").Trim();
            if (clean.Length >= 8)
            {
                string prefix = clean.Substring(0, 8).ToUpperInvariant();
                if (OuiDatabase.TryGetValue(prefix, out string? vendor))
                {
                    return vendor;
                }
            }

            // Check if locally administered address (LAA / randomized MAC)
            // In 802.11, if bit 1 of byte 0 is set (0x02), it is a locally administered / randomized MAC
            try
            {
                string firstByteHex = clean.Substring(0, 2);
                byte b0 = Convert.ToByte(firstByteHex, 16);
                if ((b0 & 0x02) != 0)
                {
                    return "Randomized / Private MAC (LAA)";
                }
            }
            catch
            {
                // ignore parsing failure
            }

            return "Unknown";
        }

        public static bool IsLocallyAdministered(string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress)) return false;
            string clean = macAddress.Replace("-", ":").Trim();
            if (clean.Length < 2) return false;
            try
            {
                string firstByteHex = clean.Substring(0, 2);
                byte b0 = Convert.ToByte(firstByteHex, 16);
                return (b0 & 0x02) != 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
