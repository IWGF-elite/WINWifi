using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WinWiFi.Interop
{
    public static class NativeWifi
    {
        private const string WLAN_API_DLL = "wlanapi.dll";

        public const uint WLAN_CLIENT_VERSION_VISTA = 2;
        public const uint ERROR_SUCCESS = 0;
        public const uint ERROR_ACCESS_DENIED = 5;
        public const uint ERROR_INVALID_PARAMETER = 87;
        public const uint ERROR_NOT_SUPPORTED = 50;
        public const uint WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7;

        [DllImport(WLAN_API_DLL, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint WlanSetProfile(IntPtr hClientHandle, [In] ref Guid pInterfaceGuid,
            uint dwFlags, string strProfileXml, string? strAllUserProfileSecurity,
            bool bOverwrite, IntPtr pReserved, out uint pdwReasonCode);

        [DllImport(WLAN_API_DLL, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint WlanConnect(IntPtr hClientHandle, [In] ref Guid pInterfaceGuid,
            [In] ref WLAN_CONNECTION_PARAMETERS pConnectionParameters, IntPtr pReserved);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanQueryInterface(IntPtr hClientHandle, [In] ref Guid pInterfaceGuid,
            uint OpCode, IntPtr pReserved, out uint pdwDataSize, out IntPtr ppData, out uint pWlanOpcodeValueType);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanOpenHandle(
            uint dwClientVersion,
            IntPtr pReserved,
            out uint pdwNegotiatedVersion,
            out IntPtr phClientHandle);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanCloseHandle(
            IntPtr hClientHandle,
            IntPtr pReserved);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanEnumInterfaces(
            IntPtr hClientHandle,
            IntPtr pReserved,
            out IntPtr ppInterfaceList);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanScan(
            IntPtr hClientHandle,
            [In] ref Guid pInterfaceGuid,
            IntPtr pDot11Ssid,
            IntPtr pIeData,
            IntPtr pReserved);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanGetNetworkBssList(
            IntPtr hClientHandle,
            [In] ref Guid pInterfaceGuid,
            IntPtr pDot11Ssid,
            DOT11_BSS_TYPE dot11BssType,
            bool bSecurityEnabled,
            IntPtr pReserved,
            out IntPtr ppWlanBssList);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern void WlanFreeMemory(IntPtr pMemory);

        // Helper to format 6-byte MAC address into standard AA:BB:CC:DD:EE:FF
        public static string FormatMacAddress(byte[] mac)
        {
            if (mac == null || mac.Length < 6) return "00:00:00:00:00:00";
            return string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }

        public static string FormatMacAddress(DOT11_MAC_ADDRESS mac) => mac.ToString();

        // Translate Center Frequency in kHz to IEEE 802.11 channel number
        public static (int channel, string band) FrequencyToChannel(uint freqKHz)
        {
            uint freqMHz = freqKHz / 1000;

            // 2.4 GHz Band (Channels 1 - 14)
            if (freqMHz == 2484) return (14, "2.4 GHz");
            if (freqMHz >= 2412 && freqMHz <= 2472)
            {
                int ch = (int)((freqMHz - 2407) / 5);
                return (ch, "2.4 GHz");
            }

            // 5 GHz Band (Channels 36 - 177)
            if (freqMHz >= 5170 && freqMHz <= 5885)
            {
                int ch = (int)((freqMHz - 5000) / 5);
                return (ch, "5 GHz");
            }

            // 6 GHz Band (Wi-Fi 6E / Wi-Fi 7, Channels 1 - 233)
            if (freqMHz >= 5955 && freqMHz <= 7115)
            {
                int ch = (int)((freqMHz - 5950) / 5);
                return (ch, "6 GHz");
            }

            return (0, "Unknown");
        }
    }
}
