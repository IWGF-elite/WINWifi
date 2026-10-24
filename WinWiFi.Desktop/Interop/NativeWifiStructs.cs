using System;
using System.Runtime.InteropServices;

namespace WinWiFi.Interop
{
    public enum WLAN_INTERFACE_STATE
    {
        wlan_interface_state_not_ready = 0,
        wlan_interface_state_connected = 1,
        wlan_interface_state_ad_hoc_network_formed = 2,
        wlan_interface_state_disconnecting = 3,
        wlan_interface_state_disconnected = 4,
        wlan_interface_state_associating = 5,
        wlan_interface_state_discovering = 6,
        wlan_interface_state_authenticating = 7
    }

    public enum DOT11_BSS_TYPE
    {
        dot11_BSS_type_infrastructure = 1,
        dot11_BSS_type_independent = 2,
        dot11_BSS_type_any = 3
    }

    public enum DOT11_PHY_TYPE : uint
    {
        dot11_phy_type_unknown = 0,
        dot11_phy_type_any = 0,
        dot11_phy_type_fhss = 1,
        dot11_phy_type_dsss = 2,
        dot11_phy_type_irbaseband = 3,
        dot11_phy_type_ofdm = 4,
        dot11_phy_type_hrdsss = 5,
        dot11_phy_type_erp = 6,
        dot11_phy_type_ht = 7,       // 802.11n
        dot11_phy_type_vht = 8,      // 802.11ac
        dot11_phy_type_dmg = 9,
        dot11_phy_type_he = 10,      // 802.11ax (Wi-Fi 6 / 6E)
        dot11_phy_type_eht = 11      // 802.11be (Wi-Fi 7)
    }

    public enum DOT11_AUTH_ALGORITHM : uint
    {
        DOT11_AUTH_ALGO_80211_OPEN = 1,
        DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
        DOT11_AUTH_ALGO_WPA = 3,
        DOT11_AUTH_ALGO_WPA_PSK = 4,
        DOT11_AUTH_ALGO_WPA_NONE = 5,
        DOT11_AUTH_ALGO_RSNA = 6,         // WPA2 Enterprise
        DOT11_AUTH_ALGO_RSNA_PSK = 7,     // WPA2 Personal
        DOT11_AUTH_ALGO_WPA3 = 8,         // WPA3 Enterprise 192-bit
        DOT11_AUTH_ALGO_WPA3_SAE = 9,     // WPA3 Personal
        DOT11_AUTH_ALGO_OWE = 10          // Enhanced Open (OWE)
    }

    public enum DOT11_CIPHER_ALGORITHM : uint
    {
        DOT11_CIPHER_ALGO_NONE = 0x00,
        DOT11_CIPHER_ALGO_WEP40 = 0x01,
        DOT11_CIPHER_ALGO_TKIP = 0x02,
        DOT11_CIPHER_ALGO_CCMP = 0x04,
        DOT11_CIPHER_ALGO_WEP104 = 0x05,
        DOT11_CIPHER_ALGO_BIP = 0x1F,     // Management Frame Protection
        DOT11_CIPHER_ALGO_GCMP = 0x08,
        DOT11_CIPHER_ALGO_GCMP_256 = 0x09
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_SSID
    {
        public uint uSSIDLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ucSSID;

        public string GetSsidString()
        {
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            if (uSSIDLength == 0 || ucSSID == null) return string.Empty;
            int len = (int)Math.Min(uSSIDLength, (uint)Math.Min(32, ucSSID.Length));
            byte[] value = ucSSID.Take(len).ToArray();
            try
            {
                string utf8 = new System.Text.UTF8Encoding(false, true).GetString(value);
                if (utf8.All(ch => !char.IsControl(ch))) return utf8;
            }
            catch (System.Text.DecoderFallbackException)
            {
                // Non-UTF8 SSIDs occur in legacy Windows deployments. CP-1252
                // is an explicit, deterministic fallback rather than mojibake.
            }
            string cp1252 = System.Text.Encoding.GetEncoding(1252).GetString(value);
            if (cp1252.All(ch => !char.IsControl(ch))) return cp1252;
            return string.Concat(value.Select(b => $"\\x{b:X2}"));
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strInterfaceDescription;
        public WLAN_INTERFACE_STATE isState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_INTERFACE_INFO_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
        // Followed in unmanaged memory by dwNumberOfItems of WLAN_INTERFACE_INFO
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_MAC_ADDRESS
    {
        public byte Byte0;
        public byte Byte1;
        public byte Byte2;
        public byte Byte3;
        public byte Byte4;
        public byte Byte5;

        public byte[] ToByteArray() => new byte[] { Byte0, Byte1, Byte2, Byte3, Byte4, Byte5 };

        public override string ToString() =>
            string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}", Byte0, Byte1, Byte2, Byte3, Byte4, Byte5);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_BSS_ENTRY
    {
        public DOT11_SSID dot11Ssid;
        public uint uPhyId;
        public DOT11_MAC_ADDRESS dot11Bssid;
        public DOT11_BSS_TYPE dot11BssType;
        public DOT11_PHY_TYPE dot11BssPhyType;
        public int lRssi; // in dBm, e.g. -65
        public uint uLinkQuality; // 0 to 100%
        [MarshalAs(UnmanagedType.I1)]
        public bool bInRegDomain;
        public ushort usBeaconPeriod;
        public ulong ullTimestamp;
        public ulong ullHostTimestamp;
        public ushort usCapabilityInformation;
        public uint ulChCenterFrequency; // in kHz, e.g. 2437000 for Channel 6
        public WLAN_RATE_SET wlanRateSet;
        public uint ulIeOffset;
        public uint ulIeSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_RATE_SET
    {
        public uint uRateSetLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)]
        public ushort[] usRateSet;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_BSS_LIST
    {
        public uint dwTotalSize;
        public uint dwNumberOfItems;
        // Followed in unmanaged memory by dwNumberOfItems of DOT11_BSS_ENTRY
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_RAW_DATA
    {
        public uint dwDataSize;
        public byte[] DataBytes;
    }

    public enum WLAN_CONNECTION_MODE
    {
        wlan_connection_mode_profile = 0,
        wlan_connection_mode_temporary_profile = 1,
        wlan_connection_mode_discovery_secure = 2,
        wlan_connection_mode_discovery_unsecure = 3,
        wlan_connection_mode_auto = 4,
        wlan_connection_mode_invalid = 5
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_CONNECTION_PARAMETERS
    {
        public WLAN_CONNECTION_MODE wlanConnectionMode;
        [MarshalAs(UnmanagedType.LPWStr)] public string? strProfile;
        public IntPtr pDot11Ssid;
        public IntPtr pDesiredBssidList;
        public DOT11_BSS_TYPE dot11BssType;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_CONNECTION_ATTRIBUTES
    {
        public WLAN_INTERFACE_STATE isState;
        public WLAN_CONNECTION_MODE wlanConnectionMode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strProfileName;
        public WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
        public WLAN_SECURITY_ATTRIBUTES wlanSecurityAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_ASSOCIATION_ATTRIBUTES
    {
        public DOT11_SSID dot11Ssid;
        public DOT11_BSS_TYPE dot11BssType;
        public DOT11_MAC_ADDRESS dot11Bssid;
        public DOT11_PHY_TYPE dot11PhyType;
        public uint uDot11PhyIndex;
        public uint wlanSignalQuality;
        public uint ulRxRate;
        public uint ulTxRate;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_SECURITY_ATTRIBUTES
    {
        [MarshalAs(UnmanagedType.Bool)] public bool bSecurityEnabled;
        [MarshalAs(UnmanagedType.Bool)] public bool bOneXEnabled;
        public DOT11_AUTH_ALGORITHM dot11AuthAlgorithm;
        public DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm;
    }
}
