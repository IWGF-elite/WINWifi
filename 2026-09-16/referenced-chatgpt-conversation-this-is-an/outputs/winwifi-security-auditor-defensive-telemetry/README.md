# WinWiFi Live Scanner

WinWiFi is a native Windows desktop application for live Wi-Fi security observation. Launching `WinWiFi.exe` opens the desktop interface, detects a Windows Wi-Fi adapter, and starts normal Windows WLAN discovery automatically. No browser, Node.js, npm command, imported capture file, training lab, or demo data is required.

## What it does

- Reads live access-point observations from the selected Windows WLAN adapter.
- Runs a normal Windows WLAN discovery cycle every 15 seconds.
- Shows observed SSIDs, BSSIDs, channels, signal strength, security settings, vendor information, RF congestion, and live threat findings.
- Stores live audit records locally in SQLite for reporting and incident management.

The application uses standard Windows WLAN APIs. It does not use monitor mode, inject packets, deauthenticate devices, or crack credentials.

## Run the application

Open `publish-live\\WinWiFi.exe` on Windows. Enable Wi-Fi first; the app will select the first available adapter and begin live discovery. Use the adapter selector if the laptop has more than one Wi-Fi interface.

## Build a release

```powershell
dotnet restore WinWiFi.sln --ignore-failed-sources
dotnet publish WinWiFi.Desktop\\WinWiFi.Desktop.csproj -c Release -o .\\publish-live
```

The publish folder is the application distribution. A machine running it needs the .NET 8 Windows Desktop Runtime unless you later publish a self-contained package.
