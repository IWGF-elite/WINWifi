/**
 * WinWiFi Security Auditor — Live Scan Integration
 * ---------------------------------------------------
 * Drop this into your web app. It polls the local scanner service
 * (wifi_scanner_service.py) every few seconds and replaces your
 * simulated network array with the real scan results.
 *
 * Prereqs:
 *   1. Run wifi_scanner_service.py on the demo machine
 *      (python wifi_scanner_service.py)
 *   2. Make sure it's reachable at http://127.0.0.1:5055
 */

const SCANNER_ENDPOINT = "http://127.0.0.1:5055/api/networks";
const POLL_INTERVAL_MS = 4000;

let liveNetworks = [];
let lastUpdated = null;
let scannerOnline = false;

async function pollLiveNetworks() {
  try {
    const res = await fetch(SCANNER_ENDPOINT, { cache: "no-store" });
    if (!res.ok) throw new Error(`Scanner responded ${res.status}`);

    const data = await res.json();
    liveNetworks = data.networks || [];
    lastUpdated = data.last_updated;
    scannerOnline = true;

    renderNetworks(liveNetworks);
    updateScannerStatusBadge(true, lastUpdated);
  } catch (err) {
    scannerOnline = false;
    updateScannerStatusBadge(false, null);
    // Fall back to whatever simulated/demo data your app already has,
    // or show a clear "scanner offline" state instead of silently
    // failing.
    console.warn("Live scanner unreachable, falling back:", err.message);
  }
}

/**
 * Example render function — adapt field names to match your
 * existing network-card / table component.
 */
function renderNetworks(networks) {
  // networks[i] = {
  //   ssid, bssid, authentication, encryption,
  //   radio_type, channel, band, signal_percent, signal_dbm
  // }
  //
  // Map this into whatever your UI's existing network object shape
  // expects, e.g.:
  //
  // const mapped = networks.map(n => ({
  //   name: n.ssid,
  //   mac: n.bssid,
  //   security: n.authentication,
  //   cipher: n.encryption,
  //   channel: n.channel,
  //   band: n.band,
  //   rssi: n.signal_dbm,
  //   signalPct: n.signal_percent,
  // }));
  // dashboardStore.setNetworks(mapped);
}

function updateScannerStatusBadge(online, timestamp) {
  // Point this at whatever badge/indicator element you use for
  // "LIVE WINDOWS DATA" / "Bridge: CONNECTED" in the header.
  // Example:
  // const badge = document.querySelector("#scanner-status");
  // if (badge) {
  //   badge.textContent = online
  //     ? `Live scan • updated ${new Date(timestamp).toLocaleTimeString()}`
  //     : "Scanner offline — showing last known data";
  //   badge.classList.toggle("status-online", online);
  //   badge.classList.toggle("status-offline", !online);
  // }
}

// Start polling
pollLiveNetworks();
setInterval(pollLiveNetworks, POLL_INTERVAL_MS);
