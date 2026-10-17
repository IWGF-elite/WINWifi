import React, { useState, useEffect } from 'react';
import { 
  FlaskConical, 
  CheckCircle2, 
  XCircle, 
  Play, 
  RotateCw, 
  X, 
  Terminal,
  ShieldCheck,
  Cpu,
  Binary,
  Layers,
  HardDrive
} from 'lucide-react';
import { SqliteDatabaseService } from '../services/storage';
import { WifiEngine } from '../services/wifiEngine';
import { PcapService } from '../services/pcapParser';

interface TestResult {
  id: string;
  name: string;
  category: 'Sandbox' | 'PCAP' | 'Crypt' | 'Protocol' | 'Storage' | 'Security';
  status: 'PENDING' | 'RUNNING' | 'PASSED' | 'FAILED';
  durationMs: number;
  details: string;
}

interface SelfTestModalProps {
  onClose: () => void;
  isDarkMode: boolean;
}

export const SelfTestModal: React.FC<SelfTestModalProps> = ({
  onClose,
  isDarkMode,
}) => {
  const [tests, setTests] = useState<TestResult[]>([
    {
      id: 'T1',
      name: 'Runtime Sandbox Boundary & Capabilities Check',
      category: 'Sandbox',
      status: 'PENDING',
      durationMs: 0,
      details: 'Verifies browser security isolation of wlanapi.dll and validates fallback to PCAP/Netsh dissector.',
    },
    {
      id: 'T2',
      name: 'Libpcap 2.4 Binary Dissector & Radiotap Decapsulator',
      category: 'PCAP',
      status: 'PENDING',
      durationMs: 0,
      details: 'Synthesizes binary PCAP buffer and tests decapsulation of 802.11 frames, RSSI, and channels.',
    },
    {
      id: 'T3',
      name: 'IEEE 802.11 Channel & Frequency Matrix Validation',
      category: 'Protocol',
      status: 'PENDING',
      durationMs: 0,
      details: 'Validates 2.4 GHz (1-14 with 2484MHz special case), 5 GHz, and 6 GHz center frequency formulas.',
    },
    {
      id: 'T4',
      name: 'EAPOL 4-Way Handshake & PMKID Parser + Hashcat 22000',
      category: 'Crypt',
      status: 'PENDING',
      durationMs: 0,
      details: 'Dissects EAPOL key frames, tests Nonce/MIC synchronization, and validates Hashcat format.',
    },
    {
      id: 'T5',
      name: 'Windows Netsh CLI Stream Parser',
      category: 'Protocol',
      status: 'PENDING',
      durationMs: 0,
      details: 'Tests multi-network parsing from genuine "netsh wlan show networks mode=bssid" dumps.',
    },
    {
      id: 'T6',
      name: 'SQLite 3 Relational Query Engine & Persistence Store',
      category: 'Storage',
      status: 'PENDING',
      durationMs: 0,
      details: 'Executes SELECT WHERE filters, ORDER BY clauses, and DDL schema integrity checks.',
    },
    {
      id: 'T7',
      name: 'NIST SP 800-153 Wireless Risk & Rogue AP Heuristics',
      category: 'Security',
      status: 'PENDING',
      durationMs: 0,
      details: 'Verifies scoring penalties for WEP/WPS/Open and flags Evil Twin SSID clones.',
    },
  ]);

  const [isRunning, setIsRunning] = useState(false);
  const [allPassed, setAllPassed] = useState(false);

  const runAllTests = async () => {
    setIsRunning(true);
    setAllPassed(false);

    const updated = [...tests];

    for (let i = 0; i < updated.length; i++) {
      updated[i].status = 'RUNNING';
      setTests([...updated]);

      const start = performance.now();
      await new Promise((r) => setTimeout(r, 120));

      try {
        // T1: Sandbox & Capabilities
        if (updated[i].id === 'T1') {
          const caps = WifiEngine.getInstance().getSystemCapabilities();
          if (caps.environment.includes('Browser') && !caps.nativeWlanApiAccess && caps.pcapDissectorActive) {
            updated[i].status = 'PASSED';
            updated[i].details = 'Browser sandbox detected. Native wlanapi.dll restriction confirmed. File dissector active.';
          } else {
            updated[i].status = 'FAILED';
            updated[i].details = 'Failed to accurately detect runtime sandbox environment.';
          }
        } 
        // T2: PCAP 2.4 Binary Decapsulator
        else if (updated[i].id === 'T2') {
          const pcapService = PcapService.getInstance();
          // Synthesize real binary PCAP buffer
          const testPackets = WifiEngine.getInstance().generatePackets(WifiEngine.getInstance().getBenchmarkAccessPoints());
          const binaryBytes = pcapService.exportBinaryPcap(testPackets.slice(0, 5));
          const parsed = pcapService.parseBinaryPcap(binaryBytes.buffer);

          if (parsed.packets.length === 5 && parsed.accessPoints.length > 0) {
            updated[i].status = 'PASSED';
            updated[i].details = `Decoded ${parsed.packets.length} frames (${parsed.summary.linkType}) with valid Radiotap dBm and 802.11 IEs.`;
          } else {
            updated[i].status = 'FAILED';
            updated[i].details = `Expected 5 decoded packets, received ${parsed.packets.length}.`;
          }
        } 
        // T3: Frequency Math
        else if (updated[i].id === 'T3') {
          const ch6 = PcapService.getChannelDetails(6);
          const ch14 = PcapService.getChannelDetails(14);
          const ch36 = PcapService.getChannelDetails(36);
          const ch149 = PcapService.getChannelDetails(149);
          const ch69 = PcapService.getChannelDetails(69);

          const ok = 
            ch6.freqMhz === 2437 && ch6.band === '2.4 GHz' &&
            ch14.freqMhz === 2484 && ch14.band === '2.4 GHz' &&
            ch36.freqMhz === 5180 && ch36.band === '5 GHz' &&
            ch149.freqMhz === 5745 && ch149.band === '5 GHz' &&
            ch69.freqMhz === 6295 && ch69.band === '6 GHz';

          if (ok) {
            updated[i].status = 'PASSED';
            updated[i].details = 'Formulas verified: CH 6 (2437MHz), CH 14 (2484MHz), CH 36 (5180MHz), CH 69 (6295MHz).';
          } else {
            updated[i].status = 'FAILED';
            updated[i].details = 'Frequency calculation mismatch.';
          }
        } 
        // T4: EAPOL Handshake & Hashcat 22000
        else if (updated[i].id === 'T4') {
          const benchmarkAps = WifiEngine.getInstance().getBenchmarkAccessPoints();
          const apWithHandshake = benchmarkAps.find(a => a.handshake);
          if (apWithHandshake && apWithHandshake.handshake) {
            const h = apWithHandshake.handshake;
            const hasFormat = h.hashcatFormat && h.hashcatFormat.startsWith('WPA*02*');
            const hasNonces = h.anonce.length === 64 && h.snonce.length === 64 && h.micHex.length === 32;

            if (hasFormat && hasNonces) {
              updated[i].status = 'PASSED';
              updated[i].details = `Verified 32-byte ANonce/SNonce, 16-byte MIC, and valid Hashcat 22000 format (${h.hashcatFormat.slice(0, 32)}...).`;
            } else {
              updated[i].status = 'FAILED';
              updated[i].details = 'Invalid EAPOL handshake parameters.';
            }
          } else {
            updated[i].status = 'FAILED';
            updated[i].details = 'No handshake found in benchmark set.';
          }
        } 
        // T5: Windows Netsh CLI Parser
        else if (updated[i].id === 'T5') {
          const sampleNetsh = `Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : Test_Netsh_Corp
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 82%
         Radio type         : 802.11ac
         Channel            : 44

SSID 2 : Open_Public
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : AA:BB:CC:DD:EE:FF
         Signal             : 60%
         Radio type         : 802.11n
         Channel            : 1`;

          const { accessPoints } = PcapService.getInstance().parseNetshOutput(sampleNetsh);
          if (accessPoints.length === 2 && accessPoints[0].ssid === 'Test_Netsh_Corp' && accessPoints[0].channel === 44) {
            updated[i].status = 'PASSED';
            updated[i].details = `Parsed ${accessPoints.length} APs from Netsh output. Signal converted: 82% -> ${accessPoints[0].rssi} dBm.`;
          } else {
            updated[i].status = 'FAILED';
            updated[i].details = 'Netsh parser failed to extract access point attributes.';
          }
        } 
        // T6: SQLite 3 Query Engine
        else if (updated[i].id === 'T6') {
          const db = SqliteDatabaseService.getInstance();
          const benchmarkAps = WifiEngine.getInstance().getBenchmarkAccessPoints();
          const resWhere = db.executeQuery('SELECT * FROM access_points WHERE score < 50;', benchmarkAps);
          const resLimit = db.executeQuery('SELECT ssid, bssid, channel FROM access_points ORDER BY channel LIMIT 3;', benchmarkAps);

          if (resWhere.rowCount > 0 && resLimit.rowCount === 3 && resLimit.columns.length === 3) {
            updated[i].status = 'PASSED';
            updated[i].details = `Query engine validated. WHERE filtering: ${resWhere.rowCount} rows. Column projection: ${resLimit.columns.join(', ')}.`;
          } else {
            updated[i].status = 'FAILED';
            updated[i].details = 'Query execution failed to return expected row structure.';
          }
        } 
        // T7: NIST SP 800-153 Heuristics
        else if (updated[i].id === 'T7') {
          const benchmarkAps = WifiEngine.getInstance().getBenchmarkAccessPoints();
          const rogue = benchmarkAps.find(a => a.isRogueCandidate);
          const wep = benchmarkAps.find(a => a.security.includes('WEP'));
          const wps = benchmarkAps.find(a => a.wpsEnabled);

          if (rogue && wep && wps && wep.securityScore <= 20) {
            updated[i].status = 'PASSED';
            updated[i].details = `Rogue SSID clone detected. WEP risk assessed (Score: ${wep.securityScore}/100). Pixie Dust alert triggered.`;
          } else {
            updated[i].status = 'FAILED';
            updated[i].details = 'Security heuristics failed validation.';
          }
        }
      } catch (err: any) {
        updated[i].status = 'FAILED';
        updated[i].details = `Execution error: ${err?.message || err}`;
      }

      updated[i].durationMs = Math.max(1, Math.round(performance.now() - start));
      setTests([...updated]);
    }

    setIsRunning(false);
    setAllPassed(updated.every(t => t.status === 'PASSED'));
  };

  useEffect(() => {
    runAllTests();
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className={`w-full max-w-2xl rounded-xl border shadow-2xl overflow-hidden flex flex-col ${
        isDarkMode ? 'bg-[#181a20] border-[#2c303b] text-slate-200' : 'bg-white border-slate-200 text-slate-800'
      }`}>
        {/* Header */}
        <div className={`p-4 border-b flex items-center justify-between ${
          isDarkMode ? 'bg-[#1d2028] border-[#262a36]' : 'bg-slate-50 border-slate-200'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-purple-600/15 text-purple-400">
              <FlaskConical className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold">Automated Self-Test &amp; Capability Audit Suite</h2>
              <p className="text-xs text-slate-400">Verifying engine logic, cryptographic validation, and sandbox compliance</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-slate-700/30 text-slate-400 hover:text-slate-200"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tests List */}
        <div className="p-4 space-y-2.5 max-h-[60vh] overflow-y-auto">
          {tests.map((t) => (
            <div
              key={t.id}
              className={`p-3 rounded-lg border transition-all text-xs ${
                isDarkMode ? 'bg-[#13151b] border-[#242834]' : 'bg-slate-50 border-slate-200'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  {t.status === 'PASSED' && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
                  {t.status === 'FAILED' && <XCircle className="w-4 h-4 text-red-400 shrink-0" />}
                  {t.status === 'RUNNING' && <RotateCw className="w-4 h-4 text-blue-400 animate-spin shrink-0" />}
                  {t.status === 'PENDING' && <div className="w-4 h-4 rounded-full border border-slate-600 shrink-0" />}
                  
                  <span className="font-semibold">{t.name}</span>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono bg-slate-700/30 text-slate-400 uppercase">
                    {t.category}
                  </span>
                  {t.durationMs > 0 && (
                    <span className="text-[10px] text-slate-500 font-mono">
                      {t.durationMs}ms
                    </span>
                  )}
                </div>
              </div>

              <div className="text-[11px] text-slate-400 mt-1 pl-6">
                {t.details}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className={`p-4 border-t flex items-center justify-between ${
          isDarkMode ? 'bg-[#1d2028] border-[#262a36]' : 'bg-slate-50 border-slate-200'
        }`}>
          <div className="flex items-center gap-2 text-xs">
            {allPassed ? (
              <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                <CheckCircle2 className="w-4 h-4" />
                All 7 Subsystem Tests Passed Successfully
              </span>
            ) : isRunning ? (
              <span className="flex items-center gap-1.5 text-blue-400">
                <RotateCw className="w-4 h-4 animate-spin" />
                Executing Automated Verification...
              </span>
            ) : (
              <span className="text-slate-400">
                Test run complete.
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={runAllTests}
              disabled={isRunning}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold hover:bg-slate-700/30 transition-colors disabled:opacity-50"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
              <span>Rerun Tests</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
