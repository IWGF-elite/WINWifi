import React, { useState } from 'react';
import { AccessPoint, FrequencyBand, DataSourceProfile } from '../types';
import { Activity, Radio, Info, AlertTriangle, ShieldCheck, Sparkles } from 'lucide-react';

interface SpectrumVisualizerProps {
  accessPoints: AccessPoint[];
  selectedBssid: string | null;
  onSelectAp: (bssid: string) => void;
  isDarkMode?: boolean;
  dataSourceProfile?: DataSourceProfile;
}

export const SpectrumVisualizer: React.FC<SpectrumVisualizerProps> = ({
  accessPoints = [],
  selectedBssid,
  onSelectAp,
  isDarkMode = true,
  dataSourceProfile = 'OFFLINE',
}) => {
  const [band, setBand] = useState<FrequencyBand>('2.4 GHz');

  // Filter access points by active spectrum band
  const filteredAps = (accessPoints || []).filter((ap) => ap.band === band);

  // Channels definition for visualization
  const channels24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
  const channels50 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];
  const channels60 = [1, 5, 9, 17, 33, 49, 65, 81, 97, 113, 129, 145, 161, 177, 193, 209, 225];

  const currentChannels = band === '2.4 GHz' ? channels24 : band === '5 GHz' ? channels50 : channels60;

  // Chart coordinate helpers
  const svgWidth = 960;
  const svgHeight = 340;
  const paddingX = 60;
  const paddingBottom = 50;
  const paddingTop = 35;

  const minRssi = -100;
  const maxRssi = -30;

  const getXForChannel = (ch: number): number => {
    const idx = currentChannels.indexOf(ch);
    if (idx === -1) {
      const first = currentChannels[0];
      const last = currentChannels[currentChannels.length - 1];
      const ratio = Math.max(0, Math.min(1, (ch - first) / (last - first)));
      return paddingX + ratio * (svgWidth - paddingX * 2);
    }
    const ratio = idx / (currentChannels.length - 1);
    return paddingX + ratio * (svgWidth - paddingX * 2);
  };

  const getYForRssi = (rssi: number): number => {
    const clamped = Math.max(minRssi, Math.min(maxRssi, rssi));
    const ratio = (clamped - minRssi) / (maxRssi - minRssi);
    const usableHeight = svgHeight - paddingTop - paddingBottom;
    return svgHeight - paddingBottom - ratio * usableHeight;
  };

  const getApColor = (ap: AccessPoint): string => {
    if (ap.isRogueCandidate) return '#ef4444'; // Red
    if (ap.security.includes('Open') || ap.security.includes('WEP')) return '#f97316'; // Orange
    if (ap.security.includes('WPA3')) return '#10b981'; // Green
    if (ap.security.includes('Enterprise')) return '#6366f1'; // Indigo
    return '#3b82f6'; // Blue
  };

  // Identify DFS channels on 5GHz (channels 52 through 144)
  const isDfsChannel = (ch: number): boolean => {
    return band === '5 GHz' && ch >= 52 && ch <= 144;
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
      {/* Header & Band switch tabs */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              <span>RF Channel Allocation &amp; Signal Footprint Model</span>
            </h3>
            <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 text-[10px] font-mono">
              BEACON-DERIVED MODEL
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Visualizes 802.11 channel allocations, channel widths (20/40/80/160 MHz), and co-channel overlap calculated from beacon telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-800 border border-slate-700 text-xs">
            {(['2.4 GHz', '5 GHz', '6 GHz'] as FrequencyBand[]).map((b) => (
              <button
                key={b}
                onClick={() => setBand(b)}
                className={`px-3 py-1 rounded-md font-semibold transition-all ${
                  band === b
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {b}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Technical Notice Banner */}
      <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3 text-xs text-slate-400 flex items-start gap-2.5">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div className="text-[11px] leading-relaxed">
          <strong className="text-slate-300">Hardware Spectrum Boundary:</strong> Curves represent calibrated 802.11 channel footprints modeled from Beacon and Probe Response parameters (RSSI dBm, channel width). 
          Raw continuous physical RF energy (non-Wi-Fi interference, microwave ovens, analog sensors, noise floor) requires a dedicated SDR receiver (e.g. Wi-Spy, HackRF) as standard 802.11 NICs demodulate valid preambles only.
        </div>
      </div>

      {/* SVG Canvas for RF Curves */}
      <div className="overflow-x-auto bg-slate-950/40 rounded-lg border border-slate-800/80 p-2">
        {filteredAps.length === 0 ? (
          <div className="py-16 text-center space-y-2">
            <Radio className="w-8 h-8 text-slate-600 mx-auto" />
            <div className="font-semibold text-slate-400 text-xs">
              No 802.11 Transmitters Discovered on {band}
            </div>
            <div className="text-[11px] text-slate-500 max-w-sm mx-auto">
              No BSS beacons or probe responses were observed on this frequency band in the active dataset.
            </div>
          </div>
        ) : (
          <svg
            viewBox={`0 0 ${svgWidth} ${svgHeight}`}
            className="w-full h-auto min-w-[760px] select-none"
          >
            {/* DFS Region shading on 5 GHz */}
            {band === '5 GHz' && (
              <g>
                <rect
                  x={getXForChannel(52) - 20}
                  y={paddingTop}
                  width={getXForChannel(144) - getXForChannel(52) + 40}
                  height={svgHeight - paddingTop - paddingBottom}
                  fill="#3b82f6"
                  fillOpacity="0.04"
                />
                <text
                  x={(getXForChannel(52) + getXForChannel(144)) / 2}
                  y={paddingTop + 14}
                  textAnchor="middle"
                  fontSize="10"
                  fill="#60a5fa"
                  fontFamily="monospace"
                  fontWeight="600"
                >
                  DFS (DYNAMIC FREQUENCY SELECTION) REGION (CH 52–144)
                </text>
              </g>
            )}

            {/* Background Grid Lines (dBm levels) */}
            {[-90, -80, -70, -60, -50, -40, -30].map((dbm) => {
              const y = getYForRssi(dbm);
              return (
                <g key={dbm}>
                  <line
                    x1={paddingX}
                    y1={y}
                    x2={svgWidth - paddingX}
                    y2={y}
                    stroke="#1e293b"
                    strokeDasharray="4 4"
                    strokeWidth="1"
                  />
                  <text
                    x={paddingX - 10}
                    y={y + 4}
                    textAnchor="end"
                    fontSize="10"
                    fill="#64748b"
                    fontFamily="monospace"
                  >
                    {dbm} dBm
                  </text>
                </g>
              );
            })}

            {/* Vertical Channel Axis lines & Labels */}
            {currentChannels.map((ch) => {
              const x = getXForChannel(ch);
              const isDfs = isDfsChannel(ch);
              return (
                <g key={ch}>
                  <line
                    x1={x}
                    y1={paddingTop}
                    x2={x}
                    y2={svgHeight - paddingBottom}
                    stroke="#1e293b"
                    strokeWidth="1"
                  />
                  <text
                    x={x}
                    y={svgHeight - paddingBottom + 16}
                    textAnchor="middle"
                    fontSize="10"
                    fontWeight="600"
                    fill={isDfs ? '#60a5fa' : '#94a3b8'}
                    fontFamily="monospace"
                  >
                    {ch}
                  </text>
                  {isDfs && (
                    <text
                      x={x}
                      y={svgHeight - paddingBottom + 27}
                      textAnchor="middle"
                      fontSize="8"
                      fill="#3b82f6"
                      fontFamily="monospace"
                    >
                      DFS
                    </text>
                  )}
                </g>
              );
            })}

            {/* Access Point RF Bell Curves */}
            {filteredAps.map((ap) => {
              const peakX = getXForChannel(ap.channel);
              const peakY = getYForRssi(ap.rssi);
              const baseY = svgHeight - paddingBottom;
              const isSelected = ap.bssid === selectedBssid;
              const color = getApColor(ap);

              // Width of bell curve based on channel bandwidth (20MHz, 40MHz, 80MHz, 160MHz)
              const spreadWidth = band === '2.4 GHz' ? 52 : (ap.channelWidthMhz / 20) * 32;
              const leftX = peakX - spreadWidth;
              const rightX = peakX + spreadWidth;

              // Smooth cubic bezier curve for RF footprint
              const pathData = `
                M ${leftX} ${baseY}
                C ${leftX + spreadWidth * 0.4} ${baseY}, ${peakX - spreadWidth * 0.3} ${peakY}, ${peakX} ${peakY}
                C ${peakX + spreadWidth * 0.3} ${peakY}, ${rightX - spreadWidth * 0.4} ${baseY}, ${rightX} ${baseY}
                Z
              `;

              return (
                <g
                  key={ap.bssid}
                  className="cursor-pointer transition-opacity"
                  style={{ opacity: selectedBssid ? (isSelected ? 1 : 0.35) : 0.85 }}
                  onClick={() => onSelectAp(ap.bssid)}
                >
                  {/* Curve Fill */}
                  <path
                    d={pathData}
                    fill={color}
                    fillOpacity={isSelected ? 0.38 : 0.18}
                    stroke={color}
                    strokeWidth={isSelected ? 2.5 : 1.5}
                  />

                  {/* Peak Indicator Dot */}
                  <circle
                    cx={peakX}
                    cy={peakY}
                    r={isSelected ? 4.5 : 3}
                    fill={color}
                    stroke="#0f172a"
                    strokeWidth="1.5"
                  />

                  {/* Label above peak */}
                  <text
                    x={peakX}
                    y={peakY - 8}
                    textAnchor="middle"
                    fontSize="10"
                    fontWeight={isSelected ? 'bold' : 'normal'}
                    fill="#f1f5f9"
                  >
                    {ap.ssid || '[Hidden SSID]'}
                  </text>
                  <text
                    x={peakX}
                    y={peakY - 20}
                    textAnchor="middle"
                    fontSize="9"
                    fontFamily="monospace"
                    fill={color}
                  >
                    {ap.rssi} dBm ({ap.channelWidthMhz}MHz)
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>

      {/* Legend & Channel Allocations */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-[11px] pt-3 border-t border-slate-800 text-slate-400">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-semibold text-slate-300 flex items-center gap-1">
            <Info className="w-3.5 h-3.5 text-blue-400" />
            <span>Security Legend:</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500" /> WPA3 SAE
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-indigo-500" /> Enterprise 802.1X
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-blue-500" /> WPA2-Personal
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-500" /> Open / WEP
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500" /> Suspected Rogue AP
          </span>
        </div>

        <div className="text-[10px] font-mono text-slate-500">
          {band === '2.4 GHz' ? 'Non-overlapping channels: 1, 6, 11' : band === '5 GHz' ? '80 MHz channels: 36, 52, 100, 116, 132, 149' : '6 GHz Wi-Fi 6E / 7 U-NII 5–8'}
        </div>
      </div>
    </div>
  );
};
