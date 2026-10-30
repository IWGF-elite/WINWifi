import React from 'react';
import {
  Activity,
  BellRing,
  Building2,
  Clock3,
  Cpu,
  FileCheck,
  FileText,
  Flame,
  KeyRound,
  Laptop,
  LayoutDashboard,
  Layers,
  MapPin,
  Sliders,
  GraduationCap,
  SlidersHorizontal,
  Wifi,
  type LucideIcon,
} from 'lucide-react';
import type { ActiveTab, UIMode } from '../types';
import { WinWiFiLogo } from './WinWiFiLogo';

interface AppSidebarProps {
  activeTab: ActiveTab;
  uiMode: UIMode;
  isScanning: boolean;
  bridgeConnected: boolean;
  accessPointCount: number;
  rogueCount: number;
  activeAlertCount: number;
  openIncidentCount: number;
  packetCount: number;
  handshakeCount: number;
  onNavigate: (tab: ActiveTab) => void;
  onSelectUIMode: (mode: UIMode) => void;
}

interface SidebarItem {
  id: ActiveTab;
  label: string;
  icon: LucideIcon;
  selectedFor?: ActiveTab[];
  count?: number;
  showZero?: boolean;
}

export const AppSidebar: React.FC<AppSidebarProps> = ({
  activeTab,
  uiMode,
  isScanning,
  bridgeConnected,
  accessPointCount,
  rogueCount,
  activeAlertCount,
  openIncidentCount,
  packetCount,
  handshakeCount,
  onNavigate,
  onSelectUIMode,
}) => {
  const groups: { label: string; items: SidebarItem[] }[] = [
    {
      label: 'OVERVIEW',
      items: [
        { id: 'dashboard', label: 'Command Center', icon: LayoutDashboard },
        { id: 'networks', label: 'Network Inventory', icon: Wifi, selectedFor: ['discovery', 'discover'], count: accessPointCount, showZero: true },
        { id: 'clients', label: 'Client Devices', icon: Laptop },
      ],
    },
    {
      label: 'MONITORING',
      items: [
        { id: 'doctor', label: 'Network Diagnostics', icon: Activity },
        { id: 'time-machine', label: 'Scan History', icon: Clock3 },
        { id: 'walk-mode', label: 'Signal Survey', icon: MapPin },
        { id: 'spectrum', label: 'Spectrum Analysis', icon: Activity, selectedFor: ['rf'] },
      ],
    },
    {
      label: 'SECURITY',
      items: [
        { id: 'threats', label: 'Threat Detection', icon: Flame, count: rogueCount },
        { id: 'alerts', label: 'Security Alerts', icon: BellRing, count: activeAlertCount },
        { id: 'investigations', label: 'Incident Management', icon: FileText, count: openIncidentCount, showZero: true },
        { id: 'packets', label: 'Packet Analysis', icon: Layers, selectedFor: ['forensics'], count: packetCount, showZero: true },
        { id: 'handshakes', label: 'Handshake Analysis', icon: KeyRound, count: handshakeCount },
      ],
    },
    {
      label: 'MANAGE',
      items: [
        { id: 'projects', label: 'Projects & Scope', icon: Building2, selectedFor: ['database'] },
        { id: 'reports', label: 'Reports', icon: FileCheck },
        { id: 'devices', label: 'Hardware', icon: Cpu },
        { id: 'settings', label: 'Settings & Lab', icon: Sliders },
        { id: 'native-desktop', label: 'System Capabilities', icon: Laptop },
      ],
    },
  ];

  return (
    <aside className="winwifi-sidebar" aria-label="Main navigation">
      <div className="winwifi-sidebar-brand">
        <WinWiFiLogo className="winwifi-sidebar-logo" />
        <div className="winwifi-sidebar-brand-copy">
          <div className="winwifi-sidebar-brand-name">WINWIFI</div>
          <div className="winwifi-sidebar-brand-subtitle">SECURITY AUDITOR</div>
        </div>
      </div>

      <div className="winwifi-sidebar-scroll">
        {groups.map(group => (
          <section className="winwifi-sidebar-group" key={group.label} aria-label={group.label}>
            <h2 className="winwifi-sidebar-heading">{group.label}</h2>
            {group.items.map(item => {
              const Icon = item.icon;
              const selected = item.id === activeTab || item.selectedFor?.includes(activeTab) === true;
              const showCount = item.count !== undefined && (item.showZero || item.count > 0);
              return (
                <button
                  className={`winwifi-sidebar-link${selected ? ' is-active' : ''}`}
                  key={item.id}
                  type="button"
                  aria-current={selected ? 'page' : undefined}
                  title={item.label}
                  onClick={() => onNavigate(item.id)}
                >
                  <Icon className="winwifi-sidebar-icon" aria-hidden="true" />
                  <span className="winwifi-sidebar-label">{item.label}</span>
                  {showCount && <span className="winwifi-sidebar-count">{item.count}</span>}
                </button>
              );
            })}
          </section>
        ))}
      </div>

      <div className="winwifi-sidebar-footer">
        <div className="winwifi-sidebar-status" role="status" title={bridgeConnected ? (isScanning ? 'Windows bridge connected; live scan active' : 'Windows bridge connected; scan stopped') : 'Windows bridge unavailable'}>
          <span className={`winwifi-sidebar-status-dot${bridgeConnected ? ' is-connected' : ' is-offline'}`} />
          <span className="winwifi-sidebar-status-copy">
            <strong>{bridgeConnected ? 'Bridge connected' : 'Bridge offline'}</strong>
            <small>{bridgeConnected ? (isScanning ? 'Live scan active' : 'Scan paused') : 'Waiting for connection'}</small>
          </span>
        </div>
        <div className="winwifi-sidebar-mode" role="group" aria-label="Display mode">
          <div className="winwifi-sidebar-mode-heading">
            <span>DISPLAY MODE</span>
            <small>{uiMode === 'beginner' ? 'GUIDED' : 'FULL DETAIL'}</small>
          </div>
          <div className="winwifi-mode-segments">
            <button
              type="button"
              className={`winwifi-mode-option${uiMode === 'beginner' ? ' is-selected' : ''}`}
              aria-pressed={uiMode === 'beginner'}
              title="Beginner: plain-language summaries and a simpler view"
              onClick={() => onSelectUIMode('beginner')}
            >
              <GraduationCap aria-hidden="true" />
              <span>Beginner</span>
            </button>
            <button
              type="button"
              className={`winwifi-mode-option${uiMode === 'expert' ? ' is-selected' : ''}`}
              aria-pressed={uiMode === 'expert'}
              title="Expert: full technical fields, evidence, and live diagnostics"
              onClick={() => onSelectUIMode('expert')}
            >
              <SlidersHorizontal aria-hidden="true" />
              <span>Expert</span>
            </button>
          </div>
          <p className="winwifi-sidebar-mode-note">
            {uiMode === 'beginner' ? 'Plain language · guided actions' : 'Technical detail · full evidence'}
          </p>
        </div>
      </div>
    </aside>
  );
};
