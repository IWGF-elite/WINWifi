import { AccessPoint, IncidentRecord, SecurityChange, TimelineEvent } from '../types';

export class ThreatEngine {
  private static instance: ThreatEngine;
  private knownGoodBaselines: Set<string> = new Set(['00:11:22:33:44:00', '00:11:22:33:44:01', '00:11:22:33:44:02']);
  private trustedOverrides: Set<string> = new Set();
  private confirmedRogues: Set<string> = new Set();
  private falsePositives: Set<string> = new Set();
  private incidents: IncidentRecord[] = [];
  private securityChanges: SecurityChange[] = [];
  private timelineEvents: TimelineEvent[] = [];
  private previousApStates: Map<string, { security: string; channel: number; vendor: string }> = new Map();

  public static getInstance(): ThreatEngine {
    if (!ThreatEngine.instance) {
      ThreatEngine.instance = new ThreatEngine();
      ThreatEngine.instance.initDefaultIncidents();
    }
    return ThreatEngine.instance;
  }

  private initDefaultIncidents() {
    this.incidents = [
      {
        id: 'INC-00042',
        title: 'Suspected Evil Twin: Unauthorized Clone of "Meridian_Guest_Portal"',
        severity: 'CRITICAL',
        confidence: 96,
        status: 'Investigating',
        createdAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
        updatedAt: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
        assignedTo: 'Lead Security Auditor (Marcus Vance)',
        summary: 'Detected duplicate SSID "Meridian_Guest_Portal" on unauthorized Shenzhen Bilian OUI (6C:5E:7A:B2:90:1C) broadcasting on Floor 14 with +8 dBm signal delta.',
        bssidTarget: '6C:5E:7A:B2:90:1C',
        ssidTarget: 'Meridian_Guest_Portal',
        evidenceIds: ['EVD-001', 'EVD-002', 'EVD-005'],
        notes: [
          { timestamp: new Date(Date.now() - 1000 * 60 * 30).toLocaleTimeString(), author: 'ThreatEngine', text: 'Automatic anomaly flag: OUI manufacturer mismatch ("Shenzhen Bilian" vs authorized "Aruba Networks") on 2.4 GHz Ch 6.' },
          { timestamp: new Date(Date.now() - 1000 * 60 * 12).toLocaleTimeString(), author: 'Marcus Vance', text: 'Triangulated physical RF signature near Floor 14 Conference Room 1402. Investigating rogue physical device.' }
        ]
      },
      {
        id: 'INC-00038',
        title: 'Legacy WEP-128 Protocol Active on Sub-Basement Warehouse Bay',
        severity: 'HIGH',
        confidence: 100,
        status: 'Open',
        createdAt: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
        updatedAt: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
        assignedTo: 'Facilities IT Operations',
        summary: 'Depot inventory scanner network using deprecated WEP-128 encryption. Violates PCI-DSS 4.0 Requirement 2.1 and NIST SP 800-153 §4.2.',
        bssidTarget: '00:14:D1:6C:5B:99',
        ssidTarget: 'Warehouse_Logistics_B4',
        evidenceIds: ['EVD-003'],
        notes: [
          { timestamp: new Date(Date.now() - 1000 * 60 * 120).toLocaleTimeString(), author: 'ThreatEngine', text: 'Automated policy violation flagged: Deprecated RC4 cipher with static 24-bit initialization vectors.' }
        ]
      },
      {
        id: 'INC-00045',
        title: 'WPS 1.0 External Registrar Active on Executive Boardroom AP',
        severity: 'HIGH',
        confidence: 90,
        status: 'Investigating',
        createdAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
        updatedAt: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
        assignedTo: 'Lead Security Auditor (Marcus Vance)',
        summary: 'NETGEAR extender (F8:1A:67:8B:11:02) advertising active Wi-Fi Protected Setup PIN negotiation susceptible to offline Pixie Dust nonce recovery.',
        bssidTarget: 'F8:1A:67:8B:11:02',
        ssidTarget: 'NETGEAR_Executive_Suite',
        evidenceIds: ['EVD-004', 'EVD-007'],
        notes: [
          { timestamp: new Date(Date.now() - 1000 * 60 * 40).toLocaleTimeString(), author: 'ThreatEngine', text: 'Detected WPS 1.0 beacon information element with unrandomized E-S1/E-S2 nonces.' }
        ]
      },
      {
        id: 'INC-00049',
        title: 'Unmonitored Wi-Fi Direct P2P Broadcast on Multi-Function Printer',
        severity: 'MEDIUM',
        confidence: 88,
        status: 'Open',
        createdAt: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
        updatedAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
        assignedTo: 'SecOps Team',
        summary: 'HP LaserJet Enterprise printer broadcasting ad-hoc P2P network DIRECT-HP-LaserJet-M608 without client isolation.',
        bssidTarget: '70:5A:0F:84:33:10',
        ssidTarget: 'DIRECT-HP-LaserJet-M608',
        evidenceIds: ['EVD-009'],
        notes: [
          { timestamp: new Date(Date.now() - 1000 * 60 * 85).toLocaleTimeString(), author: 'ThreatEngine', text: 'Wi-Fi Direct ad-hoc beacon detected on production 2.4 GHz spectrum.' }
        ]
      }
    ];

    this.securityChanges = [
      {
        id: 'CHG-101',
        bssid: '6C:5E:7A:B2:90:1C',
        ssid: 'Meridian_Guest_Portal',
        timestamp: new Date(Date.now() - 1000 * 60 * 35).toLocaleTimeString(),
        type: 'new_bssid',
        title: 'New Unrecognized BSSID Appeared',
        before: 'Not in Baseline',
        after: 'Active Broadcast on Ch 6 (Shenzhen Bilian)',
        riskImpact: 'CRITICAL',
        evidenceIds: ['EVD-001']
      },
      {
        id: 'CHG-102',
        bssid: 'F8:1A:67:8B:11:02',
        ssid: 'NETGEAR_Executive_Suite',
        timestamp: new Date(Date.now() - 1000 * 60 * 75).toLocaleTimeString(),
        type: 'wps_change',
        title: 'WPS 1.0 External Registrar Activated',
        before: 'WPS Disabled',
        after: 'WPS PIN Enabled & Unlocked',
        riskImpact: 'HIGH',
        evidenceIds: ['EVD-004']
      },
      {
        id: 'CHG-103',
        bssid: '70:5A:0F:84:33:10',
        ssid: 'DIRECT-HP-LaserJet-M608',
        timestamp: new Date(Date.now() - 1000 * 60 * 95).toLocaleTimeString(),
        type: 'new_bssid',
        title: 'Ad-Hoc Wi-Fi Direct Beacon Detected',
        before: 'Offline / Standby',
        after: 'Active P2P Broadcast on Ch 6',
        riskImpact: 'MEDIUM',
        evidenceIds: ['EVD-009']
      }
    ];
  }

  public analyzeThreats(accessPoints: AccessPoint[]): {
    rogues: AccessPoint[];
    changes: SecurityChange[];
    timeline: TimelineEvent[];
  } {
    const rogues: AccessPoint[] = [];
    const newChanges: SecurityChange[] = [];

    // Group APs by normalized SSID
    const ssidGroups = new Map<string, AccessPoint[]>();
    for (const ap of accessPoints) {
      const key = ap.ssid?.trim();
      if (!key || key === '[Hidden SSID]') continue;
      if (!ssidGroups.has(key)) ssidGroups.set(key, []);
      ssidGroups.get(key)!.push(ap);
    }

    // 1. Rogue AP / Evil Twin Multi-Factor Correlation
    for (const [ssid, group] of ssidGroups.entries()) {
      if (group.length > 1) {
        // Compare every pair
        for (let i = 0; i < group.length; i++) {
          for (let j = i + 1; j < group.length; j++) {
            const ap1 = group[i];
            const ap2 = group[j];

            // Evaluate divergence
            const hasSecDiff = ap1.security !== ap2.security;
            const hasCipherDiff = ap1.cipher !== ap2.cipher;
            const hasVendorDiff = ap1.vendor !== ap2.vendor && ap1.vendor !== 'Unknown' && ap2.vendor !== 'Unknown';
            const hasBandDiff = ap1.band !== ap2.band;

            if (hasSecDiff || hasCipherDiff || (hasVendorDiff && hasSecDiff)) {
              // The AP with weaker security or unapproved status is the suspected rogue
              const suspect = (ap1.securityScore < ap2.securityScore) ? ap1 : ap2;
              const legit = (suspect === ap1) ? ap2 : ap1;

              if (this.falsePositives.has(suspect.bssid)) {
                suspect.classification = 'Trusted';
                suspect.isRogueCandidate = false;
                continue;
              }

              suspect.isRogueCandidate = true;
              suspect.classification = this.confirmedRogues.has(suspect.bssid) ? 'Rogue' : 'Suspicious';

              // Calculate confidence score (0-100%)
              let confidence = 50;
              const evidence: string[] = [];
              evidence.push(`Identical SSID "${ssid}" shared with peer AP ${legit.bssid}`);

              if (hasSecDiff) {
                confidence += 25;
                evidence.push(`Security suite downgraded from ${legit.security} to ${suspect.security}`);
              }
              if (hasVendorDiff) {
                confidence += 15;
                evidence.push(`Hardware OUI mismatch: "${suspect.vendor}" vs authorized "${legit.vendor}"`);
              }
              if (hasBandDiff) {
                confidence += 10;
                evidence.push(`Unexpected RF channel/band deployment (${suspect.band} Ch ${suspect.channel} vs ${legit.band} Ch ${legit.channel})`);
              }

              suspect.rogueConfidence = Math.min(99, confidence);
              suspect.rogueEvidence = evidence;
              rogues.push(suspect);

              // Check if an incident already exists
              if (!this.incidents.some(inc => inc.bssidTarget === suspect.bssid)) {
                this.createIncident({
                  title: `Suspicious Rogue Clone: "${ssid}" (${suspect.bssid})`,
                  severity: 'CRITICAL',
                  confidence: suspect.rogueConfidence,
                  bssid: suspect.bssid,
                  ssid,
                  summary: evidence.join('; ')
                });
              }
            }
          }
        }
      }
    }

    // 2. Change Intelligence: Check for State Shifts
    for (const ap of accessPoints) {
      if (this.previousApStates.has(ap.bssid)) {
        const prev = this.previousApStates.get(ap.bssid)!;
        if (prev.security !== ap.security) {
          const isDowngrade = ap.securityScore < (prev.security.includes('WPA3') ? 95 : 80);
          const chg: SecurityChange = {
            id: `CHG-${Date.now()}-${Math.floor(Math.random()*1000)}`,
            bssid: ap.bssid,
            ssid: ap.ssid,
            timestamp: new Date().toLocaleTimeString(),
            type: isDowngrade ? 'security_downgrade' : 'security_upgrade',
            title: isDowngrade ? 'Security Downgrade Observed' : 'Security Suite Upgraded',
            before: prev.security,
            after: ap.security,
            riskImpact: isDowngrade ? 'CRITICAL' : 'INFO'
          };
          this.securityChanges.unshift(chg);
          newChanges.push(chg);
        }
        if (prev.channel !== ap.channel) {
          const chg: SecurityChange = {
            id: `CHG-${Date.now()}-${Math.floor(Math.random()*1000)}`,
            bssid: ap.bssid,
            ssid: ap.ssid,
            timestamp: new Date().toLocaleTimeString(),
            type: 'channel_change',
            title: 'AP Shifted Operating RF Channel',
            before: `Channel ${prev.channel}`,
            after: `Channel ${ap.channel}`,
            riskImpact: 'LOW'
          };
          this.securityChanges.unshift(chg);
          newChanges.push(chg);
        }
      } else {
        this.previousApStates.set(ap.bssid, {
          security: ap.security,
          channel: ap.channel,
          vendor: ap.vendor
        });
      }
    }

    return {
      rogues,
      changes: this.securityChanges,
      timeline: this.timelineEvents
    };
  }

  public markAnalystClassification(bssid: string, status: 'Trusted' | 'False Positive' | 'Confirmed Rogue'): void {
    if (status === 'Trusted' || status === 'False Positive') {
      this.falsePositives.add(bssid);
      this.confirmedRogues.delete(bssid);
      this.trustedOverrides.add(bssid);
    } else {
      this.confirmedRogues.add(bssid);
      this.falsePositives.delete(bssid);
      this.trustedOverrides.delete(bssid);
    }
  }

  public getIncidents(): IncidentRecord[] {
    return this.incidents;
  }

  public updateIncidentStatus(id: string, status: IncidentRecord['status'], resolutionNotes?: string): void {
    const inc = this.incidents.find(i => i.id === id);
    if (inc) {
      inc.status = status;
      inc.updatedAt = new Date().toISOString();
      if (resolutionNotes) {
        inc.resolution = resolutionNotes;
        inc.notes.push({
          timestamp: new Date().toLocaleTimeString(),
          author: 'Auditor',
          text: `Status updated to ${status}. Notes: ${resolutionNotes}`
        });
      }
    }
  }

  public createIncident(params: {
    title: string;
    severity: IncidentRecord['severity'];
    confidence: number;
    bssid?: string;
    ssid?: string;
    summary: string;
  }): IncidentRecord {
    const newInc: IncidentRecord = {
      id: `INC-${String(this.incidents.length + 45).padStart(5, '0')}`,
      title: params.title,
      severity: params.severity,
      confidence: params.confidence,
      status: 'Open',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      assignedTo: 'Lead Security Auditor',
      summary: params.summary,
      bssidTarget: params.bssid,
      ssidTarget: params.ssid,
      evidenceIds: [`EVD-${Math.floor(Math.random() * 8000 + 1000)}`],
      notes: [
        { timestamp: new Date().toLocaleTimeString(), author: 'ThreatEngine', text: params.summary }
      ]
    };
    this.incidents.unshift(newInc);
    return newInc;
  }

  public getSecurityChanges(): SecurityChange[] {
    return this.securityChanges;
  }
}
