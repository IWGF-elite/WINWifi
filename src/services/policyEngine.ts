import { AccessPoint, SecurityPolicy, PolicyEvaluationResult } from '../types';

export const DEFAULT_POLICIES: SecurityPolicy[] = [
  {
    id: 'corp-policy',
    name: 'Corporate Policy',
    description: 'Enterprise security baseline requiring WPA2-Enterprise or WPA3, mandatory PMF (802.11w), and prohibiting WPS, TKIP, and WEP.',
    minSecurity: 'WPA2-Enterprise (802.1X)',
    wpa3Required: false,
    pmfRequired: true,
    wpsProhibited: true,
    tkipProhibited: true,
    wepProhibited: true,
    openProhibited: true,
  },
  {
    id: 'high-sec-policy',
    name: 'High Security Policy',
    description: 'Zero-trust wireless policy requiring WPA3-Enterprise or WPA3-SAE, mandatory PMF, and strict prohibition of legacy ciphers.',
    minSecurity: 'WPA3-Personal (SAE)',
    wpa3Required: true,
    pmfRequired: true,
    wpsProhibited: true,
    tkipProhibited: true,
    wepProhibited: true,
    openProhibited: true,
  },
  {
    id: 'guest-policy',
    name: 'Guest Policy',
    description: 'Public or visitor wireless policy allowing OWE or WPA2-PSK with client isolation, but prohibiting unencrypted WEP and WPS PIN.',
    minSecurity: 'OWE (Enhanced Open)',
    wpa3Required: false,
    pmfRequired: false,
    wpsProhibited: true,
    tkipProhibited: true,
    wepProhibited: true,
    openProhibited: false,
  },
  {
    id: 'iot-policy',
    name: 'IoT Policy',
    description: 'Specialized device profile requiring WPA2-AES with dedicated PSK, prohibiting WEP and WPS broadcast.',
    minSecurity: 'WPA2-Personal (AES)',
    wpa3Required: false,
    pmfRequired: false,
    wpsProhibited: true,
    tkipProhibited: true,
    wepProhibited: true,
    openProhibited: true,
  }
];

export class PolicyEngine {
  private static instance: PolicyEngine;
  private policies: SecurityPolicy[] = DEFAULT_POLICIES;
  private activePolicyId: string = 'corp-policy';

  public static getInstance(): PolicyEngine {
    if (!PolicyEngine.instance) {
      PolicyEngine.instance = new PolicyEngine();
    }
    return PolicyEngine.instance;
  }

  public getPolicies(): SecurityPolicy[] {
    return this.policies;
  }

  public getActivePolicy(): SecurityPolicy {
    return this.policies.find(p => p.id === this.activePolicyId) || this.policies[0];
  }

  public setActivePolicy(policyId: string): void {
    if (this.policies.some(p => p.id === policyId)) {
      this.activePolicyId = policyId;
    }
  }

  public evaluateAP(ap: AccessPoint, policy?: SecurityPolicy): PolicyEvaluationResult {
    const pol = policy || this.getActivePolicy();
    const failed: string[] = [];
    const passed: string[] = [];

    // 1. WEP Check
    if (pol.wepProhibited && (ap.security.includes('WEP') || ap.cipher === 'WEP')) {
      failed.push('Uses prohibited WEP encryption (NIST SP 800-153 §4.2)');
    } else {
      passed.push('WEP encryption absent');
    }

    // 2. Open Network Check
    if (pol.openProhibited && ap.security === 'Open') {
      failed.push('Transmits in cleartext Open mode without air-layer encryption');
    } else if (ap.security !== 'Open') {
      passed.push('Air-layer encryption enabled');
    }

    // 3. TKIP Check
    if (pol.tkipProhibited && (ap.cipher === 'TKIP' || ap.security.includes('TKIP'))) {
      failed.push('Uses deprecated TKIP cipher subject to Michael MIC degradation');
    } else {
      passed.push('TKIP cipher avoided');
    }

    // 4. WPS Check
    if (pol.wpsProhibited && ap.wpsEnabled) {
      failed.push('Wi-Fi Protected Setup (WPS) PIN registrar is broadcast active');
    } else {
      passed.push('WPS disabled');
    }

    // 5. PMF (802.11w) Check
    if (pol.pmfRequired && !ap.pmfRequired) {
      failed.push('Protected Management Frames (802.11w PMF) are not mandatory');
    } else if (ap.pmfRequired) {
      passed.push('Protected Management Frames enforced');
    }

    // 6. WPA3 Requirement
    if (pol.wpa3Required && !ap.security.includes('WPA3')) {
      failed.push('Fails to meet mandatory WPA3-SAE / WPA3-Enterprise protocol standard');
    } else if (ap.security.includes('WPA3')) {
      passed.push('Complies with WPA3 protocol standard');
    }

    let status: 'Compliant' | 'Warning' | 'Non-Compliant' = 'Compliant';
    if (failed.length > 2 || failed.some(f => f.includes('WEP') || f.includes('cleartext'))) {
      status = 'Non-Compliant';
    } else if (failed.length > 0) {
      status = 'Warning';
    }

    return {
      apBssid: ap.bssid,
      policyName: pol.name,
      status,
      failedRules: failed,
      passedRules: passed,
    };
  }

  public evaluateAll(aps: AccessPoint[]): Map<string, PolicyEvaluationResult> {
    const results = new Map<string, PolicyEvaluationResult>();
    for (const ap of aps) {
      results.set(ap.bssid, this.evaluateAP(ap));
    }
    return results;
  }
}
