import { AccessPoint, AssetClassification, SecurityPolicy, PolicyEvaluationResult } from '../types';

/**
 * Classification routing. Classified assets are evaluated against the policy
 * assigned to their class; unclassified or Unknown assets fall back to the
 * analyst-selected default policy.
 */
export const POLICY_CLASSIFICATION_ROUTES: { classification: AssetClassification; policyId: string; rationale: string }[] = [
  { classification: 'Corporate', policyId: 'corp-policy', rationale: 'Enterprise baseline for authorized corporate infrastructure.' },
  { classification: 'Trusted', policyId: 'corp-policy', rationale: 'Analyst-trusted infrastructure inherits the enterprise baseline.' },
  { classification: 'Guest', policyId: 'guest-policy', rationale: 'Visitor networks may allow OWE or PSK but still prohibit legacy ciphers.' },
  { classification: 'IoT', policyId: 'iot-policy', rationale: 'IoT radios are held to WPA2-AES with WPS prohibited.' },
  { classification: 'Suspicious', policyId: 'high-sec-policy', rationale: 'Suspicious transmitters are held to the strictest available baseline.' },
  { classification: 'Rogue', policyId: 'high-sec-policy', rationale: 'Rogue transmitters are held to the strictest available baseline.' },
  { classification: 'Investigating', policyId: 'high-sec-policy', rationale: 'Assets under investigation are held to the strictest available baseline.' }
];

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
  private activePolicyId: string = (() => {
    try { return localStorage.getItem('winwifi_active_policy') || 'corp-policy'; }
    catch { return 'corp-policy'; }
  })();

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
      try { localStorage.setItem('winwifi_active_policy', policyId); } catch { /* Storage may be unavailable in private mode. */ }
    }
  }

  /** Resolves the effective policy for an asset from its classification. */
  public resolvePolicy(ap: AccessPoint): SecurityPolicy {
    const route = ap.classification
      ? POLICY_CLASSIFICATION_ROUTES.find(candidate => candidate.classification === ap.classification)
      : undefined;
    const routed = route ? this.policies.find(policy => policy.id === route.policyId) : undefined;
    return routed || this.getActivePolicy();
  }

  /** Evaluates one AP. An explicit policy overrides classification routing. */
  public evaluateAP(ap: AccessPoint, policy?: SecurityPolicy): PolicyEvaluationResult {
    const pol = policy || this.resolvePolicy(ap);
    const failed: string[] = [];
    const passed: string[] = [];
    let approvalNonCompliant = false;
    let approvalWarning = false;

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

    // 7. Classification and registry approval governance
    if (ap.classification === 'Rogue') {
      failed.push('Network is classified as rogue in the project scope');
      approvalNonCompliant = true;
    } else if (ap.classification === 'Suspicious') {
      failed.push('Network is classified as suspicious and requires analyst review');
      approvalWarning = true;
    }

    switch (ap.approvedStatus) {
      case 'Approved':
        passed.push('Registry approval status is Approved');
        break;
      case 'Unapproved':
        failed.push('Registry approval status is Unapproved');
        approvalNonCompliant = true;
        break;
      case 'Investigating':
        failed.push('Registry approval status is Under Investigation');
        approvalWarning = true;
        break;
      case 'Pending Review':
        failed.push('Registry approval status is Pending Review');
        approvalWarning = true;
        break;
    }

    let status: 'Compliant' | 'Warning' | 'Non-Compliant' = 'Compliant';
    if (approvalNonCompliant || failed.length > 2 || failed.some(f => f.includes('WEP') || f.includes('cleartext'))) {
      status = 'Non-Compliant';
    } else if (approvalWarning || failed.length > 0) {
      status = 'Warning';
    }

    return {
      apBssid: ap.bssid,
      policyId: pol.id,
      policyName: pol.name,
      status,
      classification: ap.classification,
      approvalStatus: ap.approvedStatus,
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
