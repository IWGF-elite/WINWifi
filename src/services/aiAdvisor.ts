import { AccessPoint, SecurityIssue, IncidentRecord, SecurityChange } from '../types';

export interface AIExplanationResult {
  headline: string;
  simpleExplanation: string;
  whyItMatters: string;
  recommendedAction: string;
  riskLevelText: string;
  evidenceGrounded: string[];
}

export class AIAdvisor {
  private static instance: AIAdvisor;

  public static getInstance(): AIAdvisor {
    if (!AIAdvisor.instance) {
      AIAdvisor.instance = new AIAdvisor();
    }
    return AIAdvisor.instance;
  }

  public explainSecurityFinding(issue: SecurityIssue): {
    whatItMeans: string;
    whyItIsRisky: string;
    howToFix: string;
  } {
    if (issue.id === 'VULN-WEP-BROKEN') {
      return {
        whatItMeans: 'This access point is using WEP (Wired Equivalent Privacy), an encryption protocol broken in 2001.',
        whyItIsRisky: 'Anyone within radio range can passively capture IV packets and recover the full network key in seconds using mathematical cryptanalysis.',
        howToFix: 'Access router administrative settings, navigate to Wireless Security, select WPA2-Personal (AES) or WPA3-SAE, and save changes.'
      };
    }
    if (issue.id === 'VULN-OPEN-UNENCRYPTED') {
      return {
        whatItMeans: 'All frames and user data are broadcast in cleartext across open radio frequencies with zero layer-2 encryption.',
        whyItIsRisky: 'Eavesdroppers can capture session tokens, unencrypted credentials, and conduct effortless Evil Twin rogue spoofing.',
        howToFix: 'Enable WPA2/WPA3 password protection, or deploy 802.11 Enhanced Open (OWE) if guest access is required.'
      };
    }
    if (issue.id === 'VULN-WPS-PIN') {
      return {
        whatItMeans: 'The Wi-Fi Protected Setup PIN registrar feature is active on this router.',
        whyItIsRisky: 'Attackers can brute-force the 8-digit PIN due to a protocol split-check vulnerability in hours without knowing the passphrase.',
        howToFix: 'Navigate to router Advanced Wireless settings and disable WPS or Wi-Fi Protected Setup PIN authentication.'
      };
    }
    if (issue.id === 'WARN-PMF-DISABLED') {
      return {
        whatItMeans: 'Protected Management Frames (IEEE 802.11w) are not required by this access point.',
        whyItIsRisky: 'Clients can be knocked offline by spoofed deauthentication frames sent by attackers seeking to capture handshakes.',
        howToFix: 'In the access point security profile, set Management Frame Protection (PMF) to "Capable" or "Required".'
      };
    }
    return {
      whatItMeans: issue.description,
      whyItIsRisky: 'Non-standard security posture increases attack surface and fails NIST SP 800-153 guidelines.',
      howToFix: issue.recommendation
    };
  }

  public explainAccessPointPosture(ap: AccessPoint): {
    executiveSummary: string;
    primaryRisk: string;
    recommendedAction: string;
  } {
    if (ap.isRogueCandidate) {
      return {
        executiveSummary: `Network "${ap.ssid}" (${ap.bssid}) is flagged as a high-confidence Rogue AP / Evil Twin candidate cloning authorized enterprise infrastructure.`,
        primaryRisk: 'Credential harvesting and unauthorized MitM interception of corporate devices.',
        recommendedAction: 'Isolate the radio source using directional RSSI triangulation and revoke rogue MAC from upstream switches.'
      };
    }
    if (ap.security.includes('WEP')) {
      return {
        executiveSummary: `Access point "${ap.ssid}" is operating completely broken legacy WEP encryption.`,
        primaryRisk: 'Instant key recovery via statistical FMS/Korek/PTW attacks.',
        recommendedAction: 'Decommission legacy hardware or upgrade firmware immediately to WPA2/WPA3.'
      };
    }
    if (ap.security === 'Open') {
      return {
        executiveSummary: `Network "${ap.ssid}" transmits user packets without wireless encryption.`,
        primaryRisk: 'Cleartext packet interception and rogue station impersonation.',
        recommendedAction: 'Enable WPA2-Enterprise or deploy 802.11 Enhanced Open (OWE).'
      };
    }
    if (ap.wpsEnabled) {
      return {
        executiveSummary: `Network "${ap.ssid}" is using WPA2, but has vulnerable WPS PIN registrar enabled.`,
        primaryRisk: 'Offline PIN brute-force recovery of the underlying WPA2 pre-shared key.',
        recommendedAction: 'Disable WPS PIN registrar in management settings.'
      };
    }
    if (ap.securityScore >= 85) {
      return {
        executiveSummary: `Access point "${ap.ssid}" demonstrates robust compliance with modern enterprise wireless standards (AES-CCMP / WPA3).`,
        primaryRisk: 'Minimal operational risk; periodic firmware patching recommended.',
        recommendedAction: 'Maintain baseline monitoring and verify client isolation policies.'
      };
    }
    return {
      executiveSummary: `Network "${ap.ssid}" has moderate security findings with a score of ${ap.securityScore}/100.`,
      primaryRisk: ap.issues[0]?.title || 'Configuration deviations from NIST SP 800-153.',
      recommendedAction: ap.issues[0]?.recommendation || 'Review access point settings.'
    };
  }

  public explainFinding(ap: AccessPoint, issue: SecurityIssue): AIExplanationResult {
    const evidence = [
      `Target Network: "${ap.ssid}" (${ap.bssid})`,
      `Current Encryption: ${ap.security} with ${ap.cipher}`,
      `Observed Signal: ${ap.rssi} dBm on Channel ${ap.channel} (${ap.band})`
    ];

    if (issue.id === 'VULN-WEP-BROKEN') {
      return {
        headline: 'Dangerously Outdated Wi-Fi Security (WEP)',
        simpleExplanation: 'This network is using a security technology invented in 1997 that was broken decades ago. Anyone nearby can discover the password and view all internet traffic in under a minute.',
        whyItMatters: 'Using WEP is equivalent to having an open, unprotected network. It violates PCI-DSS compliance and leaves confidential data completely exposed.',
        recommendedAction: 'Log in to your Wi-Fi router or access point settings and switch the security mode to WPA2-Personal (AES) or WPA3.',
        riskLevelText: 'CRITICAL (Immediate Action Required)',
        evidenceGrounded: [...evidence, 'Detected WEP cipher keys in 802.11 Beacon frame.']
      };
    }

    if (issue.id === 'VULN-OPEN-UNENCRYPTED') {
      return {
        headline: 'Completely Unencrypted Airwaves (Open Wi-Fi)',
        simpleExplanation: 'This network transmits everything in plain text through the air. Anyone sitting in the parking lot or nearby room can passively capture passwords, session cookies, and viewed pages.',
        whyItMatters: 'Malicious actors can easily clone the network, perform man-in-the-middle attacks, or inspect sensitive unencrypted traffic.',
        recommendedAction: 'Enable WPA2/WPA3 password protection, or if this is a public guest network, deploy OWE (Opportunistic Wireless Encryption) with client isolation.',
        riskLevelText: 'HIGH RISK',
        evidenceGrounded: [...evidence, 'Beacon frame contains no RSN or WPA Information Element.']
      };
    }

    if (issue.id === 'VULN-WPS-PIN') {
      return {
        headline: 'Vulnerable Wi-Fi Protected Setup (WPS PIN)',
        simpleExplanation: 'The router has a quick-connect PIN feature turned on. Because of a design flaw in this feature, attackers can guess the 8-digit PIN using automated mathematical tools in a few hours without knowing your Wi-Fi password.',
        whyItMatters: 'Once the attacker guesses the PIN, the router hands over your real WPA2 passphrase automatically.',
        recommendedAction: 'Turn off "WPS" or "Wi-Fi Protected Setup" inside your router management interface.',
        riskLevelText: 'HIGH RISK',
        evidenceGrounded: [...evidence, 'Tag 221 WPS Vendor Element is present and unlocked.']
      };
    }

    if (issue.id === 'WARN-PMF-DISABLED') {
      return {
        headline: 'Management Frame Protection Missing (802.11w)',
        simpleExplanation: 'While passwords on this network are encrypted, the control signals that connect and disconnect laptops are not protected. An attacker can send fake "disconnect" messages to kick users off the network.',
        whyItMatters: 'Causes annoying Wi-Fi drops and allows attackers to force laptops to disconnect so they can capture handshake packets.',
        recommendedAction: 'In your AP management portal, set "Protected Management Frames (PMF / 802.11w)" to "Required" or "Capable".',
        riskLevelText: 'MEDIUM RISK',
        evidenceGrounded: [...evidence, 'RSN Capabilities byte shows PMF bit 6 and 7 set to 0.']
      };
    }

    if (issue.id === 'ROGUE-EVIL-TWIN') {
      return {
        headline: 'Suspected Fake Network / Evil Twin Clone',
        simpleExplanation: 'Someone has set up an access point broadcasting your exact company Wi-Fi name, but it has weaker security or different hardware. They may be trying to trick employees into connecting to steal their credentials.',
        whyItMatters: 'Employees connecting to this fake network will have their usernames and passwords intercepted.',
        recommendedAction: 'Physically locate the device broadcasting this BSSID, disconnect it from power/Ethernet, and alert security.',
        riskLevelText: 'CRITICAL THREAT',
        evidenceGrounded: [...evidence, 'Duplicate SSID broadcast with downgraded cipher compared to authorized baseline.']
      };
    }

    // Default generic explanation grounded in data
    return {
      headline: issue.title,
      simpleExplanation: issue.description,
      whyItMatters: 'Non-standard wireless configurations increase the attack surface and can lead to data interception or policy failure.',
      recommendedAction: issue.recommendation,
      riskLevelText: issue.severity,
      evidenceGrounded: evidence
    };
  }

  public explainChange(change: SecurityChange): string {
    if (change.type === 'security_downgrade') {
      return `Network "${change.ssid}" was previously protected by ${change.before}, but suddenly switched to ${change.after}. This is a serious indicator of an active downgrade attack or misconfiguration.`;
    }
    if (change.type === 'new_bssid') {
      return `A brand new transmitter with MAC address ${change.bssid} started broadcasting SSID "${change.ssid}". If this was not installed by your IT staff, it may be an unauthorized rogue router.`;
    }
    if (change.type === 'channel_change' || change.type === 'channel_shift') {
      return `Network "${change.ssid}" migrated from ${change.before} to ${change.after}. This is usually normal dynamic frequency selection, but verify if sudden interference occurred.`;
    }
    if (change.type === 'pmf_disabled' || change.type === 'pmf_change') {
      return `Network "${change.ssid}" now advertises protected management frames as ${change.after} (previously ${change.before}). Losing PMF removes protection against deauth-style disruption of clients.`;
    }
    if (change.type === 'wps_enabled' || change.type === 'wps_change') {
      return `Wi-Fi Protected Setup on "${change.ssid}" changed from ${change.before} to ${change.after}. An enabled WPS PIN restores a brute-forceable path around the WPA2/WPA3 passphrase.`;
    }
    if (change.type === 'vendor_mismatch') {
      return `The transmitter for "${change.ssid}" now reports a different manufacturer (${change.before} to ${change.after}) for BSSID ${change.bssid}. Verify the hardware was actually replaced.`;
    }
    if (change.type === 'bssid_drift') {
      return `Broadcast parameters for "${change.ssid}" drifted on BSSID ${change.bssid}: ${change.before} to ${change.after}.`;
    }
    return `State shift detected for ${change.ssid}: changed from "${change.before}" to "${change.after}".`;
  }

  public generateAssessmentExecutiveSummary(aps: AccessPoint[], incidents: IncidentRecord[]): {
    whatIsGood: string[];
    whatIsRisky: string[];
    whatChanged: string[];
    urgentActions: string[];
  } {
    const total = aps.length;
    const wpa3Count = aps.filter(a => a.security.includes('WPA3')).length;
    const wepCount = aps.filter(a => a.security.includes('WEP')).length;
    const openCount = aps.filter(a => a.security === 'Open').length;
    const rogueCount = aps.filter(a => a.isRogueCandidate).length;
    const wpsCount = aps.filter(a => a.wpsEnabled).length;

    const whatIsGood: string[] = [];
    if (wpa3Count > 0) {
      whatIsGood.push(`${wpa3Count} network(s) are leveraging modern WPA3 encryption, immune to offline dictionary attacks.`);
    }
    const compliantCount = aps.filter(a => a.securityScore >= 85).length;
    if (compliantCount > 0) {
      whatIsGood.push(`${compliantCount} out of ${total} access points meet enterprise security compliance baselines.`);
    }

    const whatIsRisky: string[] = [];
    if (rogueCount > 0) {
      whatIsRisky.push(`${rogueCount} suspected Rogue AP / Evil Twin clones detected broadcasting corporate network names.`);
    }
    if (wepCount > 0) {
      whatIsRisky.push(`${wepCount} access point(s) are still using obsolete WEP encryption that can be compromised in seconds.`);
    }
    if (openCount > 0) {
      whatIsRisky.push(`${openCount} network(s) are unencrypted, allowing anyone nearby to passively sniff session data.`);
    }
    if (wpsCount > 0) {
      whatIsRisky.push(`${wpsCount} router(s) have vulnerable WPS PIN registrars enabled.`);
    }

    const whatChanged: string[] = [
      `Observed ${total} unique BSSIDs during the latest wireless survey.`,
      incidents.length > 0 ? `${incidents.length} security incident(s) currently open for investigation.` : 'No critical anomalies identified.'
    ];

    const urgentActions: string[] = [];
    if (rogueCount > 0) {
      urgentActions.push('Priority 1: Investigate and physically isolate the rogue transmitter cloning corporate SSIDs.');
    }
    if (wepCount > 0) {
      urgentActions.push('Priority 2: Immediately upgrade legacy WEP warehouse routers to WPA2/WPA3.');
    }
    if (wpsCount > 0) {
      urgentActions.push('Priority 3: Disable WPS PIN features in router management firmware across all perimeter sites.');
    }

    return { whatIsGood, whatIsRisky, whatChanged, urgentActions };
  }
}
