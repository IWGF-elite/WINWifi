import React from 'react';

interface WinWiFiLogoProps {
  className?: string;
  title?: string;
}

/** The supplied WinWiFi shield shared by all dashboard surfaces. */
export const WinWiFiLogo: React.FC<WinWiFiLogoProps> = ({ className = '', title = 'WinWiFi' }) => (
  <img src="/winwifi-shield.png" alt={title} className={className} />
);
