import React from 'react';

interface WinWiFiLogoProps {
  className?: string;
  title?: string;
}

/** WebView-safe version of the WinWiFi application mark. */
export const WinWiFiLogo: React.FC<WinWiFiLogoProps> = ({ className = '', title = 'WinWiFi' }) => (
  <svg viewBox="0 0 48 48" role="img" aria-label={title} className={className} xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="winwifi-logo-gradient" x1="7" y1="5" x2="41" y2="43" gradientUnits="userSpaceOnUse">
        <stop stopColor="#27C6FF" />
        <stop offset="1" stopColor="#2563EB" />
      </linearGradient>
    </defs>
    <rect x="2" y="2" width="44" height="44" rx="11" fill="url(#winwifi-logo-gradient)" />
    <path d="M24 8.5 36.5 13v9.4c0 8.2-5.1 14.3-12.5 17.1C16.6 36.7 11.5 30.6 11.5 22.4V13L24 8.5Z" fill="#071525" fillOpacity=".92" />
    <path d="M16.4 21.5a10.75 10.75 0 0 1 15.2 0M19.6 24.7a6.2 6.2 0 0 1 8.8 0M22.8 27.9a1.7 1.7 0 0 1 2.4 0" fill="none" stroke="#F8FAFC" strokeWidth="2.45" strokeLinecap="round" />
    <circle cx="24" cy="31.2" r="1.75" fill="#40F5C5" />
  </svg>
);
