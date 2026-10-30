import React, { createContext, useContext } from 'react';

/** Authoritative continuous WLAN scanner state shared by every screen. */
const ScanActivityContext = createContext(false);

export const ScanActivityProvider: React.FC<React.PropsWithChildren<{ active: boolean }>> = ({ active, children }) => (
  <ScanActivityContext.Provider value={active}>{children}</ScanActivityContext.Provider>
);

export const useScanActive = (): boolean => useContext(ScanActivityContext);
