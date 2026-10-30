import React from 'react';
import { ThinkingOrb, type OrbState } from 'thinking-orbs';

interface ProcessingOrbProps {
  state: OrbState;
  label: string;
  size?: 20 | 64;
  className?: string;
}

/** Shared accessible wrapper: keeps every processing orb on the app's automatic theme. */
export const ProcessingOrb: React.FC<ProcessingOrbProps> = ({
  state,
  label,
  size = 20,
  className = 'shrink-0',
}) => (
  <ThinkingOrb
    state={state}
    size={size}
    theme="auto"
    aria-label={label}
    className={className}
  />
);
