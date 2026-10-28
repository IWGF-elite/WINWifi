import { AccessPoint } from '../types';

export const isSuspiciousAccessPoint = (ap: AccessPoint): boolean =>
  !!ap.isRogueCandidate || ap.classification === 'Rogue' || ap.classification === 'Suspicious';

export const countSuspiciousAccessPoints = (accessPoints: AccessPoint[]): number =>
  accessPoints.filter(isSuspiciousAccessPoint).length;
