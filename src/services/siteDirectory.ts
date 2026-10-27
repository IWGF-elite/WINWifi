import {
  EnterpriseAssetRecord,
  EnterpriseScope,
  SiteBuildingRecord,
  SiteFloorRecord,
  SiteRecord
} from '../types';

const MAX_SITES = 50;
const MAX_BUILDINGS = 50;
const MAX_FLOORS = 100;
const MAX_NAME = 80;

export interface SiteMutationResult {
  directory: SiteRecord[];
  error?: string;
}

const nameKey = (value: string): string => value.trim().toLowerCase();
const matches = (left: string | undefined, right: string | undefined): boolean =>
  Boolean(left && right) && nameKey(left!) === nameKey(right!);

function randomSuffix(): string {
  const buffered = new Uint8Array(4);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(buffered);
  } else {
    for (let index = 0; index < buffered.length; index++) buffered[index] = Math.floor(Math.random() * 256);
  }
  return Array.from(buffered, byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
}

const newEntityId = (prefix: 'site' | 'bldg' | 'floor'): string => `${prefix}-${randomSuffix()}`;

export function sanitizeSiteName(value: unknown): string {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_NAME);
}

/** Accepts untrusted stored JSON and returns a bounded, de-duplicated directory. */
export function normalizeSiteDirectory(input: unknown): SiteRecord[] {
  if (!Array.isArray(input)) return [];

  const sites: SiteRecord[] = [];
  const siteNames = new Set<string>();
  const usedIds = new Set<string>();
  const uniqueId = (raw: unknown, prefix: 'site' | 'bldg' | 'floor'): string => {
    let id = typeof raw === 'string' ? raw.trim().slice(0, 64) : '';
    if (!id || usedIds.has(id)) id = newEntityId(prefix);
    while (usedIds.has(id)) id = newEntityId(prefix);
    usedIds.add(id);
    return id;
  };

  for (const rawSite of input) {
    if (sites.length >= MAX_SITES) break;
    if (!rawSite || typeof rawSite !== 'object') continue;
    const site = rawSite as Record<string, unknown>;
    const name = sanitizeSiteName(site.name);
    if (!name || siteNames.has(nameKey(name))) continue;
    siteNames.add(nameKey(name));

    const buildings: SiteBuildingRecord[] = [];
    const buildingNames = new Set<string>();
    if (Array.isArray(site.buildings)) {
      for (const rawBuilding of site.buildings) {
        if (buildings.length >= MAX_BUILDINGS) break;
        if (!rawBuilding || typeof rawBuilding !== 'object') continue;
        const building = rawBuilding as Record<string, unknown>;
        const buildingName = sanitizeSiteName(building.name);
        if (!buildingName || buildingNames.has(nameKey(buildingName))) continue;
        buildingNames.add(nameKey(buildingName));

        const floors: SiteFloorRecord[] = [];
        const floorNames = new Set<string>();
        if (Array.isArray(building.floors)) {
          for (const rawFloor of building.floors) {
            if (floors.length >= MAX_FLOORS) break;
            if (!rawFloor || typeof rawFloor !== 'object') continue;
            const floor = rawFloor as Record<string, unknown>;
            const floorName = sanitizeSiteName(floor.name);
            if (!floorName || floorNames.has(nameKey(floorName))) continue;
            floorNames.add(nameKey(floorName));
            floors.push({ id: uniqueId(floor.id, 'floor'), name: floorName });
          }
        }

        buildings.push({
          id: uniqueId(building.id, 'bldg'),
          name: buildingName,
          floors
        });
      }
    }

    sites.push({ id: uniqueId(site.id, 'site'), name, buildings });
  }

  return sites;
}

const fail = (directory: SiteRecord[], error: string): SiteMutationResult => ({ directory, error });
const succeed = (directory: SiteRecord[]): SiteMutationResult => ({ directory });

export function addSite(directory: SiteRecord[], name: string): SiteMutationResult {
  const clean = sanitizeSiteName(name);
  if (!clean) return fail(directory, 'Enter a site name.');
  if (directory.some(site => nameKey(site.name) === nameKey(clean))) {
    return fail(directory, `A site named "${clean}" already exists.`);
  }
  if (directory.length >= MAX_SITES) return fail(directory, `This project supports up to ${MAX_SITES} sites.`);
  return succeed([...directory, { id: newEntityId('site'), name: clean, buildings: [] }]);
}

export function renameSite(directory: SiteRecord[], siteId: string, name: string): SiteMutationResult {
  const clean = sanitizeSiteName(name);
  if (!clean) return fail(directory, 'Enter a site name.');
  if (!directory.some(site => site.id === siteId)) return fail(directory, 'That site no longer exists.');
  if (directory.some(site => site.id !== siteId && nameKey(site.name) === nameKey(clean))) {
    return fail(directory, `A site named "${clean}" already exists.`);
  }
  return succeed(directory.map(site => site.id === siteId ? { ...site, name: clean } : site));
}

export function deleteSite(directory: SiteRecord[], siteId: string): SiteMutationResult {
  if (!directory.some(site => site.id === siteId)) return fail(directory, 'That site no longer exists.');
  return succeed(directory.filter(site => site.id !== siteId));
}

export function addBuilding(directory: SiteRecord[], siteId: string, name: string): SiteMutationResult {
  const clean = sanitizeSiteName(name);
  if (!clean) return fail(directory, 'Enter a building name.');
  const site = directory.find(candidate => candidate.id === siteId);
  if (!site) return fail(directory, 'That site no longer exists.');
  if (site.buildings.some(building => nameKey(building.name) === nameKey(clean))) {
    return fail(directory, `Building "${clean}" already exists at ${site.name}.`);
  }
  if (site.buildings.length >= MAX_BUILDINGS) {
    return fail(directory, `This site supports up to ${MAX_BUILDINGS} buildings.`);
  }
  return succeed(directory.map(candidate => candidate.id === siteId
    ? { ...candidate, buildings: [...candidate.buildings, { id: newEntityId('bldg'), name: clean, floors: [] }] }
    : candidate));
}

export function renameBuilding(directory: SiteRecord[], siteId: string, buildingId: string, name: string): SiteMutationResult {
  const clean = sanitizeSiteName(name);
  if (!clean) return fail(directory, 'Enter a building name.');
  const site = directory.find(candidate => candidate.id === siteId);
  if (!site) return fail(directory, 'That site no longer exists.');
  if (!site.buildings.some(building => building.id === buildingId)) return fail(directory, 'That building no longer exists.');
  if (site.buildings.some(building => building.id !== buildingId && nameKey(building.name) === nameKey(clean))) {
    return fail(directory, `Building "${clean}" already exists at ${site.name}.`);
  }
  return succeed(directory.map(candidate => candidate.id === siteId
    ? {
        ...candidate,
        buildings: candidate.buildings.map(building => building.id === buildingId ? { ...building, name: clean } : building)
      }
    : candidate));
}

export function deleteBuilding(directory: SiteRecord[], siteId: string, buildingId: string): SiteMutationResult {
  const site = directory.find(candidate => candidate.id === siteId);
  if (!site) return fail(directory, 'That site no longer exists.');
  if (!site.buildings.some(building => building.id === buildingId)) return fail(directory, 'That building no longer exists.');
  return succeed(directory.map(candidate => candidate.id === siteId
    ? { ...candidate, buildings: candidate.buildings.filter(building => building.id !== buildingId) }
    : candidate));
}

export function addFloor(directory: SiteRecord[], siteId: string, buildingId: string, name: string): SiteMutationResult {
  const clean = sanitizeSiteName(name);
  if (!clean) return fail(directory, 'Enter a floor or area name.');
  const site = directory.find(candidate => candidate.id === siteId);
  if (!site) return fail(directory, 'That site no longer exists.');
  const building = site.buildings.find(candidate => candidate.id === buildingId);
  if (!building) return fail(directory, 'That building no longer exists.');
  if (building.floors.some(floor => nameKey(floor.name) === nameKey(clean))) {
    return fail(directory, `Floor "${clean}" already exists at ${site.name} / ${building.name}.`);
  }
  if (building.floors.length >= MAX_FLOORS) {
    return fail(directory, `This building supports up to ${MAX_FLOORS} floors.`);
  }
  return succeed(directory.map(candidate => candidate.id === siteId
    ? {
        ...candidate,
        buildings: candidate.buildings.map(buildingCandidate => buildingCandidate.id === buildingId
          ? { ...buildingCandidate, floors: [...buildingCandidate.floors, { id: newEntityId('floor'), name: clean }] }
          : buildingCandidate)
      }
    : candidate));
}

export function renameFloor(
  directory: SiteRecord[],
  siteId: string,
  buildingId: string,
  floorId: string,
  name: string
): SiteMutationResult {
  const clean = sanitizeSiteName(name);
  if (!clean) return fail(directory, 'Enter a floor or area name.');
  const site = directory.find(candidate => candidate.id === siteId);
  if (!site) return fail(directory, 'That site no longer exists.');
  const building = site.buildings.find(candidate => candidate.id === buildingId);
  if (!building) return fail(directory, 'That building no longer exists.');
  if (!building.floors.some(floor => floor.id === floorId)) return fail(directory, 'That floor no longer exists.');
  if (building.floors.some(floor => floor.id !== floorId && nameKey(floor.name) === nameKey(clean))) {
    return fail(directory, `Floor "${clean}" already exists at ${site.name} / ${building.name}.`);
  }
  return succeed(directory.map(candidate => candidate.id === siteId
    ? {
        ...candidate,
        buildings: candidate.buildings.map(buildingCandidate => buildingCandidate.id === buildingId
          ? {
              ...buildingCandidate,
              floors: buildingCandidate.floors.map(floor => floor.id === floorId ? { ...floor, name: clean } : floor)
            }
          : buildingCandidate)
      }
    : candidate));
}

export function deleteFloor(directory: SiteRecord[], siteId: string, buildingId: string, floorId: string): SiteMutationResult {
  const site = directory.find(candidate => candidate.id === siteId);
  if (!site) return fail(directory, 'That site no longer exists.');
  const building = site.buildings.find(candidate => candidate.id === buildingId);
  if (!building) return fail(directory, 'That building no longer exists.');
  if (!building.floors.some(floor => floor.id === floorId)) return fail(directory, 'That floor no longer exists.');
  return succeed(directory.map(candidate => candidate.id === siteId
    ? {
        ...candidate,
        buildings: candidate.buildings.map(buildingCandidate => buildingCandidate.id === buildingId
          ? { ...buildingCandidate, floors: buildingCandidate.floors.filter(floor => floor.id !== floorId) }
          : buildingCandidate)
      }
    : candidate));
}

export function listSiteNames(directory: SiteRecord[]): string[] {
  return directory.map(site => site.name);
}

export function listBuildingNames(directory: SiteRecord[], siteName: string): string[] {
  const site = directory.find(candidate => matches(candidate.name, siteName));
  return site ? site.buildings.map(building => building.name) : [];
}

export function listFloorNames(directory: SiteRecord[], siteName: string, buildingName: string): string[] {
  const site = directory.find(candidate => matches(candidate.name, siteName));
  const building = site?.buildings.find(candidate => matches(candidate.name, buildingName));
  return building ? building.floors.map(floor => floor.name) : [];
}

export function countAssetsAtSite(assets: EnterpriseAssetRecord[], siteName: string): number {
  return assets.filter(asset => matches(asset.site, siteName)).length;
}

export function countAssetsInBuilding(assets: EnterpriseAssetRecord[], siteName: string, buildingName: string): number {
  return assets.filter(asset => matches(asset.site, siteName) && matches(asset.building, buildingName)).length;
}

export function countAssetsOnFloor(
  assets: EnterpriseAssetRecord[],
  siteName: string,
  buildingName: string,
  floorName: string
): number {
  return assets.filter(asset =>
    matches(asset.site, siteName) &&
    matches(asset.building, buildingName) &&
    matches(asset.areaFloor, floorName)).length;
}

export function renameSiteInAssets(assets: EnterpriseAssetRecord[], oldName: string, newName: string): EnterpriseAssetRecord[] {
  if (oldName === newName) return assets;
  return assets.map(asset => matches(asset.site, oldName) ? { ...asset, site: newName } : asset);
}

export function renameBuildingInAssets(
  assets: EnterpriseAssetRecord[],
  siteName: string,
  oldName: string,
  newName: string
): EnterpriseAssetRecord[] {
  if (oldName === newName) return assets;
  return assets.map(asset =>
    matches(asset.site, siteName) && matches(asset.building, oldName)
      ? { ...asset, building: newName }
      : asset);
}

export function renameFloorInAssets(
  assets: EnterpriseAssetRecord[],
  siteName: string,
  buildingName: string,
  oldName: string,
  newName: string
): EnterpriseAssetRecord[] {
  if (oldName === newName) return assets;
  return assets.map(asset =>
    matches(asset.site, siteName) && matches(asset.building, buildingName) && matches(asset.areaFloor, oldName)
      ? { ...asset, areaFloor: newName }
      : asset);
}

/** Adds the project's declared scope to an empty or incomplete directory. */
export function ensureScopeInDirectory(directory: SiteRecord[], scope?: EnterpriseScope | null): SiteRecord[] {
  const siteName = sanitizeSiteName(scope?.site);
  if (!siteName) return directory;

  let next = directory;
  let site = next.find(candidate => matches(candidate.name, siteName));
  if (!site) {
    const added = addSite(next, siteName);
    if (added.error) return directory;
    next = added.directory;
    site = next[next.length - 1];
  }

  const buildingName = sanitizeSiteName(scope?.building);
  if (buildingName && !site.buildings.some(building => matches(building.name, buildingName))) {
    const added = addBuilding(next, site.id, buildingName);
    if (!added.error) next = added.directory;
  }

  return next;
}
