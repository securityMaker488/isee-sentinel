/** Exact, reviewed targets only. No resolution, subprocesses, or implicit network authorization. */
export interface TargetManifest {
  version: 1;
  targets: { assetId: string; address: string; ports: number[] }[];
  exclusions: { address: string }[];
}

const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, keys: string[]) => Object.keys(value).length === keys.length && Object.keys(value).every(key => keys.includes(key));
const uuid = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

/** RFC1918 and loopback literals, in canonical dotted decimal. Private does not mean authorized. */
export function isLabIPv4(address: unknown): address is string {
  if (typeof address !== 'string' || !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(address)) return false;
  const parts = address.split('.').map(Number);
  if (parts.some(part => part > 255)) return false;
  return parts[0] === 127 || parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168);
}

export function validTargetManifest(value: unknown, assetIds?: readonly string[], allowedPorts?: readonly number[]): value is TargetManifest {
  if (!record(value) || !exactKeys(value, ['version', 'targets', 'exclusions']) || value.version !== 1
    || !Array.isArray(value.targets) || value.targets.length < 1 || value.targets.length > 100
    || !Array.isArray(value.exclusions) || value.exclusions.length > 100) return false;
  const targets = new Set<string>(), exclusions = new Set<string>();
  for (const target of value.targets) {
    if (!record(target) || !exactKeys(target, ['assetId', 'address', 'ports']) || !uuid(target.assetId) || !isLabIPv4(target.address)
      || (assetIds && !assetIds.includes(target.assetId)) || !Array.isArray(target.ports) || target.ports.length < 1 || target.ports.length > 16
      || new Set(target.ports).size !== target.ports.length || target.ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535 || (allowedPorts && !allowedPorts.includes(port)))) return false;
    const identity = `${target.assetId.toLowerCase()}:${target.address}`;
    if (targets.has(identity)) return false;
    targets.add(identity);
  }
  for (const exclusion of value.exclusions) {
    if (!record(exclusion) || !exactKeys(exclusion, ['address']) || !isLabIPv4(exclusion.address) || exclusions.has(exclusion.address)) return false;
    exclusions.add(exclusion.address);
  }
  return true;
}

/** Call only after validation. Creates a canonical copy, never mutating the reviewed input. */
export function normalizeTargetManifest(value: TargetManifest): TargetManifest {
  return { version: 1,
    targets: value.targets.map(target => ({ assetId: target.assetId.toLowerCase(), address: target.address, ports: [...target.ports].sort((a, b) => a - b) }))
      .sort((a, b) => a.assetId.localeCompare(b.assetId) || a.address.localeCompare(b.address)),
    exclusions: value.exclusions.map(exclusion => ({ address: exclusion.address })).sort((a, b) => a.address.localeCompare(b.address)),
  };
}

/** Exclusions apply across the operation, including an address explicitly present in targets. */
export function targetManifestAllows(manifest: TargetManifest, assetId: string, address: string, ports?: readonly number[]): boolean {
  if (!validTargetManifest(manifest) || !uuid(assetId) || !isLabIPv4(address) || manifest.exclusions.some(item => item.address === address)) return false;
  const target = manifest.targets.find(item => item.assetId.toLowerCase() === assetId.toLowerCase() && item.address === address);
  if (!target) return false;
  return ports === undefined || (ports.length > 0 && ports.length <= 16 && new Set(ports).size === ports.length
    && ports.every(port => Number.isInteger(port) && target.ports.includes(port)));
}
