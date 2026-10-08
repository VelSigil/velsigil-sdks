import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { sha256Hex } from './encoding.js';
import { VelsigilError } from './errors.js';

/** Domain-separation prefix of the hardware id derivation (identical in every Velsigil SDK). */
export const HWID_PREFIX = 'vx-hwid-v1:';

const LINUX_MACHINE_ID_FILES = ['/etc/machine-id', '/var/lib/dbus/machine-id'];
const COMMAND_TIMEOUT_MS = 10_000;

let cachedHardwareId: string | undefined;

/** Machine ids are trimmed and lowercased before hashing. */
export function normalizeMachineId(machineId: string): string {
  return machineId.trim().toLowerCase();
}

/**
 * Derives the Velsigil hardware id from a raw machine id:
 * `lowercase hex SHA-256("vx-hwid-v1:" + machineId.trim().toLowerCase())`.
 */
export function hwidFromMachineId(machineId: string): string {
  const normalized = typeof machineId === 'string' ? normalizeMachineId(machineId) : '';
  if (normalized.length === 0) {
    throw new VelsigilError('hwid_unavailable', 'Machine id is empty');
  }
  return sha256Hex(HWID_PREFIX + normalized);
}

/**
 * Returns this machine's Velsigil hardware id (64 lowercase hex chars). The value is computed once
 * per process and cached. Throws `VelsigilError('hwid_unavailable')` when the platform machine id
 * cannot be read; in that case pass an explicit `hwid` option to the client.
 *
 * Sources: Windows `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (64-bit registry view),
 * Linux `/etc/machine-id` then `/var/lib/dbus/machine-id`, macOS `IOPlatformUUID`.
 */
export function getHardwareId(): string {
  if (cachedHardwareId === undefined) {
    cachedHardwareId = hwidFromMachineId(readMachineId());
  }
  return cachedHardwareId;
}

/** Reads the raw platform machine id. Throws `VelsigilError('hwid_unavailable')` on failure. */
export function readMachineId(platform: NodeJS.Platform = process.platform): string {
  let id: string | null;
  switch (platform) {
    case 'win32':
      id = readWindowsMachineGuid();
      break;
    case 'darwin':
      id = readMacPlatformUuid();
      break;
    default:
      id = readLinuxMachineId();
      break;
  }
  if (id === null || normalizeMachineId(id).length === 0) {
    throw new VelsigilError(
      'hwid_unavailable',
      'Could not determine a machine id on this system; pass the `hwid` option explicitly',
    );
  }
  return id;
}

/** Extracts the MachineGuid value from `reg query ... /v MachineGuid` output. */
export function parseRegQueryOutput(output: string): string | null {
  const match = /^\s*MachineGuid\s+REG_SZ\s+(.+?)\s*$/im.exec(output);
  return match?.[1] ?? null;
}

/** Extracts IOPlatformUUID from `ioreg -rd1 -c IOPlatformExpertDevice` output. */
export function parseIoregOutput(output: string): string | null {
  const match = /"IOPlatformUUID"\s*=\s*"([^"]+)"/.exec(output);
  return match?.[1] ?? null;
}

function runCommand(file: string, args: string[]): string | null {
  try {
    // execFileSync never spawns a shell; arguments are passed verbatim.
    return execFileSync(file, args, {
      encoding: 'utf8',
      timeout: COMMAND_TIMEOUT_MS,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return null;
  }
}

function readWindowsMachineGuid(): string | null {
  // Prefer the absolute system path to avoid resolving a different `reg` through PATH.
  const systemRoot = process.env.SystemRoot ?? process.env.windir;
  const absolute = systemRoot ? join(systemRoot, 'System32', 'reg.exe') : null;
  const reg = absolute !== null && existsSync(absolute) ? absolute : 'reg';
  const output = runCommand(reg, [
    'query',
    'HKLM\\SOFTWARE\\Microsoft\\Cryptography',
    '/v',
    'MachineGuid',
    '/reg:64',
  ]);
  return output === null ? null : parseRegQueryOutput(output);
}

function readMacPlatformUuid(): string | null {
  const ioreg = existsSync('/usr/sbin/ioreg') ? '/usr/sbin/ioreg' : 'ioreg';
  const output = runCommand(ioreg, ['-rd1', '-c', 'IOPlatformExpertDevice']);
  return output === null ? null : parseIoregOutput(output);
}

/**
 * The machine id in the content of a Linux machine-id file, or null when the file holds no usable id: empty, or
 * systemd's placeholder `uninitialized` (any case; written during early boot and left in images systemd never booted,
 * where every copy would share one hwid). The same rule in every Velsigil SDK (CLIENT_PROTOCOL 8.1).
 */
export function usableLinuxMachineId(content: string): string | null {
  const value = content.trim();
  const normalized = normalizeMachineId(value);
  return normalized.length === 0 || normalized === 'uninitialized' ? null : value;
}

function readLinuxMachineId(): string | null {
  for (const file of LINUX_MACHINE_ID_FILES) {
    try {
      const value = usableLinuxMachineId(readFileSync(file, 'utf8'));
      if (value !== null) return value;
    } catch {
      // try the next source
    }
  }
  return null;
}
