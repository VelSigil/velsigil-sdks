import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { sha256Hex } from './encoding.js';
import { VelsigilError } from './errors.js';

/** Prefix of the hardware id hash; the same in every Velsigil SDK. */
export const HWID_PREFIX = 'vx-hwid-v1:';

const LINUX_MACHINE_ID_FILES = ['/etc/machine-id', '/var/lib/dbus/machine-id'];
const COMMAND_TIMEOUT_MS = 10_000;

let cachedHardwareId: string | undefined;

export function normalizeMachineId(machineId: string): string {
  return machineId.trim().toLowerCase();
}

/** Derives the hardware id: hex SHA-256 of the prefix plus the trimmed, lowercased machine id. */
export function hwidFromMachineId(machineId: string): string {
  const normalized = typeof machineId === 'string' ? normalizeMachineId(machineId) : '';
  if (normalized.length === 0) {
    throw new VelsigilError('hwid_unavailable', 'Machine id is empty');
  }
  return sha256Hex(HWID_PREFIX + normalized);
}

/** This machine's hardware id; throws `hwid_unavailable` if none can be read (pass `hwid` then). */
export function getHardwareId(): string {
  if (cachedHardwareId === undefined) {
    cachedHardwareId = hwidFromMachineId(readMachineId());
  }
  return cachedHardwareId;
}

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

export function parseRegQueryOutput(output: string): string | null {
  const match = /^\s*MachineGuid\s+REG_SZ\s+(.+?)\s*$/im.exec(output);
  return match?.[1] ?? null;
}

export function parseIoregOutput(output: string): string | null {
  const match = /"IOPlatformUUID"\s*=\s*"([^"]+)"/.exec(output);
  return match?.[1] ?? null;
}

function runCommand(file: string, args: string[]): string | null {
  try {
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
  // Absolute path so a different `reg` on PATH is never used.
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

/** Null for an empty id or systemd's `uninitialized` placeholder, which cloned images would share. */
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
