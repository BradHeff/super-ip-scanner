export type HostStatus = 'alive' | 'dead' | 'unknown';

export interface HostResult {
  ip: string;
  status: HostStatus;
  hostname: string | null;
  mac: string | null;
  vendor: string | null;
  rtt_ms: number | null;
  open_ports: number[];
  via: string[];
}

export interface NetIface {
  name: string;
  description: string;
  mac: string | null;
  ipv4: string[];
  is_loopback: boolean;
  is_up: boolean;
}

export interface DetectedSubnet {
  iface_name: string;
  cidr: string;
  gateway: string | null;
}

export type ScanEvent =
  | { type: 'started'; total: number; target: string }
  | { type: 'hostUpdate'; host: HostResult }
  | { type: 'progress'; scanned: number; alive: number }
  | { type: 'finished'; scanned: number; alive: number; elapsedMs: number }
  | { type: 'error'; message: string };

export interface ScanOptions {
  target: string;
  source_ip?: string | null;
  concurrency?: number;
  probe_timeout_ms?: number;
  use_arp?: boolean;
  use_icmp?: boolean;
  use_tcp_probe?: boolean;
  resolve_hostnames?: boolean;
  tcp_ports?: number[];
}
