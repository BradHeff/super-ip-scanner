<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke, Channel } from '@tauri-apps/api/core';
  import { save } from '@tauri-apps/plugin-dialog';
  import {
    Activity,
    Play,
    Square,
    RefreshCw,
    Download,
    Search,
    Wifi,
    Globe,
    HardDrive,
    Network,
    Filter,
  } from 'lucide-svelte';
  import type {
    HostResult,
    HostStatus,
    DetectedSubnet,
    ScanEvent,
    ScanOptions,
  } from '$lib/types';
  import { cn, formatRtt, formatElapsed } from '$lib/utils';
  import { compareIPv4 } from '$lib/ip';
  import Toggle from '$lib/components/Toggle.svelte';
  import Th from '$lib/components/Th.svelte';

  // ── state ──────────────────────────────────────────────────────────────────
  let target = $state('192.168.1.0/24');
  let sourceIp = $state<string | null>(null);
  let subnets = $state<DetectedSubnet[]>([]);
  let scanning = $state(false);
  let resultsMap = $state<Map<string, HostResult>>(new Map());
  let scanned = $state(0);
  let alive = $state(0);
  let total = $state(0);
  let elapsed = $state(0);
  let elapsedTimer: ReturnType<typeof setInterval> | null = null;
  let scanStart = 0;
  let lastStatus = $state<string>('Ready');

  let useArp = $state(true);
  let useIcmp = $state(true);
  let useTcp = $state(true);
  let resolveHostnames = $state(true);
  let concurrency = $state(256);
  let timeoutMs = $state(1000);
  let extraPorts = $state('');

  let filter = $state('');
  let hideDead = $state(true);
  let sortKey = $state<'ip' | 'hostname' | 'mac' | 'vendor' | 'rtt'>('ip');
  let sortDir = $state<'asc' | 'desc'>('asc');

  // ── derived ───────────────────────────────────────────────────────────────
  const results = $derived(Array.from(resultsMap.values()));
  const filteredResults = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    let r = results;
    if (hideDead) r = r.filter((h) => h.status === 'alive');
    if (q) {
      r = r.filter(
        (h) =>
          h.ip.includes(q) ||
          (h.hostname ?? '').toLowerCase().includes(q) ||
          (h.mac ?? '').toLowerCase().includes(q) ||
          (h.vendor ?? '').toLowerCase().includes(q),
      );
    }
    const dir = sortDir === 'asc' ? 1 : -1;
    return [...r].sort((a, b) => {
      switch (sortKey) {
        case 'ip':
          return dir * compareIPv4(a.ip, b.ip);
        case 'hostname':
          return dir * (a.hostname ?? '').localeCompare(b.hostname ?? '');
        case 'mac':
          return dir * (a.mac ?? '').localeCompare(b.mac ?? '');
        case 'vendor':
          return dir * (a.vendor ?? '').localeCompare(b.vendor ?? '');
        case 'rtt':
          return dir * ((a.rtt_ms ?? Infinity) - (b.rtt_ms ?? Infinity));
      }
    });
  });

  const progress = $derived(total > 0 ? Math.min(100, (scanned / total) * 100) : 0);

  // ── lifecycle ─────────────────────────────────────────────────────────────
  onMount(async () => {
    await refreshSubnets();
  });

  async function refreshSubnets() {
    try {
      subnets = await invoke<DetectedSubnet[]>('detect_local_subnet');
      if (subnets.length > 0 && (!target || target === '192.168.1.0/24')) {
        target = subnets[0].cidr;
        sourceIp = subnets[0].cidr.split('/')[0];
      }
    } catch (e) {
      console.error(e);
    }
  }

  function pickSubnet(s: DetectedSubnet) {
    target = s.cidr;
    sourceIp = s.cidr.split('/')[0];
  }

  function setSort(key: typeof sortKey) {
    if (sortKey === key) {
      sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      sortKey = key;
      sortDir = 'asc';
    }
  }

  function parseExtraPorts(): number[] {
    return extraPorts
      .split(/[\s,]+/)
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => Number.isFinite(n) && n > 0 && n < 65536);
  }

  async function startScan() {
    if (scanning) return;
    resultsMap = new Map();
    scanned = 0;
    alive = 0;
    total = 0;
    elapsed = 0;
    scanStart = performance.now();
    scanning = true;
    lastStatus = 'Scanning…';
    elapsedTimer = setInterval(() => {
      elapsed = performance.now() - scanStart;
    }, 100);

    const channel = new Channel<ScanEvent>();
    channel.onmessage = (event) => handleScanEvent(event);

    const opts: ScanOptions = {
      target,
      source_ip: sourceIp,
      use_arp: useArp,
      use_icmp: useIcmp,
      use_tcp_probe: useTcp,
      resolve_hostnames: resolveHostnames,
      concurrency,
      probe_timeout_ms: timeoutMs,
      tcp_ports: parseExtraPorts(),
    };

    try {
      await invoke('start_scan', { options: opts, onEvent: channel });
    } catch (e) {
      lastStatus = `Error: ${e}`;
      scanning = false;
      if (elapsedTimer) clearInterval(elapsedTimer);
    }
  }

  async function stopScan() {
    try {
      await invoke('stop_scan');
    } catch (e) {
      console.error(e);
    }
    scanning = false;
    if (elapsedTimer) clearInterval(elapsedTimer);
    lastStatus = 'Stopped';
  }

  function handleScanEvent(ev: ScanEvent) {
    switch (ev.type) {
      case 'started':
        total = ev.total;
        lastStatus = `Probing ${ev.total} hosts in ${ev.target}`;
        break;
      case 'hostBatch': {
        // One copy-on-write per batch (not per host) — keeps Svelte 5 Map reactivity
        // while matching the backend's coalesced streaming.
        const next = new Map(resultsMap);
        for (const host of ev.hosts) next.set(host.ip, host);
        resultsMap = next;
        break;
      }
      case 'progress':
        scanned = ev.scanned;
        alive = ev.alive;
        break;
      case 'finished':
        scanned = ev.scanned;
        alive = ev.alive;
        elapsed = ev.elapsedMs;
        scanning = false;
        if (elapsedTimer) clearInterval(elapsedTimer);
        lastStatus = `Done — ${ev.alive} of ${ev.scanned} alive (${formatElapsed(ev.elapsedMs)})`;
        break;
      case 'error':
        scanning = false;
        if (elapsedTimer) clearInterval(elapsedTimer);
        lastStatus = `Error: ${ev.message}`;
        break;
    }
  }

  async function exportResults(format: 'csv' | 'json') {
    const path = await save({
      defaultPath: `scan-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.${format}`,
      filters: [{ name: format.toUpperCase(), extensions: [format] }],
    });
    if (!path) return;
    try {
      await invoke('export_results', {
        req: { path, format, hosts: results.filter((h) => h.status === 'alive') },
      });
      lastStatus = `Exported to ${path}`;
    } catch (e) {
      lastStatus = `Export failed: ${e}`;
    }
  }

  function statusDot(s: HostStatus): string {
    if (s === 'alive') return 'bg-emerald-500 shadow-emerald-500/40';
    if (s === 'dead') return 'bg-zinc-700';
    return 'bg-amber-500';
  }
</script>

<svelte:head>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
  <link
    href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
    rel="stylesheet"
  />
</svelte:head>

<div class="flex h-screen flex-col bg-background text-foreground">
  <!-- ── header ────────────────────────────────────────────────────────── -->
  <header
    class="flex items-center justify-between border-b border-border bg-card/40 px-5 py-3 backdrop-blur"
  >
    <div class="flex items-center gap-2.5">
      <div
        class="grid h-8 w-8 place-items-center rounded-md bg-primary/15 ring-1 ring-primary/30"
      >
        <Activity class="h-4 w-4 text-primary" />
      </div>
      <div class="leading-tight">
        <h1 class="text-sm font-semibold tracking-tight">Super IP Scanner</h1>
        <p class="text-[11px] text-muted-foreground">ARP · ICMP · TCP · DNS · NBNS</p>
      </div>
    </div>
    <div class="flex items-center gap-1.5">
      <span
        class={cn(
          'inline-block h-2 w-2 rounded-full transition-shadow',
          scanning
            ? 'bg-primary shadow-[0_0_12px] shadow-primary/70 animate-pulse'
            : 'bg-zinc-600',
        )}
      ></span>
      <span class="text-xs text-muted-foreground">{lastStatus}</span>
    </div>
  </header>

  <!-- ── control bar ─────────────────────────────────────────────────────── -->
  <section class="border-b border-border bg-card/20 px-5 py-3">
    <div class="flex flex-wrap items-end gap-3">
      <!-- target -->
      <div class="flex-1 min-w-[320px]">
        <label
          for="target"
          class="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground"
          >Target</label
        >
        <div class="relative">
          <Network
            class="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          />
          <input
            id="target"
            type="text"
            bind:value={target}
            disabled={scanning}
            placeholder="192.168.1.0/24 or 10.0.0.1-50"
            class="h-9 w-full rounded-md border border-border bg-input/60 pr-3 font-mono text-sm outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/25 disabled:opacity-50"
            style="padding-left: 2.1rem"
          />
        </div>
      </div>

      <!-- source IP -->
      <div class="w-[180px]">
        <label
          for="source"
          class="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground"
          >Source IP (ARP)</label
        >
        <input
          id="source"
          type="text"
          bind:value={sourceIp}
          disabled={scanning}
          placeholder="auto"
          class="h-9 w-full rounded-md border border-border bg-input/60 px-2.5 font-mono text-sm outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/25 disabled:opacity-50"
        />
      </div>

      <!-- detected subnets -->
      {#if subnets.length > 0}
        <div class="flex items-end gap-1">
          {#each subnets.slice(0, 3) as s}
            <button
              type="button"
              onclick={() => pickSubnet(s)}
              disabled={scanning}
              title="{s.iface_name} → {s.cidr}"
              class="h-9 rounded-md border border-border bg-card px-2.5 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-50"
            >
              <Wifi class="mr-1 inline h-3 w-3" />
              {s.cidr}
            </button>
          {/each}
          <button
            type="button"
            onclick={refreshSubnets}
            disabled={scanning}
            title="Refresh interfaces"
            class="grid h-9 w-9 place-items-center rounded-md border border-border bg-card text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-50"
          >
            <RefreshCw class="h-3.5 w-3.5" />
          </button>
        </div>
      {/if}

      <!-- scan button -->
      <div class="flex items-end gap-1.5">
        {#if !scanning}
          <button
            type="button"
            onclick={startScan}
            class="inline-flex h-9 items-center gap-1.5 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground shadow-lg shadow-primary/20 transition-all hover:brightness-110 active:scale-[0.98]"
          >
            <Play class="h-3.5 w-3.5 fill-current" />
            Start scan
          </button>
        {:else}
          <button
            type="button"
            onclick={stopScan}
            class="inline-flex h-9 items-center gap-1.5 rounded-md bg-destructive px-4 text-sm font-medium text-destructive-foreground transition-all hover:brightness-110 active:scale-[0.98]"
          >
            <Square class="h-3.5 w-3.5 fill-current" />
            Stop
          </button>
        {/if}
      </div>
    </div>

    <!-- options row -->
    <div class="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
      <Toggle bind:checked={useArp} label="ARP" disabled={scanning} />
      <Toggle bind:checked={useIcmp} label="ICMP" disabled={scanning} />
      <Toggle bind:checked={useTcp} label="TCP probe" disabled={scanning} />
      <Toggle bind:checked={resolveHostnames} label="Resolve hostnames" disabled={scanning} />
      <span class="text-muted-foreground">·</span>
      <label class="flex items-center gap-1.5 text-muted-foreground">
        Concurrency
        <input
          type="number"
          min="16"
          max="2048"
          bind:value={concurrency}
          disabled={scanning}
          class="h-7 w-16 rounded-md border border-border bg-input/60 px-2 text-center font-mono text-foreground outline-none focus:border-primary/60 disabled:opacity-50"
        />
      </label>
      <label class="flex items-center gap-1.5 text-muted-foreground">
        Timeout (ms)
        <input
          type="number"
          min="100"
          max="10000"
          step="100"
          bind:value={timeoutMs}
          disabled={scanning}
          class="h-7 w-20 rounded-md border border-border bg-input/60 px-2 text-center font-mono text-foreground outline-none focus:border-primary/60 disabled:opacity-50"
        />
      </label>
      <label class="flex items-center gap-1.5 text-muted-foreground">
        Extra ports
        <input
          type="text"
          bind:value={extraPorts}
          disabled={scanning}
          placeholder="e.g. 8443, 9000"
          class="h-7 w-44 rounded-md border border-border bg-input/60 px-2 font-mono text-foreground outline-none focus:border-primary/60 disabled:opacity-50"
        />
      </label>
    </div>
  </section>

  <!-- ── results table ──────────────────────────────────────────────────── -->
  <main class="flex-1 overflow-hidden">
    <div class="flex h-full flex-col">
      <!-- filter / actions bar -->
      <div class="flex items-center gap-2 border-b border-border bg-card/20 px-5 py-2">
        <div class="relative max-w-md flex-1">
          <Search
            class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
          />
          <input
            type="text"
            bind:value={filter}
            placeholder="Filter by IP, hostname, MAC, vendor…"
            class="h-8 w-full rounded-md border border-border bg-input/60 pl-8 pr-3 text-sm outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/25"
          />
        </div>
        <label class="flex items-center gap-1.5 text-xs text-muted-foreground">
          <input type="checkbox" bind:checked={hideDead} class="h-3.5 w-3.5 accent-primary" />
          <Filter class="h-3 w-3" /> Alive only
        </label>
        <div class="flex-1"></div>
        <button
          type="button"
          onclick={() => exportResults('csv')}
          disabled={alive === 0}
          class="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-card px-3 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Download class="h-3 w-3" /> CSV
        </button>
        <button
          type="button"
          onclick={() => exportResults('json')}
          disabled={alive === 0}
          class="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-card px-3 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Download class="h-3 w-3" /> JSON
        </button>
      </div>

      <!-- table -->
      <div class="flex-1 overflow-auto">
        <table class="w-full border-separate border-spacing-0 text-sm">
          <thead class="sticky top-0 z-10 bg-card/90 backdrop-blur">
            <tr class="text-[11px] uppercase tracking-wider text-muted-foreground">
              <Th></Th>
              <Th sortable active={sortKey === 'ip'} dir={sortDir} onclick={() => setSort('ip')}>IP</Th>
              <Th sortable active={sortKey === 'hostname'} dir={sortDir} onclick={() => setSort('hostname')}>Hostname</Th>
              <Th sortable active={sortKey === 'mac'} dir={sortDir} onclick={() => setSort('mac')}>MAC</Th>
              <Th sortable active={sortKey === 'vendor'} dir={sortDir} onclick={() => setSort('vendor')}>Vendor</Th>
              <Th sortable active={sortKey === 'rtt'} dir={sortDir} onclick={() => setSort('rtt')} class="text-right">RTT</Th>
              <Th>Ports</Th>
              <Th>Via</Th>
            </tr>
          </thead>
          <tbody class="font-mono text-[13px]">
            {#each filteredResults as h (h.ip)}
              <tr class="group hover:bg-accent/40">
                <td class="border-b border-border/40 px-3 py-1.5">
                  <span class={cn('inline-block h-2 w-2 rounded-full', statusDot(h.status))}></span>
                </td>
                <td class="border-b border-border/40 px-3 py-1.5 tabular-nums">{h.ip}</td>
                <td class="border-b border-border/40 px-3 py-1.5">
                  {#if h.hostname}
                    <span class="inline-flex items-center gap-1.5">
                      <Globe class="h-3 w-3 text-muted-foreground" />
                      {h.hostname}
                    </span>
                  {:else}
                    <span class="text-muted-foreground/50">—</span>
                  {/if}
                </td>
                <td class="border-b border-border/40 px-3 py-1.5 tabular-nums text-muted-foreground">
                  {h.mac ?? '—'}
                </td>
                <td class="border-b border-border/40 px-3 py-1.5 font-sans text-xs text-muted-foreground">
                  {#if h.vendor}
                    <span class="inline-flex items-center gap-1.5">
                      <HardDrive class="h-3 w-3" />
                      {h.vendor}
                    </span>
                  {:else}—{/if}
                </td>
                <td class="border-b border-border/40 px-3 py-1.5 text-right tabular-nums">
                  {formatRtt(h.rtt_ms)}
                </td>
                <td class="border-b border-border/40 px-3 py-1.5">
                  {#if h.open_ports.length === 0}
                    <span class="text-muted-foreground/50">—</span>
                  {:else}
                    <div class="flex flex-wrap gap-1">
                      {#each h.open_ports as p}
                        <span class="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">{p}</span>
                      {/each}
                    </div>
                  {/if}
                </td>
                <td class="border-b border-border/40 px-3 py-1.5">
                  <div class="flex gap-1">
                    {#each h.via as v}
                      <span class="rounded bg-secondary px-1.5 py-0.5 text-[10px] uppercase text-secondary-foreground/80">{v}</span>
                    {/each}
                  </div>
                </td>
              </tr>
            {:else}
              <tr>
                <td colspan="8" class="px-3 py-16 text-center">
                  <div class="flex flex-col items-center gap-2 text-muted-foreground">
                    {#if scanning}
                      <div class="h-6 w-6 animate-spin rounded-full border-2 border-primary/30 border-t-primary"></div>
                      <p class="text-sm">Probing the network…</p>
                    {:else}
                      <Network class="h-6 w-6 opacity-40" />
                      <p class="text-sm">
                        No results yet. Configure a target and press
                        <kbd class="rounded border border-border bg-card px-1.5 py-0.5 text-[10px]">Start scan</kbd>.
                      </p>
                    {/if}
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  </main>

  <!-- ── status bar ─────────────────────────────────────────────────────── -->
  <footer class="border-t border-border bg-card/40 px-5 py-2">
    <div class="flex items-center gap-4 text-xs">
      <div class="flex items-center gap-1.5">
        <span class="text-muted-foreground">Scanned</span>
        <span class="font-mono font-semibold tabular-nums">
          {scanned}<span class="text-muted-foreground">/{total}</span>
        </span>
      </div>
      <div class="flex items-center gap-1.5">
        <span class="text-muted-foreground">Alive</span>
        <span class="font-mono font-semibold tabular-nums text-emerald-400">{alive}</span>
      </div>
      <div class="flex items-center gap-1.5">
        <span class="text-muted-foreground">Elapsed</span>
        <span class="font-mono tabular-nums">{formatElapsed(elapsed)}</span>
      </div>
      <div class="ml-4 flex-1">
        <div class="h-1.5 w-full overflow-hidden rounded-full bg-border/60">
          <div
            class="h-full rounded-full bg-primary transition-[width] duration-150"
            style="width: {progress}%"
          ></div>
        </div>
      </div>
      <span class="font-mono tabular-nums text-muted-foreground">{progress.toFixed(0)}%</span>
    </div>
  </footer>
</div>
