<script lang="ts">
  import { ArrowDown, ArrowUp } from 'lucide-svelte';
  import type { Snippet } from 'svelte';
  import { cn } from '$lib/utils';

  interface Props {
    sortable?: boolean;
    active?: boolean;
    dir?: 'asc' | 'desc';
    onclick?: () => void;
    class?: string;
    children?: Snippet;
  }
  let {
    sortable = false,
    active = false,
    dir = 'asc',
    onclick,
    class: klass = '',
    children,
  }: Props = $props();
</script>

<th
  class={cn(
    'border-b border-border px-3 py-2 font-medium text-left',
    sortable && 'cursor-pointer select-none transition-colors hover:text-foreground',
    active && 'text-primary',
    klass,
  )}
  onclick={sortable ? onclick : undefined}
>
  <span class="inline-flex items-center gap-1">
    {#if children}{@render children()}{/if}
    {#if sortable && active}
      {#if dir === 'asc'}
        <ArrowUp class="h-3 w-3" />
      {:else}
        <ArrowDown class="h-3 w-3" />
      {/if}
    {/if}
  </span>
</th>
