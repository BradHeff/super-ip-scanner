<script lang="ts">
  interface Props {
    checked: boolean;
    label: string;
    disabled?: boolean;
  }
  let { checked = $bindable(), label, disabled = false }: Props = $props();
</script>

<label
  class="inline-flex cursor-pointer select-none items-center gap-1.5 text-muted-foreground transition-colors hover:text-foreground"
  class:opacity-50={disabled}
  class:cursor-not-allowed={disabled}
>
  <span
    class="relative inline-flex h-4 w-7 items-center rounded-full transition-colors"
    class:bg-primary={checked}
    class:bg-border={!checked}
  >
    <span
      class="inline-block h-3 w-3 transform rounded-full bg-white shadow transition-transform"
      class:translate-x-3.5={checked}
      class:translate-x-0.5={!checked}
    ></span>
  </span>
  <input type="checkbox" bind:checked {disabled} class="sr-only" />
  <span>{label}</span>
</label>
