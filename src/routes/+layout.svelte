<script lang="ts">
  // Self-hosted fonts — bundled by Vite and served from the app origin, so they work
  // offline and satisfy the production CSP (a remote Google Fonts <link> is blocked by
  // `style-src 'self'`/`font-src 'self'` and would silently fall back to system fonts).
  import '@fontsource/inter/400.css';
  import '@fontsource/inter/500.css';
  import '@fontsource/inter/600.css';
  import '@fontsource/inter/700.css';
  import '@fontsource/jetbrains-mono/400.css';
  import '@fontsource/jetbrains-mono/500.css';
  import '../app.css';

  let { children } = $props();
</script>

{@render children()}
