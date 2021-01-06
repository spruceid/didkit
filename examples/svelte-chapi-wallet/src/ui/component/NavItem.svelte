<script lang="ts">
  import { Link } from "svelte-navigator";
  export let url = "";
</script>

<Link
  class="no-underline focus:no-underline hover:no-underline text-grey-dark border-b-2 border-transparent uppercase tracking-wide font-bold text-xs py-3 mr-8 hover:border-current"
  to={url}
  on:click
>
  <slot />
</Link>
