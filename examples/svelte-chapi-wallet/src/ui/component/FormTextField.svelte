<script lang="ts">
  export let name = "";
  export let placeholder = "";
  export let value;
</script>

<input
  bind:value
  class="block w-full px-4 py-1 my-2 text-sm rounded"
  {placeholder}
  type="text"
  id={name}
  {name}
/>
