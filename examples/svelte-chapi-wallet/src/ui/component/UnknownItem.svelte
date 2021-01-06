<script lang="ts">
  export let item;

  let text = JSON.stringify(item);
</script>

<span class="text-xl" alt={text}>{item}</span>
