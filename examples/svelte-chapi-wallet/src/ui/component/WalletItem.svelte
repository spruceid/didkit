<script lang="ts">
  export let type;
  export let item;
  export let copy = undefined;
  export let share = undefined;
  export let remove = undefined;
  export let buttons = ["copy", "share"];

  import {
    UnknownItem,
    VerifiableCredential,
    VerifiablePresentation,
  } from "../component";
</script>

<div
  class="block mx-2 my-4 w-full flex flex-row items-center rounded hover:shadow"
>
  <div class="flex-none block p-8 text-sm text-bold">{type}</div>
  <div class="flex-1 overflow-x-scroll mx-4">
    {#if type === "VerifiablePresentation"}
      <VerifiablePresentation {item} />
    {:else if type === "VerifiableCredential"}
      <VerifiableCredential {item} />
    {:else}
      <UnknownItem {item} />
    {/if}
  </div>
  <div class="flex-none block p-2 flex flex-col">
    {#if buttons.includes("copy")}
      <button
        class="text-sm m-1 px-6 py-1 rounded"
        on:click={copy}
        disabled={typeof copy === "undefined" || copy === null}>
        {"Copy"}
      </button>
    {/if}
    {#if buttons.includes("share")}
      <button
        class="text-sm m-1 px-6 py-1 rounded"
        on:click={share}
        disabled={typeof share === "undefined" || share === null}>
        {"Share"}
      </button>
    {/if}
    {#if buttons.includes("remove")}
      <button
        class="text-sm m-1 px-6 py-1 rounded"
        on:click={remove}
        disabled={typeof remove === "undefined" || remove === null}>
        {"Remove"}
      </button>
    {/if}
  </div>
</div>
