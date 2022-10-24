<script>
  import { onMount } from 'svelte';
  import { Router } from "svelte-navigator";

  import { Body, Footer, Header } from "./ui/container";
  import { minimalState } from "./store.ts";

  import init from "didkit-wasm";
  let appInitialized = false;
  onMount(async () => {
      await init();
      appInitialized = true
      });

  let minimal;
  minimalState.subscribe((value) => {
    minimal = value;
  });
</script>

<Router>
  {#if appInitialized}
    {#if minimal}
      <main
        class="flex flex-col w-full h-full justify-center items-center p-2 bg-white"
      >
        <Body />
      </main>
    {:else}
      <Header />
      <main class="h-full">
        <Body />
      </main>
      <Footer />
    {/if}
  {/if}
</Router>

<style global lang="postcss">
  @tailwind base;
  @tailwind components;
  @tailwind utilities;

  html,
  body {
    height: 100%;
    margin: 0;
    padding: 0;
  }

  body {
    display: flex;
    flex-direction: column;
  }
</style>
