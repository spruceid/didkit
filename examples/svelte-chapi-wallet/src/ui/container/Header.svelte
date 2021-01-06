<script lang="ts">
  import { LogoutLink, NavItem } from "../component";
  import { walletState } from "../../store.ts";

  let wstate;
  walletState.subscribe((value) => {
    wstate = value;
  });
</script>

<nav class="bg-white px-8 pt-2 shadow-md">
  <div class="flex justify-between items-center">
    <h1 class="text-lg">Svelte Demo CHAPI Wallet</h1>
    <div class="flex justify-center">
      {#if wstate !== null}
        <NavItem url="/">Wallet</NavItem>
        <LogoutLink />
      {:else}
        <NavItem url="/">Index</NavItem>
        <NavItem url="/sign-in">Sign In</NavItem>
        <NavItem url="/sign-up">Sign Up</NavItem>
      {/if}
    </div>
  </div>
</nav>
