<script lang="ts">
  import { Route } from "svelte-navigator";
  import { Home, SignIn, SignUp, Wallet } from "../view";
  import { walletState } from "../../store.ts";
  import { WalletGet, WalletStore, WalletWorker } from "../wallet";

  let wstate;
  walletState.subscribe((value) => {
    wstate = value;
  });
</script>

<Route path="/">
  {#if wstate !== null}
    <Wallet />
  {:else}
    <Home />
  {/if}
</Route>
<Route path="/sign-in">
  <SignIn />
</Route>
<Route path="/sign-up">
  <SignUp />
</Route>

<Route path="/wallet-get">
  <WalletGet />
</Route>
<Route path="/wallet-store">
  <WalletStore />
</Route>
<Route path="/wallet-worker">
  <WalletWorker />
</Route>
