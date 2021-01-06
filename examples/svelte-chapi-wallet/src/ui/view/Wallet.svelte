<script lang="ts">
  import { walletState } from "../../store.ts";
  import { WalletItem } from "../component";
  import { copyToClipboard, enumerateItems } from "../../utils.ts";

  let wstate;
  walletState.subscribe((value) => {
    wstate = value;
  });

  let counter = 0;
  let didKey = "";
  let copyDID = (event) => {
    event.preventDefault();
    copyToClipboard(didKey);
  };

  DIDKitLoader.loadDIDKit().then(({ keyToDID }) => {
    didKey = keyToDID("key", JSON.stringify(wstate.storage.getItem("key")));
  });

  const reload = () => (counter += 1);
</script>

<div class="container mx-auto my-8 px-6 py-4 shadow">
  {#if wstate !== null}
    <h1 class="text-xl text-black">{wstate.username}'s wallet</h1>
    <h2 class="text-sm text-gray-500">
      Here you can view your DIDs, Credentials.
      <a class="float-right text-sm" href={"#"} on:click={reload}>
        {"click to reload"}
      </a>
    </h2>

    <div class="mt-8">
      <div class="px-8 py-2 my-4 text-sm bg-yellow-50 rounded">
        {"Your did:key is: " + didKey}
        <a class="float-right" href={"#"} on:click={copyDID}>
          {"click to copy"}
        </a>
      </div>
    </div>

    <div class="mt-8">
      {#if wstate.storage.getItem("data") !== null}
        {#each enumerateItems(wstate.storage.getItem("data")) as { type, item, copy }}
          <WalletItem {type} {item} {copy} />
        {/each}
      {:else}
        <div class="px-8 py-2 my-4 text-sm bg-yellow-50 rounded">
          {"Your wallet is empty"}
        </div>
      {/if}
    </div>
  {:else}
    <div class="px-8 py-2 my-4 text-sm bg-red-50 rounded">
      {"This page is only accessible to authenticated users."}
    </div>
  {/if}
</div>
