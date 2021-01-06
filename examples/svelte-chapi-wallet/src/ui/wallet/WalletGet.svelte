<script lang="ts">
  import { navigate } from "svelte-navigator";
  import { receiveCredentialEvent } from "web-credential-handler";
  import { v4 as uuid } from "uuid";

  import { WalletItem } from "../component";

  import Config from "../../config.ts";
  import { walletState, minimalState } from "../../store.ts";
  import { enumerateItems } from "../../utils.ts";

  minimalState.set(true);

  let wstate;
  walletState.subscribe((value) => {
    wstate = value;
  });

  let reason = "";
  let origin = "";

  let present = () => null;
  let cancel = null;

  const handleGetEvent = async () => {
    present = () => null;
    cancel = null;

    if (wstate === null) {
      navigate(`/sign-in?redirect=${Config.WALLET_GET}`);
      return;
    }

    await DIDKitLoader.loadDIDKit();
    const event = await receiveCredentialEvent();
    origin = event.credentialRequestOrigin;

    const vp = event.credentialRequestOptions.web.VerifiablePresentation;
    const { challenge, domain } = vp;
    const query = Array.isArray(vp.query) ? vp.query[0] : vp.query;

    if (query.type !== "QueryByExample") {
      throw new Error(
        "Only QueryByExample requests are supported in demo wallet."
      );
    }

    reason = query.credentialQuery.reason;

    present = (data) => async () => {
      const { keyToDID, keyToVerificationMethod, issuePresentation } = DIDKit;
      const key = wstate.storage.getItem("key");
      const keyStr = JSON.stringify(key);
      const didKey = keyToDID("key", keyStr);
      const verificationMethod = await keyToVerificationMethod("key", keyStr);
      const vp = JSON.stringify({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        type: ["VerifiablePresentation"],
        id: `urn:uuid:${uuid()}`,
        holder: didKey,
        verifiableCredential: data,
      });
      const options = JSON.stringify({
        challenge,
        domain,
        verificationMethod,
        proofPurpose: "authentication",
      });

      const signedStr = await issuePresentation(vp, options, keyStr);
      const signed = JSON.parse(signedStr);

      event.respondWith(
        Promise.resolve({
          dataType: "VerifiablePresentation",
          data: signed,
        })
      );
    };

    cancel = () => {
      event.respondWith(
        Promise.resolve({ dataType: "Response", data: "error" })
      );
    };
  };

  credentialHandlerPolyfill.loadOnce(Config.MEDIATOR).then(handleGetEvent);
</script>

<div class="container flex flex-col px-6 py-4 shadow rounded overflow-y-scroll">
  <h1 class="text-xl text-black my-2">
    <span class="font-bold">{origin}</span>
    {" is requesting a credential"}
  </h1>
  <h2 class="text-xs text-gray-500">
    <span class="font-bold">{"Reason:"}</span>
    <span class="text-sm">{reason}</span>
  </h2>

  <div class="my-2">
    {#if wstate !== null}
      {#each enumerateItems(wstate.storage.getItem("data")) as { type, item }}
        <WalletItem {type} {item} share={present(item)} buttons={["share"]} />
      {/each}
    {/if}
  </div>

  <button
    class="text-sm font-medium text-center w-full rounded px-4 py-2 ml-2"
    on:click={cancel}>{"Cancel"}</button
  >
</div>
