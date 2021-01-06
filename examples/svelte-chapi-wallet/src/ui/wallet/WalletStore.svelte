<script lang="ts">
  import { navigate } from "svelte-navigator";
  import { receiveCredentialEvent } from "web-credential-handler";

  import Config from "../../config.ts";
  import { walletState, minimalState } from "../../store.ts";

  minimalState.set(true);

  let wstate;
  walletState.subscribe((value) => {
    wstate = value;
  });

  let type = "";
  let issuer = "";
  let preview = "";

  let accept = null;
  let reject = null;

  const handleStoreEvent = async () => {
    accept = null;
    reject = null;

    if (wstate === null) {
      navigate(`/sign-in?redirect=${Config.WALLET_STORE}`);
      return;
    }

    await DIDKitLoader.loadDIDKit();
    const event = await receiveCredentialEvent();
    const { credential } = event;
    const { data, dataType } = credential;

    type = dataType;
    if (dataType === "VerifiablePresentation") {
      preview = Array.isArray(data.verifiableCredential)
        ? data.verifiableCredential
            .map((item) => JSON.stringify(item, null, 2))
            .join("\n\n")
        : JSON.stringify(data.verifiableCredential, null, 2);
      issuer = Array.isArray(data.verifiableCredential)
        ? data.verifiableCredential.map((item) => item.issuer).join(", ")
        : data.verifiableCredential.issuer;
    } else if (dataType === "VerifiableCredential") {
      preview = JSON.stringify(data, null, 2);
      issuer = data.issuer;
    } else {
      preview = "Cannot display a preview of this item";
      issuer = "-";
    }

    accept = async () => {
      const { verifyCredential } = DIDKit;
      const verificationMethod = `${data.issuer}#${data.issuer.substring(8)}`;
      const options = JSON.stringify({
        verificationMethod,
        proofPurpose: "assertionMethod",
      });
      const verifyStr = await verifyCredential(JSON.stringify(data), options);
      const verify = JSON.parse(verifyStr);
      if (verify.errors.length > 0) {
        console.log("Failed to verify credential: " + verify.errors);
      } else {
        const walletData = wstate.storage.getItem("data") || [];
        wstate.storage.setItem("data", [...walletData, data]);
        event.respondWith(Promise.resolve({ dataType, data }));
      }
    };

    reject = () => event.respondWith(Promise.resolve(null));
  };

  credentialHandlerPolyfill.loadOnce(Config.MEDIATOR).then(handleStoreEvent);
</script>

<div class="container flex flex-col px-6 py-4 shadow rounded">
  <h1 class="text-xl text-black my-2">
    {"You have received the following credential:"}
  </h1>
  <h2 class="text-xs text-gray-500">
    <span class="font-bold">{"Type:"}</span>
    <span class="text-sm">{type}</span>
  </h2>
  <h2 class="text-xs text-gray-500">
    <span class="font-bold">{"Issued by:"}</span>
    <span class="text-sm">{issuer}</span>
  </h2>
  <textarea
    class="text-xs font-mono my-4 px-4"
    rows="8"
    value={"\n" + preview + "\n"}
    disabled
  />
  <div class="flex flex-row">
    <button
      class="text-sm font-medium text-center w-full rounded px-4 py-2 mr-2"
      on:click={accept}>{"Accept"}</button
    >
    <button
      class="text-sm font-medium text-center w-full rounded px-4 py-2 ml-2"
      on:click={reject}>{"Reject"}</button
    >
  </div>
</div>
