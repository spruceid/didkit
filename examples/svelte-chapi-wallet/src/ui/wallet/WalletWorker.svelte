<script lang="ts">
  import { activateHandler } from "web-credential-handler";

  import Config from "../../config.ts";
  import { minimalState } from "../../store.ts";

  minimalState.set(true);

  const activateWalletEventHandler = async () => {
    try {
      await credentialHandlerPolyfill.loadOnce(Config.MEDIATOR);
      await DIDKitLoader.loadDIDKit();
    } catch (e) {
      console.error("Error in loadOnce:", e);
    }

    return activateHandler({
      mediatorOrigin: Config.MEDIATOR,
      async get(event) {
        return {
          type: "redirect",
          url: Config.WALLET_GET_URL,
        };
      },
      async store(event) {
        return {
          type: "redirect",
          url: Config.WALLET_STORE_URL,
        };
      },
    });
  };

  activateWalletEventHandler();
</script>
