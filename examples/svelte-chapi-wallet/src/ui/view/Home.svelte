<script lang="ts">
  import { Link } from "svelte-navigator";
  import { installHandler } from "web-credential-handler";

  import Config from "../../config.ts";

  const onClick = async (event) => {
    event.preventDefault();

    try {
      await credentialHandlerPolyfill.loadOnce(Config.MEDIATOR);
    } catch (e) {
      console.error("Error in loadOnce:", e);
    }

    const registration = await installHandler({
      url: Config.WALLET_WORKER_URL,
    });

    await registration.credentialManager.hints.set("test", {
      name: "User",
      enabledTypes: ["VerifiablePresentation", "VerifiableCredential"],
    });

    console.log("Wallet registered!");
  };

  const linkStyle =
    "text-sm font-medium text-center " +
    "visited:text-black hover:no-underline " +
    "border border-gray-300 rounded " +
    "w-full px-4 py-2 my-1";

  let version = "";
  DIDKitLoader.loadDIDKit().then(({ getVersion }) => {
    console.log("Loaded DIDKit v" + getVersion());
    version = getVersion();
  });
</script>

<div
  class="flex flex-col justify-center container w-1/3 shadow rounded mx-auto my-8 px-3 py-4"
>
  <Link class={linkStyle} to="/sign-in">
    {"Sign In"}
  </Link>
  <Link class={linkStyle} to="/sign-up">
    {"Sign Up"}
  </Link>
  <a class={linkStyle} href={"#"} on:click={onClick}>
    {"Register Wallet"}
  </a>
  <span class="text-center text-xs mt-2">{"using DIDKit v" + version}</span>
</div>
