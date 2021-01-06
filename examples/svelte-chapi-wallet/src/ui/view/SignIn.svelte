<script lang="ts">
  import { navigate } from "svelte-navigator";
  import queryString from "query-string";

  import {
    Form,
    FormButton,
    FormError,
    FormTextField,
    FormPassword,
  } from "../component";

  import { createStorage } from "../../storage.ts";
  import { walletState } from "../../store";

  let username = "";
  let password = "";
  let error = "";

  let redirect = queryString.parse(location?.search)?.redirect || "/";

  const onSubmit = () => {
    error = "";

    if (username === "") {
      error = "Please fill your username";
    } else if (password === "") {
      error = "Please fill your password";
    } else {
      const user = localStorage.getItem(username);
      const storage = createStorage(username, password);
      const verification = storage.getItem("verification");

      if (user === null) {
        error = "Account does not exist";
      } else if (user !== verification) {
        error = "Invalid username and password combination";
      } else {
        walletState.set({ storage, username });
        navigate(redirect, { replace: true });
      }
    }
  };
</script>

<Form on:submit={onSubmit}>
  <span slot="title">Sign In</span>
  <span slot="subtitle">
    Sign in into your wallet with username and password.
  </span>

  {#if error && error !== ""}
    <FormError>{error}</FormError>
  {/if}

  <FormTextField bind:value={username} placeholder="Username" name="username" />
  <FormPassword bind:value={password} placeholder="Password" name="password" />
  <FormButton>Sign In</FormButton>
</Form>
