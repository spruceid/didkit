<script lang="ts">
  import {
    Form,
    FormButton,
    FormError,
    FormPassword,
    FormTextField,
  } from "../component";
  import { createStorage } from "../../storage.ts";
  import { v4 as uuid } from "uuid";
  import { navigate } from "svelte-navigator";

  let username = "";
  let password = "";
  let error = "";

  const clear = () => {
    username = "";
    password = "";
  };

  const onSubmit = () => {
    error = "";

    if (username === "") {
      error = "Please fill your username";
    } else if (password === "") {
      error = "Please fill your password";
    } else {
      const user = localStorage.getItem(username);
      const verification = uuid();

      if (user !== null) {
        error = "Account already exists";
      } else {
        const storage = createStorage(username, password);
        localStorage.setItem(username, verification);
        storage.setItem("verification", verification);
        storage.setItem("key", JSON.parse(DIDKit.generateEd25519Key()));
        clear();
        navigate("/sign-in");
      }
    }
  };
</script>

<Form on:submit={onSubmit}>
  <span slot="title">Sign Up</span>
  <span slot="subtitle">
    Create an account by providing your username and password.
  </span>

  {#if error && error !== ""}
    <FormError>{error}</FormError>
  {/if}

  <FormTextField bind:value={username} placeholder="Username" name="username" />
  <FormPassword bind:value={password} placeholder="Password" name="password" />
  <FormButton>Sign Up</FormButton>
</Form>
