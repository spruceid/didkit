<script lang="ts">
  import { NavItem } from "../component";
  import { walletState } from "../../store.ts";
  import { navigate } from "svelte-navigator";

  const logout = (event) => {
    event.preventDefault();
    walletState.set(null);
    navigate("/");
  };
</script>

<NavItem on:click={logout}>Logout</NavItem>
