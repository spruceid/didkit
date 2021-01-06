import type { Writable } from "svelte/store";
import { writable } from "svelte/store";

export type Wallet = {
  storage: any;
  username: string;
};

export type WalletState = Wallet | null;
export const walletState: Writable<WalletState> = writable(null);

export const minimalState: Writable<boolean> = writable(false);
