export const MEDIATOR =
  "https://authn.theosirian.com/mediator" +
  "?origin=" +
  encodeURIComponent(location.origin);

export const WALLET_LOCATION = location.origin + "/";

export const WALLET_GET = "wallet-get";
export const WALLET_STORE = "wallet-store";
export const WALLET_WORKER = "wallet-worker";

export const WALLET_GET_URL = WALLET_LOCATION + WALLET_GET;
export const WALLET_STORE_URL = WALLET_LOCATION + WALLET_STORE;
export const WALLET_WORKER_URL = WALLET_LOCATION + WALLET_WORKER;

export default {
  MEDIATOR,
  WALLET_LOCATION,
  WALLET_GET,
  WALLET_STORE,
  WALLET_WORKER,
  WALLET_GET_URL,
  WALLET_STORE_URL,
  WALLET_WORKER_URL,
};
