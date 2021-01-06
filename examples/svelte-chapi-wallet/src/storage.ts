import Crypto from "crypto-es";
import SecureStorage from "secure-web-storage";

export const createStorage = (
  username: string,
  password: string
): SecureStorage => {
  return new SecureStorage(localStorage, {
    hash: (key: string): string => {
      return Crypto.HmacSHA256(`${username}/${key}`, password).toString();
    },
    encrypt: (data: any): string => {
      return Crypto.AES.encrypt(data, password).toString();
    },
    decrypt: (data: any): string => {
      return Crypto.AES.decrypt(data, password).toString(Crypto.enc.Utf8);
    },
  });
};
