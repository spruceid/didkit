declare module "didkit" {
  declare interface Ed25519Key {
    kty: string;
    crv: string;
    x: string;
    d: string;
  }

  declare type Key = Ed25519Key | any;

  declare interface Options {
    proofPurpose?: string;
    verificationMethod?: string;
    challenge?: string;
    domain?: string;
    created?: string;
  }

  declare interface VerifyResult {
    errors: string[];
    warnings: string[];
    checks: string[];
  }

  declare type Method =
    | "key"
    | "tz"
    | "web"
    | "ethr"
    | "onion"
    | "pkh"
    | "sol"
    | string;

  function getVersion(): string;
  function generateEd25519Key(): Ed25519Key;

  function keyToDID(method: Method, key: Key): string;
  function keyToVerificationMethod(method: Method, key: Key): string;

  function issueCredential(vc: any, options: Options, key: Key): any;
  function verifyCredential(vc: any, options: Options): VerifyResult;

  function issuePresentation(vp: any, options: Options, key: Key): any;
  function verifyPresentation(vp: any, options: Options): VerifyResult;

  function DIDAuth(did: string, options: Options, key: Key): string;
}
