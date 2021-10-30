const path = require('path');
const jest = require('jest');
const help = require('vc-http-api-test-server/services/utilities');
const DIDKitHTTP = require('./didkit-http');

(async () => {

  let {baseUrl, shutdown} = await DIDKitHTTP({
    keyPath: path.join(__dirname, '../key.jwk'),
  });

  let config = {
    name: "DIDKit",
    issueCredentialConfiguration: [
      {
        id: "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD",
        endpoint: baseUrl + "/issue/credentials",
        proofType: "Ed25519Signature2018",
        options: {
          assertionMethod: "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD#z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD"
        },
        credentialStatusesSupported: []
      }
    ],
    verifyCredentialConfiguration: {
      endpoint: baseUrl + "/verify/credentials",
      didMethodsSupported: [ "did:key:", "did:web:", "did:tz:" ],
      linkedDataProofSuitesSupported: [ "Ed25519Signature2018" ],
      credentialStatusesSupported: []
    },
    verifyPresentationConfiguration: {
      endpoint: baseUrl + "/verify/presentations"
    },
    credentials: require('vc-http-api-test-server/__fixtures__/credentials'),
    verifiableCredentials: require('vc-http-api-test-server/__fixtures__/verifiableCredentials'),
    verifiablePresentations: require('vc-http-api-test-server/__fixtures__/verifiablePresentations')
  };

  config.verifiableCredentials = help.filterVerifiableCredentialsByDidMethods(config.verifiableCredentials, config.verifyCredentialConfiguration.didMethodsSupported)
  const { results } = await jest.runCLI(
    {
      json: false,
      roots: [path.join(__dirname, 'vc-api-test-suite', 'packages', 'vc-http-api-test-server')],
      globals: JSON.stringify({ suiteConfig: config }),
      testTimeout: 60e3
    },
    [process.cwd()]
  );

  shutdown();

  process.exit(results.numFailedTests);

})();
