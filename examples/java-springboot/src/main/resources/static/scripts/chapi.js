const MEDIATOR = 'https://authn.theosirian.com/mediator' + '?origin=' + encodeURIComponent(window.location.origin);

$(document).ready(async function() {
  const polyfill = window.credentialHandlerPolyfill;

  await polyfill.loadOnce(MEDIATOR);

  $('#chapi-sign-in').on('click', async function (event) {
    event.preventDefault();

    const credentialQuery = {
      web: {
        VerifiablePresentation: {
          //challenge: uuidv4(),
          domain: "java.theosirian.com",
          query: {
            type: 'QueryByExample',
            credentialQuery: {
              reason: "Login to Demo App",
            },
          },
        },
      },
    };

    const webCredential = await navigator.credentials.get(credentialQuery);
    if (!webCredential) return;

    if (webCredential.type !== 'web') {
      return alert('Invalid web credential type');
    }

    if (webCredential.dataType !== 'VerifiablePresentation') {
      return alert('Invalid web credential data type');
    }

    const vp = webCredential.data;

    $('#chapi-vp').val(JSON.stringify(vp));
    $('#chapi-form').submit();
  });

  $('#chapi-store').on('click', async function (event) {
    event.preventDefault();

    const vc = JSON.parse(document.getElementById('credential').value);
    // https://github.com/digitalbazaar/credential-handler-polyfill#webcredential
    const webCredential = new WebCredential('VerifiableCredential', vc);
    const result = await navigator.credentials.store(webCredential);
  });
});
