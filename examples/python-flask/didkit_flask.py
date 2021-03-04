from socket import socket, AF_INET, SOCK_DGRAM
from flask import Flask, request, render_template, jsonify
from issue_credential import issueCredential
from flask_qrcode import QRcode
from didkit import generateEd25519Key
import errno
import os
import json

app = Flask(__name__)
qrcode = QRcode(app)


@app.route('/')
def index():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()

    url = (request.is_secure and "https://" or "http://") + IP + \
        ":" + request.host.split(':')[-1] + "/wallet"

    return render_template('index.html', url=url)


@app.route('/credential', methods=['GET', 'POST'])
def credential():
    credential = json.dumps(issueCredential(request), indent=2, sort_keys=True)

    return render_template('credential.html', credential=credential)


@app.route('/wallet', methods=['GET', 'POST'])
def wallet():
    credential = issueCredential(request)
    if request.method == 'GET':
        return jsonify({
            "type": "CredentialOffer",
            "credentialPreview": credential
        })

    elif request.method == 'POST':
        return jsonify(credential)


if __name__ == '__main__':
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        file_handle = os.open('key.jwk', flags)
    except OSError as e:
        if e.errno == errno.EEXIST:
            pass
        else:
            raise
    else:
        with os.fdopen(file_handle, 'w') as file_obj:
            file_obj.write(generateEd25519Key())
    app.run(host='0.0.0.0')
