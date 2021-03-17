# Flask Example

This project demonstrates use of verifiable credentials and presentation  for an
application.

## Dependencies

- Rust ([installation instructions](https://www.rust-lang.org/tools/install))
- Python 3
- Pip
- Python 3 virtual environment

```bash
$ sudo apt update
$ sudo apt install -y python3.6 python3-pip python3-virtualenv python3-venv
```

### Python dependencies

- flask-qrcode
- Flask
- didkit

```bash
$ python3 -m pip install flask-qrcode flask
```

### Building DIDKit

DIDKit is used to handle credentials and presentations, since it's not yet
publically available in PyPI manual installation is required.

To do so got to the root folder of this repository and run:
```bash
$ make -C lib ../target/test/python.stamp
```

## Running

For the first time running you will need to run the migrations,
this can be accomplished by running the following command:

To start the server just run:

```bash
$ FLASK_APP=didkit_flask.py python3 didkit_flask.py
```
