# Django Example

This project demonstrates use of verifiable credentials and presentation  for an
application.

## Dependencies

- Rust ([installation instructions](https://www.rust-lang.org/tools/install))
- Python 3
- Pip

```bash
$ sudo apt update
$ sudo apt install -y python3.6 python3-pip
```

### Python dependencies

- django-qr-code
- didkit
- Django

```bash
$ python3 -m pip install django-qr-code django
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

```bash
$ python3 manage.py migrate
```

To start the server just run:

```bash
$ python3 manage.py runserver
```
