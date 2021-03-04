#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import errno
import os
import sys
import didkit
flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'python_django.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    try:
        file_handle = os.open('key.jwk', flags)
    except OSError as e:
        if e.errno == errno.EEXIST:
            pass
        else:
            raise
    else:
        with os.fdopen(file_handle, 'w') as file_obj:
            file_obj.write(didkit.generateEd25519Key())

    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
