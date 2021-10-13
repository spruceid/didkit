#! /usr/bin/env python3
import os
import platform
from setuptools import setup, Extension

##Determine what system we are building on to determine what type of shared object has been built and needs copyingthis differs between OS's (e.g. libdidkit.so vs libdidkit.dylib vs libdidkit.dll)
didpath = "didkit"
host_os = platform.system()

if host_os == "Linux":
    LIBDIDKIT_SHARE_OBJ = os.path.join(didpath, 'libdidkit.so')
elif host_os == "Darwin":
    LIBDIDKIT_SHARE_OBJ = os.path.join(didpath, 'libdidkit.dylib')
elif host_os == "Windows":
    LIBDIDKIT_SHARE_OBJ = os.path.join(didpath, 'didkit.dll')
else:
    raise RuntimeError("System type %s unsupported. Exiting setup."%(host_os))

## All other static build variables comes from setup.cfg
setup_args = dict(
    data_files = [ ("" , [LIBDIDKIT_SHARE_OBJ] ) ]
)

setup(**setup_args)