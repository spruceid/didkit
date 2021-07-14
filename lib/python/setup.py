#! /usr/bin/env python3
import os
from sys import platform
from setuptools import setup, Extension

##Determine what system we are building on to determine what type of shared object has been built and needs copyingthis differs between OS's (e.g. libdidkit.so vs libdidkit.dylib vs libdidkit.dll)
didpath = "didkit"
so_filename = "libdidkit"
if platform == "linux" or platform == "linux2":
    LIBDIDKIT_SHARE_OBJ = os.path.join(didpath, '%s.so'%(so_filename))
elif platform == "darwin":
    LIBDIDKIT_SHARE_OBJ = os.path.join(didpath, '%s.dylib'%(so_filename))
else:
    LIBDIDKIT_SHARE_OBJ = os.path.join(didpath, '%s.dll'%(so_filename))

## All other static build variables comes from setup.cfg
setup_args = dict(
    data_files = [ ("" , [LIBDIDKIT_SHARE_OBJ] ) ]
)

setup(**setup_args)