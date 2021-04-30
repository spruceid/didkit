from setuptools import setup, find_packages
import sys

lib_name = ''
plat = ''
if "linux" in sys.argv[-1]:
    lib_name = "libdidkit.so"
elif "macosx" in sys.argv[-1]:
    lib_name = "libdidkit.dylib"
elif "win" in sys.argv[-1]:
    lib_name = "didkit.dll"
else:
    quit()

setup(
    package_data={'didkit': [lib_name]}
)
