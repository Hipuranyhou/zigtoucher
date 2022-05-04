# NOTE: Dependencies are taken care of in our setup script, because we modify some of them

from __future__ import print_function
import sys

try:
    from setuptools import setup, Extension
except ImportError:
    print("No setuptools found, attempting to use distutils instead.")
    from distutils.core import setup, Extension

zigbee_crypt = Extension(
    "zigbee_crypt",
    sources=["extensions/zigbee_crypt/zigbee_crypt.c"],
    libraries=["gcrypt"],
    include_dirs=["/usr/local/include", "/usr/include", "/sw/include/", "zigbee_crypt"],
    library_dirs=["/usr/local/lib", "/usr/lib", "/sw/var/lib/"],
)

setup(
    name="zigtoucher",
    version="0.0.1b2",
    description="Advanced ZigBee Touchlink sniffer and packet sender",
    author="Jakub Šatoplet",
    author_email="satopja2@fit.cvut.cz",
    license="",
    packages=[
        "zigtoucher",
        "zigtoucher.mode",
        "zigtoucher.zigbee",
        "zigtoucher.zigbee.touchlink",
    ],
    scripts=["scripts/zigtoucher"],
    install_requires=[],
    ext_modules=[zigbee_crypt],
)
