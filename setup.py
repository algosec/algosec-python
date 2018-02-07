from codecs import open
from os import path

from setuptools import setup

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="algosec",
    version="0.4.0",
    packages=["algosec"],
    url="https://github.com/AlmogCohen/algosec",
    license="MIT",
    author="Almog Cohen",
    description="Set of modules working with Algosec services",
    long_description=long_description,
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        # "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 2.7",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
        "Programming Language :: Python :: 2.7",
    ],
    setup_requires=[
        "nose>=1.3.6",
    ],
    tests_require=[
        "mock>=2.0.0",
        "PyHamcrest>=1.9.0",
    ],
    install_requires=[
        "requests",
        "enum",
        "suds_requests",
        "ipaddress",
    ],
    python_requires='~=2.7'
)
