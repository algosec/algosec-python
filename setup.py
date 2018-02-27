from codecs import open
from os import path

from setuptools import setup

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="algosec",
    version="0.6.0",
    packages=["algosec"],
    url="https://github.com/algosec/algosec-python",
    license="MIT",
    author="Almog Cohen",
    author_email="support@algosec.com",
    description="The AlgoSec SDK for Python",
    long_description=long_description,
    # TODO: Check how those arguments are shown on PYPI
    keywords="algosec businessflow fireflow firewallanalyzer security policy management network security",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 2.7",
    ],
    tests_require=[
        "nose>=1.3.6",
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
