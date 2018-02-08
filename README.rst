algosec
=======

Framework tools and api clients to manage your on on-premises Algosec services using Python.
Clients are implemented for the following AlgoSec services:

* Algosec BusinessFlow
* Algosec FireFlow
* Algosec FirewallAnalyzer

Contribution
------------

Currently the SDK is still pretty basic. Every contribution will be welcome with a proper PR :)

Developing
----------

To setup the project for local development, make sure you have a Python 2.7 virtualenv setup::

    mkvirtualenv --python=python2.7 algobotframeworkenv -a .

and then to install the package run::

    pip install -e .

This will install all the dependencies and set the project up for local usage and development .


Testing
_______

To run the unittests run::

    python setup.py nosetests


Deplying To PyPi
----------------

Run::

    python setup.py sdist
    twine upload dist/algosec-*.tar.gz

