algosec
=======

A Python SDK providing simple access to AlgoSec APIs, including handy methods
to implement common network security policy management tasks, such as:

* Check whether specific traffic is allowed by the firewalls and security devices in the network.
* Open a network security change request.
* Check status of existing change requests.
* Update business application connectivity requirements (and automatically trigger change requests as needed)

Useful for automation and orchestration (e.g. DevOps), building custom portals, or exposing specific functionality to Application Owners, IT, Helpdesk, Information Security, Security Operations, etc.

Included in this package are clients for AlgoSec Firewall Analyzer, FireFlow and BusinessFlow.

Contribution
------------

Contributions are welcome! Please follow the standard pull request process.

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


Deploying To PyPi
----------------

Run::

    python setup.py sdist
    twine upload dist/algosec-*.tar.gz

