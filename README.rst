==================
AlgoSec Python SDK
==================

.. start-badges

.. list-table::
    :stub-columns: 1

    * - docs
      - |docs|
    * - tests
      - | |travis| |coverage|
    * - package
      - | |version| |wheel| |supported-versions|


.. |version| image:: https://img.shields.io/pypi/v/algosec.svg
   :target: https://pypi.python.org/pypi/algosec
   :alt: Package on PyPi

.. |docs| image:: https://readthedocs.org/projects/algosec-python/badge/
   :target: http://algosec-python.readthedocs.io/en/latest/
   :alt: Documentation Status

.. |coverage| image:: https://coveralls.io/repos/github/algosec/algosec-python/badge.svg
    :target: https://coveralls.io/github/algosec/algosec-python

.. |travis| image:: https://travis-ci.org/algosec/algosec-python.svg?branch=master
    :target: https://travis-ci.org/algosec/algosec-python

.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/algosec.svg
    :alt: Supported versions
    :target: https://pypi.python.org/pypi/algosec

.. |wheel| image:: https://img.shields.io/pypi/wheel/algosec.svg
    :alt: PyPI Wheel
    :target: https://pypi.python.org/pypi/algosec


A Python SDK providing simple access to AlgoSec APIs, including handy methods
to implement common network security policy management tasks, such as:

* Check whether specific traffic is allowed by the firewalls and security devices in the network.
* Open a network security change request.
* Check status of existing change requests.
* Update business application connectivity requirements (and automatically trigger change requests as needed)

Useful for automation and orchestration (e.g. DevOps), building custom portals, or exposing specific functionality to Application Owners, IT, Helpdesk, Information Security, Security Operations, etc.

Included in this package are clients for AlgoSec Firewall Analyzer, FireFlow and BusinessFlow.

Installation
------------

Install the latest version from PyPi by running::

    pip install algosec --upgrade

or clone this repo and run::

    python setup.py install


Contribution
------------

Contributions are welcome! Please follow the standard pull request process.

Documentation
-------------

.. image:: https://readthedocs.org/projects/algosec-python/badge/
   :target: https://algosec-python.readthedocs.io/en/latest/
   :alt: Documentation Status


Documentation available online at: https://algosec-python.readthedocs.io/en/latest/

How to build doc's locally?
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Using Spinx::

    $ cd docs
    $ make html

Then see the ``docs/_build`` folder created for the html files.

Developing
----------

To install the package for local development just run::

   pipenv install

This will install all the dependencies and set the project up for local usage and development .


Testing
^^^^^^^

To run the unittests for all supported python versions, simply run::

    tox

