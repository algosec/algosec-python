from codecs import open

from setuptools import setup, find_packages

# Get the long description from the README file
with open('README.rst') as f:
    long_description = f.read()

setup(
    name='algosec',
    version='1.2.0',
    packages=find_packages(exclude=['tests', 'tests.*']),
    url='https://github.com/algosec/algosec-python',
    license='MIT',
    author='Almog Cohen',
    author_email='support@algosec.com',
    description='The AlgoSec SDK for Python',
    long_description=long_description,
    keywords='algosec businessflow fireflow firewallanalyzer security policy management network security',
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    install_requires=[
        'requests',
        'enum34',
        'suds-jurko>=0.6',
        'suds_requests>=0.4.0',
        'ipaddress',
        'six',
        'deprecated',
    ],
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
)
