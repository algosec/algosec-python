"""Helper functions and classes used internally by the package and the API clients.

Note:
    Most developers will not have to use any of the contents of this module directly.
"""

import six
from ipaddress import IPv4Network, AddressValueError, NetmaskValueError
from requests.adapters import HTTPAdapter


class AlgoSecServersHTTPAdapter(HTTPAdapter):
    """HTTP adapter to customize ``requests`` sessions with AlgoSec's servers.

    Currently this adapter is making the following adaptations to the request:

    * Setting the default connect and read timeout.
        This connect timeout prevent the connections from hanging when the server is unreachable.
    """
    ALGOSEC_SERVER_CONNECT_TIMEOUT = 5
    ALGOSEC_SERVER_READ_TIMEOUT = None

    def __init__(self, *args, **kwargs):
        super(AlgoSecServersHTTPAdapter, self).__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs['timeout'] = (self.ALGOSEC_SERVER_CONNECT_TIMEOUT, self.ALGOSEC_SERVER_READ_TIMEOUT)
        return super(AlgoSecServersHTTPAdapter, self).send(*args, **kwargs)


def mount_algosec_adapter_on_session(session):
    """Used to mount the ``AlgoSecServersHTTPAdapter`` on a ``requests`` session.

    The adapter is mounted for all HTTP/HTTPS calls.

    Args:
        session (requests.Session): The requests session to mount the AlgoSec adapter on.
    """
    session.mount('https://', AlgoSecServersHTTPAdapter())
    session.mount('http://', AlgoSecServersHTTPAdapter())


def is_ip_or_subnet(string):
    """Return true if the given string if an IPv4 address or a subnet.

    Args:
        string (str): The string to check.

    Returns:
        bool: True if the given argument is IPv4 address or a subnet.
    """
    try:
        # string must be unicode for this package
        IPv4Network(six.text_type(string))
        return True
    except (AddressValueError, NetmaskValueError, ValueError):
        return False
