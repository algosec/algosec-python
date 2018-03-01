"""Helper functions and classes used internally by the package and the API clients.

Note:
    Most developers will not have to use any of the contents of this module directly.
"""
import re

from ipaddress import IPv4Network, AddressValueError
from requests.adapters import HTTPAdapter

from algosec.errors import UnrecognizedServiceString


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
        IPv4Network(unicode(string))
        return True
    except AddressValueError:
        return False


# TODO: Add unittests for this helper.
class LiteralService(object):
    """Class to represent and interact with a *protocol/proto* service string.

    Args:
        service (string): The service string to represent. (e.g. tcp/200, *, udp/*)

    Attributes:
          protocol (string): The protocol portion of the service string.
          port (string): The port portion of the service string.
          service (string): Uppercase version of the service string.



    Examples:
        To check if a given string represents a *protocol/proto*::

            LiteralService.is_protocol_string("unsupported-service-name") # Returns False
            LiteralService.is_protocol_string("tcp/50") # Returns True
            LiteralService.is_protocol_string("tcp/*") # Returns True
            LiteralService.is_protocol_string("*") # Returns True

        To represent a service string object::

            service = LiteralService("udp/200")
            service.protocol # Returns *udp*
            service.port # Returns *200*

        Or to check equilibrium::

            LiteralService("udp/200") == LiteralService("UDP/200") # Returns True
    """
    PROTO_PORT_PATTERN = "(?P<protocol>(?:UDP|TCP))/(?P<port>\d+|\*)"
    ALL = "*"

    def __init__(self, service):
        # TODO: Once all the uppercase / lowercase issues are solved on BusinessFlow APIs, this line can be removed.
        # TODO: When it is removed, update the ``__eq__`` method to ``.upper()`` the service string of both objects.
        self.service = service.upper()

        protocol, port = self._parse_string(self.service)
        self.protocol = protocol
        self.port = port

    @classmethod
    def _parse_string(cls, string):
        # If the string if just *, both the protocol and port are *
        if string == cls.ALL:
            return cls.ALL, cls.ALL

        # Now try and match and parse regular "protocol/port" pattern
        proto_port_match = re.match(cls.PROTO_PORT_PATTERN, string, re.IGNORECASE)
        if not proto_port_match:
            raise UnrecognizedServiceString("Unable to parse literal service name: {}".format(string))

        port = proto_port_match.groupdict()["port"]
        protocol = proto_port_match.groupdict()["protocol"]
        return protocol, port

    @classmethod
    def is_protocol_string(cls, string):
        try:
            cls._parse_string(string)
            return True
        except UnrecognizedServiceString:
            return False

    def __hash__(self):
        return hash(self.service)

    def __eq__(self, other):
        return self.service == other.service

    def __ne__(self, other):
        # Not strictly necessary, but to avoid having both x==y and x!=y
        # True at the same time
        return not (self == other)

    def __str__(self):
        return self.service

    def __repr__(self):
        return "<LiteralService {}>".format(self.service)
