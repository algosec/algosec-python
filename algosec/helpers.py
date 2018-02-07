import re

from ipaddress import IPv4Network, AddressValueError
from requests.adapters import HTTPAdapter

from algosec.errors import UnrecognizedServiceString


PROTO_PORT_PATTERN = "(?P<protocol>(?:UDP|TCP))/(?P<port>\d+|\*)"


class AlgosecServersHTTPAdapter(HTTPAdapter):
    """
    This adapter is used to customize http requests sessions we have with Algosec's servers

    Setting the default connect and read timeout. This timeout will prevent the bot from being stuck when the server
    is not responsive
    """
    ALGOSEC_SERVER_CONNECT_TIMEOUT = 5
    ALGOSEC_SERVER_READ_TIMEOUT = None

    def __init__(self, *args, **kwargs):
        super(AlgosecServersHTTPAdapter, self).__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs['timeout'] = (self.ALGOSEC_SERVER_CONNECT_TIMEOUT, self.ALGOSEC_SERVER_READ_TIMEOUT)
        return super(AlgosecServersHTTPAdapter, self).send(*args, **kwargs)


def mount_algosec_adapter_on_session(session):
    session.mount('https://', AlgosecServersHTTPAdapter())
    session.mount('http://', AlgosecServersHTTPAdapter())


def is_ip_or_subnet(string):
    try:
        # string must be unicode for this package
        IPv4Network(unicode(string))
        return True
    except AddressValueError:
        return False


class LiteralService(object):
    """
    Represent a protocol/proto service originated in a simple string

    e.g: tcp/50, tcp/*, *
    """
    ALL = "*"

    def __init__(self, service):
        # We upper the service since services are represented with upper when returned from Algosec
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
        proto_port_match = re.match(PROTO_PORT_PATTERN, string, re.IGNORECASE)
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

