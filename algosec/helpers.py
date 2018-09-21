"""Helper functions and classes used internally by the package and the API clients.

Note:
    Most developers will not have to use any of the contents of this module directly.
"""
import logging
from contextlib import contextmanager

import six
from ipaddress import IPv4Network, AddressValueError, NetmaskValueError
from requests.adapters import HTTPAdapter
from suds import WebFault
from suds.plugin import MessagePlugin
from suds.transport import TransportError


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


@contextmanager
def report_soap_failure(exception_to_raise):
    """
    Handle soap calls and raise proper exception when needed.

    Used as a context manager by wrapping the code blocks with soap calls

    Args:
        exception_to_raise (algosec.errors.AlgoSecAPIError): The exception type that should be
            raised in case of execution failure.

    Returns:
        Nothing. Used as
    """
    reason = "SOAP API call failed."
    try:
        yield
    except WebFault:
        # Handle exceptions in SOAP logical level
        raise exception_to_raise(reason)
    except TransportError as e:
        # Handle exceptions at the transport layer
        # For example, when getting status code 500 from the server upon mere HTTP request
        # This code assumes that the transport error is raised by the suds_requests package.
        status_code = e.httpcode
        response_content = e.fp.read()
        reason += ' status_code: {}, response_content: {}'.format(status_code, response_content)
        raise exception_to_raise(
            reason,
            status_code=status_code,
            response_content=response_content,
        )


# LogSOAPMessages inherit from `object` as the `MessagePlugin` is not defined as new-style class object
class LogSOAPMessages(MessagePlugin, object):
    """Used to send soap log messages into the builtin logging module"""
    LOG_LEVEL = logging.DEBUG

    def __init__(self):
        self.log = logging.getLogger(__name__)
        super(LogSOAPMessages, self).__init__()

    def sending(self, context):
        self.log.log(self.LOG_LEVEL, "Sending SOAP message: {}".format(str(context.envelope)))

    def received(self, context):
        self.log.log(self.LOG_LEVEL, "Received SOAP message: {}".format(str(context.reply)))
