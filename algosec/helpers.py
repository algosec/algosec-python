"""Helper functions and classes used internally by the package and the API clients.

Note:
    Most developers will not have to use any of the contents of this module directly.
"""
import logging
from contextlib import contextmanager

import six
import re
from ipaddress import IPv4Network, AddressValueError, NetmaskValueError
from requests.adapters import HTTPAdapter
from zeep.exceptions import TransportError, Fault

from algosec.errors import UnauthorizedUserException

logger = logging.getLogger(__name__)

class AlgoSecServersHTTPAdapter(HTTPAdapter):
    """HTTP adapter to customize ``requests`` sessions with AlgoSec's servers.

    Currently this adapter is making the following adaptations to the request:

    * Setting the default connect and read timeout.
        This connect timeout prevent the connections from hanging when the server is unreachable.
    """

    ALGOSEC_SERVER_CONNECT_TIMEOUT = 15
    ALGOSEC_SERVER_READ_TIMEOUT = None

    def __init__(self, *args, **kwargs):
        super(AlgoSecServersHTTPAdapter, self).__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs["timeout"] = (
            self.ALGOSEC_SERVER_CONNECT_TIMEOUT,
            self.ALGOSEC_SERVER_READ_TIMEOUT,
        )
        return super(AlgoSecServersHTTPAdapter, self).send(*args, **kwargs)


def mount_adapter_on_session(session, adapter):
    """Used to mount the ``AlgoSecServersHTTPAdapter`` on a ``requests`` session.

    The adapter is mounted for all HTTP/HTTPS calls.

    Args:
        session (requests.Session): The requests session to mount the AlgoSec adapter on.
        adapter (HTTPAdapter): The adapter to mount on the session
    """
    session.mount("https://", adapter)
    session.mount("http://", adapter)


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
    # unauthorized user exception, re-raised to handler to inform user that he has no permissions for this action.
    except UnauthorizedUserException as e:
        logger.debug(e.extra_details)
        raise

    except Fault as e:
        # Handle exceptions in SOAP logical level
        all_args_are_strings = (
            hasattr(e, "args")
            and isinstance(e.args, tuple)
            and all(isinstance(i, str) for i in e.args)
        )
        if all_args_are_strings:
            reason = ", ".join(e.args)
        raise exception_to_raise(reason)
    except TransportError as e:
        # Handle exceptions at the transport layer
        # For example, when getting status code 500 from the server upon mere HTTP request
        # This code assumes that the transport error is raised by the zeep package.
        status_code = e.status_code
        response_content = e.content
        reason += " status_code: {}, response_content: {}".format(
            status_code, response_content
        )
        raise exception_to_raise(
            reason, status_code=status_code, response_content=response_content
        )

#TODO: check if LogSOAPMessages is necessary or it may be removed.

class LogSOAPMessages(object):
    """Used to send soap log messages into the builtin logging module"""

    LOG_LEVEL = logging.DEBUG

    def __init__(self):
        self.log = logging.getLogger(__name__)
        super(LogSOAPMessages, self).__init__()

    def sending(self, context):
        self.log.log(
            self.LOG_LEVEL, "Sending SOAP message: {}".format(str(context.envelope))
        )

    def received(self, context):
        self.log.log(
            self.LOG_LEVEL, "Received SOAP message: {}".format(str(context.reply))
        )


class IPHelper(object):
    """
        A class for testing if strings are certain types of IP addresses,
        and handling IPs in algosec python package.
    """


    IP_PATTERN = (
        '([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])' +
        '\\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])'
    )

    SINGLE_IP_PATTERN = '^{}$'.format(IP_PATTERN)

    IP_RANGE_PATTERN = '^({0})-({0})$'.format(IP_PATTERN)

    CIDR_PATTERN = '^{}/([12][0-9]|[3][0-2]|[1-9])$'.format(IP_PATTERN)

    @staticmethod
    def is_single_ip(address):
        """

        Args:
            address (str): A string to test if it's an address.

        Returns:
            bool: True if the given argument is a single ip address.
        """
        # 'not not' is a shorthand for using the boolean trait of a python object.
        return not not re.match(IPHelper.SINGLE_IP_PATTERN, address)

    @staticmethod
    def is_ip_range(ip_range):
        """

        Args:
            ip_range (str): A string to test if it's an ip_range

        Returns:
            bool: True if the given argument is an ip range
        """
        # 'not not' is a shorthand for using the boolean trait of a python object.
        return not not re.match(IPHelper.IP_RANGE_PATTERN, ip_range)

    @staticmethod
    def is_cidr(cidr):
        """

        Args:
            cidr (str): A string to test if it's a cidr.

        Returns:
            bool: True if the given argument is a cidr.
        """
        # 'not not' is a shorthand for using the boolean trait of a python object.
        return not not re.match(IPHelper.CIDR_PATTERN, cidr)

    @staticmethod
    def is_network_address(network_object):
        """

        Args:
            network_object (str): A string to test if it's a network object.

        Returns:
            bool: True if the given argument is a network object.
        """
        return (IPHelper.is_single_ip(network_object) or IPHelper.is_ip_range(network_object)
                or IPHelper.is_cidr(network_object))