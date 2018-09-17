"""Base classes for API clients for AlgoSec services.

Includes base classes for both REST and SOAP API clients. Classes in this file are intended to be inherited by
specific API client implementations. Classes here are used by all three clients currently implemented.

"""
import logging
import traceback
from contextlib import contextmanager

import requests
import suds_requests
from requests import HTTPError
from suds import client, WebFault
from suds.transport import TransportError

from algosec.errors import AlgoSecAPIError

logger = logging.getLogger(__name__)


class APIClient(object):
    """Abstract class inherited by all other API Clients.

    All API clients require the same arguments to be initiated.

    Args:
        server_ip (str): IP address of the AlgoSec server.
        user (str): Username used to log in to AlgoSec.
        password (str): The user's password, similar to the one used to log in to the UI.
        verify_ssl (bool): Turn on/off the connection's SSL certificate verification. Defaults to True.

    Note:
        This class is intended to be inherited. It should not be initiated or used directly in your code.
    """

    def __init__(self, server_ip, user, password, verify_ssl=True):
        super(APIClient, self).__init__()
        self.server_ip = server_ip
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl


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


class RESTAPIClient(APIClient):
    """Abstract REST API class inherited by all REST API clients.

    Currently this class is inherited only by the :class:`~algosec.api_clients.business_flow.BusinessFlowAPIClient`

    Args:
        server_ip (str): IP address of the AlgoSec server.
        user (str): Username used to log in to AlgoSec.
        password (str): The user's password, similar to the one used to log in to the UI.
        verify_ssl (bool): Turn on/off the connection's SSL certificate verification. Defaults to True.

    Note:
        This class should not be used directly but rather inherited to implement any new SOAP API clients.
    """
    def __init__(self, server_ip, user, password, verify_ssl=True):
        super(RESTAPIClient, self).__init__(server_ip, user, password, verify_ssl)
        # Will be initialized once the session is used
        self._session = None

    def _initiate_session(self):  # pragma: no cover
        raise NotImplementedError()

    @property
    def session(self):
        """Return an authenticated ``requests`` session.

        The same session is returned on subsequent calls.

        Returns: Authenticated ``requests`` session.
        """
        if self._session is None:
            self._session = self._initiate_session()
        return self._session

    def _check_api_response(self, response):
        """Check an API response and raise AlgoSecAPIError if needed.

        Args:
            response (requests.Response): Response object returned from an API call.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If any error is found in the response object.

        Returns:
            Same response object passed in.
        """
        try:
            response.raise_for_status()
        except HTTPError:
            try:
                # Try and extract a json for failed responses for better exception description
                content = response.json()
            except ValueError:
                content = response.content
            raise AlgoSecAPIError(
                "response code: {}, content: {}, exception: {}".format(
                    response.status_code,
                    content,
                    traceback.format_exc(),
                ),
                response=response,
                response_content=content,
                status_code=response.status_code,
            )
        return response


class SoapAPIClient(APIClient):
    """Abstract SOAP API class inherited by all SOAP API clients.

    Args:
        server_ip (str): IP address of the AlgoSec server.
        user (str): Username used to log in to AlgoSec.
        password (str): The user's password, similar to the one used to log in to the UI.
        verify_ssl (bool): Turn on/off the connection's SSL certificate verification. Defaults to True.

    Note:
        This class should not be used directly but rather inherited to implement any new SOAP API clients.
    """

    def __init__(self, server_ip, user, password, verify_ssl=True):
        super(SoapAPIClient, self).__init__(server_ip, user, password, verify_ssl)
        self._client = None
        # Used to persist the session id used for security reasons on reoccurring requests
        self._session_id = None

    def _initiate_client(self):  # pragma: no cover
        raise NotImplementedError()

    @property
    def _wsdl_url_path(self):   # pragma: no cover
        raise NotImplementedError()

    @property
    def client(self):
        """Return a suds SOAP client and make sure ``self._session_id`` is populated

        The same session is returned on subsequent calls.
        """
        if self._client is None:
            self._client = self._initiate_client()
        return self._client

    def _get_soap_client(self, wsdl_path, **kwargs):
        """.

        Args:
            wsdl_path (str): The url for the wsdl to connect to.
            **kwargs: Keyword-arguments that are forwarded to the suds client constructor.

        Returns:
            suds.client.Client: A suds SOAP client.
        """
        session = requests.Session()
        session.verify = self.verify_ssl
        # use ``requests`` based suds implementation to handle AlgoSec's self-signed certificate properly.
        with report_soap_failure(AlgoSecAPIError):
            return client.Client(wsdl_path, transport=suds_requests.RequestsTransport(session), **kwargs)
