"""Base classes for API clients for AlgoSec services.

Includes base classes for both REST and SOAP API clients. Classes in this file are intended to be inherited by
specific API client implementations. Classes here are used by all three clients currently implemented.

"""
import logging
import traceback

import requests
from requests import HTTPError
from zeep import Client
from zeep.transports import Transport
from zeep.settings import Settings

from algosec.constants import PLACEHOLDER_EMAIL
from algosec.errors import AlgoSecAPIError
from algosec.helpers import (
    report_soap_failure,
    LogSOAPMessages,
    mount_adapter_on_session,
    AlgoSecServersHTTPAdapter,
)

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
    _impersonation_success = False

    def __init__(
        self,
        server_ip,
        user,
        password,
        algobot_login_user,
        algobot_login_password,
        user_email=PLACEHOLDER_EMAIL,
        afa_sess_id=None,
        verify_ssl=True,
        session_adapter=AlgoSecServersHTTPAdapter,
    ):
        super(APIClient, self).__init__()
        self.server_ip = server_ip
        self.user = user
        self.password = password
        self.algobot_login_user = algobot_login_user
        self.algobot_login_password = algobot_login_password
        self.user_email = user_email
        self.afa_sess_id = afa_sess_id
        self.verify_ssl = verify_ssl
        self._session_adapter = session_adapter()
        self._api_info_string = "API: {}\nurl: {}\nrequest: {}\n"


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

    def __init__(
        self,
        server_ip,
        user,
        password,
        algobot_login_user,
        algobot_login_password,
        user_email=PLACEHOLDER_EMAIL,
        afa_sess_id=None,
        verify_ssl=True,
        session_adapter=AlgoSecServersHTTPAdapter,
    ):
        super(RESTAPIClient, self).__init__(
            server_ip, user, password, algobot_login_user, algobot_login_password, user_email, afa_sess_id, verify_ssl, session_adapter
        )
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
                    response.status_code, content, traceback.format_exc()
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

    def __init__(
        self,
        server_ip,
        user,
        password,
        algobot_login_user,
        algobot_login_password,
        user_email=PLACEHOLDER_EMAIL,
        afa_sess_id=None,
        verify_ssl=True,
        session_adapter=AlgoSecServersHTTPAdapter,
    ):
        super(SoapAPIClient, self).__init__(
            server_ip, user, password, algobot_login_user, algobot_login_password, user_email, afa_sess_id, verify_ssl, session_adapter
        )
        self._client = None
        # Used to persist the session id used for security reasons on reoccurring requests
        self._session_id = None
        self._service = None

    def _initiate_client(self):  # pragma: no cover
        raise NotImplementedError()

    @property
    def _wsdl_url_path(self):  # pragma: no cover
        raise NotImplementedError()

    @property
    def _soap_service_location(self):  # pragma: no cover
        raise NotImplementedError()

    @property
    def client(self):
        """Return a zeep SOAP client and make sure ``self._session_id`` is populated

        The same session is returned on subsequent calls.
        """
        if self._client is None:
            self._client = self._initiate_client()
        return self._client

    def _get_soap_client(self, wsdl_path, **kwargs):
        """.

        Args:
            wsdl_path (str): The url for the wsdl to connect to.
            **kwargs: Keyword-arguments that are forwarded to the zeep client constructor.

        Returns:
            zeep.Client: A zeep SOAP client.
        """
        session = requests.Session()
        mount_adapter_on_session(session, self._session_adapter)
        session.verify = self.verify_ssl

        with report_soap_failure(AlgoSecAPIError):
            return Client(
                wsdl_path,
                transport=Transport(session=session),
                settings=Settings(strict=False, xsd_ignore_sequence_order=True)
            )
