import mock
import pytest
import requests
import responses
from zeep.transports import Transport
from mock import create_autospec, MagicMock
from requests import Response, HTTPError
from zeep import Client
from zeep.exceptions import Fault, TransportError

from algosec.api_clients.base import APIClient, RESTAPIClient, SoapAPIClient
from algosec.helpers import report_soap_failure
from algosec.errors import AlgoSecAPIError

class TestAPIClient(object):
    def test_init(self):
        APIClient("server-ip", "username", "password", "algobot_login_user", "algobot_login_password", verify_ssl=True)


class TestRESTAPIClient(object):
    @pytest.fixture()
    def rest_client(self, request):
        return RESTAPIClient("server-ip", "username", "password", "algobot_login_user", "algobot_login_password", verify_ssl=True)

    @pytest.fixture()
    def mock_response(self, request):
        response = create_autospec(Response)
        # Add the status_code attribute to the response as it is missing from the auto-spec
        response.status_code = MagicMock()
        return response

    def test_init(self, rest_client):
        assert rest_client._session is None

    def test_session_auto_populate(self, mocker, rest_client):
        mocker.patch.object(RESTAPIClient, "_initiate_session")
        assert rest_client.session == rest_client._initiate_session.return_value

    def test_session_initiate_only_once(self, mocker, rest_client):
        mocker.patch.object(RESTAPIClient, "_initiate_session")
        # Inititate rest_client session creation twice
        rest_client.session
        rest_client.session
        rest_client._initiate_session.assert_called_once_with()

    def test_check_api_response(self, rest_client, mock_response):
        assert rest_client._check_api_response(mock_response) == mock_response
        mock_response.raise_for_status.assert_called_once_with()

    def test_check_api_response__extract_json_on_fail(self, rest_client, mock_response):
        mock_response.raise_for_status.side_effect = HTTPError

        with pytest.raises(AlgoSecAPIError) as e:
            rest_client._check_api_response(mock_response)

        assert e.value.response == mock_response
        assert e.value.response_content == mock_response.json()
        assert e.value.status_code == mock_response.status_code

    def test_check_api_response__use_empty_json_on_fail_with_no_json(
        self, rest_client, mock_response
    ):
        mock_response.raise_for_status.side_effect = HTTPError

        with pytest.raises(AlgoSecAPIError) as e:
            # No json on response
            mock_response.json.side_effect = ValueError
            mock_response.content = response_content = "some-response-content"
            rest_client._check_api_response(mock_response)

        assert e.value.response == mock_response
        assert e.value.response_content == response_content
        assert e.value.status_code == mock_response.status_code


class TestSoapAPIClient(object):
    @pytest.fixture()
    def soap_client(self, request):
        return SoapAPIClient("server-ip", "username", "password", "algobot_login_user", "algobot_login_password", verify_ssl=True)

    def test_init(self, soap_client):
        assert soap_client._client is None
        assert soap_client._session_id is None

    def test_client_auto_populate(self, mocker, soap_client):
        mocker.patch.object(SoapAPIClient, "_initiate_client")
        assert soap_client.client == soap_client._initiate_client.return_value

    def test_client_initiate_only_once(self, mocker, soap_client):
        mocker.patch.object(SoapAPIClient, "_initiate_client")
        # Inititate soap_client client creation twice
        soap_client.client
        soap_client.client
        soap_client._initiate_client.assert_called_once_with()

    @mock.patch("algosec.api_clients.base.mount_adapter_on_session")
    @mock.patch('algosec.api_clients.base.Client', name='zeep')
    def test_get_soap_client(self, Client, mock_session_adapter, soap_client, mocker):
        mocker.patch.object(requests, "Session")
        wsdl_path = "http://some-wsdl-path"
        new_client = soap_client._get_soap_client(wsdl_path)
        session = requests.Session()
        assert session.verify == soap_client.verify_ssl
        assert new_client == Client.return_value
        assert Client.called_once_with(
            wsdl_path, transport=Transport(session=session)
        )
        mock_session_adapter.assert_called_once_with(
            session, soap_client._session_adapter
        )


class TestReportSoapFailure(object):
    @mock.patch('algosec.api_clients.base.Client', name='zeep')
    def test_report_soap_failure__detailed_transport_error(self,Client):
        wsdl_path = "http://some-wsdl-path"
        api_error = "some error description"
        Client.side_effect = TransportError(status_code=500, content=api_error)

        with pytest.raises(AlgoSecAPIError) as e:
            with report_soap_failure(AlgoSecAPIError):
                # Force an api soap call, that is destined to fail
                Client(wsdl_path, transport=Transport())

        assert "status_code: 500" in str(e)
        assert api_error in str(e)

    def test_report_soap_failure__webfault_is_fetched(self):
        """See that webfault is translated into AlgoSecAPIError"""
        with pytest.raises(AlgoSecAPIError):
            with report_soap_failure(AlgoSecAPIError):
                raise Fault("Some Error")

    def test_report_soap_failure__no_failure(self):
        # See that no exception is raised
        with report_soap_failure(AlgoSecAPIError):
            pass
