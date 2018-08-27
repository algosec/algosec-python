import pytest
import requests
import suds_requests
from mock import create_autospec, MagicMock
from requests import Response, HTTPError
from suds import client

from algosec.api_clients.base import APIClient, RESTAPIClient, SoapAPIClient
from algosec.errors import AlgoSecAPIError


class TestAPIClient(object):
    def test_init(self):
        APIClient(
            'server-ip',
            'username',
            'password',
            verify_ssl=True
        )


class TestRESTAPIClient(object):
    @pytest.fixture()
    def rest_client(self, request):
        return RESTAPIClient(
            'server-ip',
            'username',
            'password',
            verify_ssl=True
        )

    @pytest.fixture()
    def mock_response(self, request):
        response = create_autospec(Response)
        # Add the status_code attribute to the response as it is missing from the auto-spec
        response.status_code = MagicMock()
        return response

    def test_init(self, rest_client):
        assert rest_client._session is None

    def test_session_auto_populate(self, mocker, rest_client):
        with mocker.patch.object(RESTAPIClient, '_initiate_session'):
            assert rest_client.session == rest_client._initiate_session.return_value

    def test_session_initiate_only_once(self, mocker, rest_client):
        with mocker.patch.object(RESTAPIClient, '_initiate_session'):
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
            assert e.response == mock_response
            assert e.response_json == mock_response.json()

    def test_check_api_response__use_empty_json_on_fail_with_no_json(self, rest_client, mock_response):
        mock_response.raise_for_status.side_effect = HTTPError

        with pytest.raises(AlgoSecAPIError) as e:
            # No json on response
            mock_response.json.side_effect = ValueError
            rest_client._check_api_response(mock_response)
            assert e.response == mock_response
            assert e.response_json == {}


class TestSoapAPIClient(object):
    @pytest.fixture()
    def soap_client(self, request):
        return SoapAPIClient(
            'server-ip',
            'username',
            'password',
            verify_ssl=True
        )

    def test_init(self, soap_client):
        assert soap_client._client is None
        assert soap_client._session_id is None

    def test_client_auto_populate(self, mocker, soap_client):
        with mocker.patch.object(SoapAPIClient, '_initiate_client'):
            assert soap_client.client == soap_client._initiate_client.return_value

    def test_client_initiate_only_once(self, mocker, soap_client):
        with mocker.patch.object(SoapAPIClient, '_initiate_client'):
            # Inititate soap_client client creation twice
            soap_client.client
            soap_client.client
            soap_client._initiate_client.assert_called_once_with()

    def test_get_soap_client(self, soap_client, mocker):
        with mocker.patch.object(client, 'Client'):
            with mocker.patch.object(requests, 'Session'):
                wsdl_path = 'http://some-wsdl-path'
                new_client = soap_client._get_soap_client(wsdl_path)
                session = requests.Session()
                assert session.verify == soap_client.verify_ssl
                assert new_client == client.Client.return_value
                assert client.Client.called_once_with(
                    wsdl_path,
                    transport=suds_requests.RequestsTransport(session)
                )
