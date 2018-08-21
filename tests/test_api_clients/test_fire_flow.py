import pytest
from mock import mock
from suds import WebFault

from algosec.api_clients.fire_flow import FireFlowAPIClient
from algosec.errors import AlgoSecLoginError


class TestFireFlowAPIClient(object):
    @pytest.fixture()
    def fireflow_client(self, request):
        return FireFlowAPIClient(
            'server-ip',
            'username',
            'password',
            verify_ssl=True
        )

    @pytest.mark.parametrize('host,expected', [
        ('127.0.0.1', 'https://127.0.0.1/WebServices/FireFlow.wsdl'),
        ('local.algosec.com', 'https://local.algosec.com/WebServices/FireFlow.wsdl'),
    ])
    def test_wsdl_url_path_property(self, fireflow_client, host, expected):
        fireflow_client.server_ip = host
        assert fireflow_client._wsdl_url_path == expected

    @mock.patch("algosec.api_clients.fire_flow.FireFlowAPIClient._get_soap_client")
    @mock.patch("algosec.api_clients.fire_flow.FireFlowAPIClient._wsdl_url_path")
    def test_initiate_client(self, mock_wsdl_path, mock_get_soap_client, mocker, fireflow_client):
        client = fireflow_client._initiate_client()

        # Assert that the soap client was created properly
        assert client == fireflow_client._get_soap_client.return_value
        fireflow_client._get_soap_client.assert_called_once_with(mock_wsdl_path)

        # Assert that the soap client was logged in and the session id was saved
        assert client.service.authenticate.call_args == mocker.call(
            username=fireflow_client.user,
            password=fireflow_client.password,
        )
        assert fireflow_client._session_id == client.service.authenticate.return_value.sessionId

    def test_initiate_client_login_error(self, mocker, fireflow_client):
        mock_get_soap_client = mocker.MagicMock()
        mock_get_soap_client.return_value.service.authenticate.side_effect = WebFault("Login Error", document={})
        with mocker.patch.object(fireflow_client, "_get_soap_client", mock_get_soap_client):
            with pytest.raises(AlgoSecLoginError):
                fireflow_client._initiate_client()

    def test_get_change_request_by_id(self):
        pass

    def test_get_change_request_by_id__good_error_description_when_ticket_is_not_on_server(self):
        pass

    def test_create_change_request(self):
        pass

    def test_create_change_request__faulty_api_call(self):
        """Make sure that upon api call failure, AlgoSecAPIError is raised"""
        pass
