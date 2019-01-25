import pytest
from mock import mock, MagicMock
from suds import WebFault

from algosec.errors import AlgoSecLoginError, AlgoSecAPIError


class TestFireFlowAPIClient(object):
    @pytest.mark.parametrize('host,expected', [
        ('127.0.0.1', 'https://127.0.0.1/WebServices/FireFlow.wsdl'),
        ('local.algosec.com', 'https://local.algosec.com/WebServices/FireFlow.wsdl'),
    ])
    def test_wsdl_url_path_property(self, fireflow_client, host, expected):
        fireflow_client.server_ip = host
        assert fireflow_client._wsdl_url_path == expected

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient._get_soap_client')
    def test_initiate_client(self, mock_get_soap_client, mocker, fireflow_client):
        client = fireflow_client._initiate_client()

        # Assert that the soap client was created properly
        assert client == fireflow_client._get_soap_client.return_value
        fireflow_client._get_soap_client.assert_called_once_with(
            'https://testing.algosec.com/WebServices/FireFlow.wsdl',
            location='https://testing.algosec.com/WebServices/WSDispatcher.pl',
        )

        # Assert that the soap client was logged in and the session id was saved
        assert client.service.authenticate.call_args == mocker.call(
            username=fireflow_client.user,
            password=fireflow_client.password,
        )
        assert fireflow_client._session_id == client.service.authenticate.return_value.sessionId

    def test_initiate_client_login_error(self, mocker, fireflow_client):
        mock_get_soap_client = mocker.MagicMock()
        mock_get_soap_client.return_value.service.authenticate.side_effect = WebFault('Login Error', document={})
        with mocker.patch.object(fireflow_client, '_get_soap_client', mock_get_soap_client):
            with pytest.raises(AlgoSecLoginError):
                fireflow_client._initiate_client()

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_get_change_request_by_id__faulty_request(self, mock_soap_client, fireflow_client):
        """Make sure that api call failure result in AlgoSecAPIError being raised"""
        mock_soap_client.service.getTicket.side_effect = WebFault(MagicMock(), document={})

        with pytest.raises(AlgoSecAPIError):
            fireflow_client.get_change_request_by_id(MagicMock())

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_create_change_request__faulty_api_call(self, mock_soap_client, fireflow_client):
        """Make sure that upon api call failure, AlgoSecAPIError is raised"""
        mock_soap_client.service.createTicket.side_effect = WebFault('Query Error', document={})

        with pytest.raises(AlgoSecAPIError):
            fireflow_client.create_change_request(
                subject=(MagicMock()),
                requestor_name=(MagicMock()),
                email=(MagicMock()),
                traffic_lines=MagicMock(),
                description=(MagicMock()),
                template=(MagicMock()),
            )
