import pytest
from algosec.constants import PERMISSION_ERROR_MSG
from mock import mock, MagicMock
from zeep.exceptions import Fault

from algosec.errors import AlgoSecLoginError, AlgoSecAPIError, UnauthorizedUserException


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
        assert client.service.authenticate.call_args_list[0] == mocker.call(
            FFWSHeader={'version': '', 'opaque': ''},
            username=fireflow_client.user,
            password=fireflow_client.password,
        )
        assert client.service.authenticate.call_args_list[1] == mocker.call(
            FFWSHeader={'version': '', 'opaque': ''},
            username=fireflow_client.algobot_login_user,
            password=fireflow_client.algobot_login_password,
        )
        assert fireflow_client._session_id == client.service.authenticate.return_value.sessionId

    def test_initiate_client_login_error(self, mocker, fireflow_client):
        mock_get_soap_client = mocker.MagicMock()
        mock_get_soap_client.return_value.service.authenticate.side_effect = Fault('Login Error')
        mocker.patch.object(fireflow_client, '_get_soap_client', mock_get_soap_client)
        with pytest.raises(AlgoSecLoginError):
            fireflow_client._initiate_client()

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_get_change_request_by_id__faulty_request(self, mock_soap_client, fireflow_client):
        """Make sure that api call failure result in AlgoSecAPIError being raised"""
        mock_soap_client.service.getTicket.side_effect = Fault(MagicMock())

        with pytest.raises(AlgoSecAPIError):
            fireflow_client.get_change_request_by_id(MagicMock())

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_create_change_request__faulty_api_call(self, mock_soap_client, fireflow_client):
        """Make sure that upon api call failure, AlgoSecAPIError is raised"""
        mock_soap_client.service.createTicket.side_effect = Fault('Query Error')

        with pytest.raises(AlgoSecAPIError):
            fireflow_client.create_change_request(
                subject=(MagicMock()),
                requestor_name=(MagicMock()),
                email=(MagicMock()),
                traffic_lines=MagicMock(),
                description=(MagicMock()),
                template=(MagicMock()),
            )

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_get_change_request_by_id__user_is_the_requestor(self, mock_soap_client, fireflow_client):
        """Test return value when requestor email equals user email."""
        mock_soap_client.service.getTicket.return_value.ticket.requestorEmail = fireflow_client.user_email
        assert fireflow_client.get_change_request_by_id(MagicMock()) == \
            mock_soap_client.service.getTicket.return_value.ticket

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_get_change_request_by_id__user_is_privileged(self, mock_soap_client, fireflow_client):
        """Test return value when user have privileged permissions."""
        fireflow_client.algobot_login_user_defined = True
        mock_soap_client.service.getTicket.return_value.ticket.requestorEmail = "privileged_user@email.com"
        response_patcher = mock.patch('algosec.api_clients.fire_flow.requests.get')
        mock_response = response_patcher.start()
        mock_response.return_value = MagicMock(name='mock_response')
        mock_response.return_value.text.splitlines.return_value = \
            [
                '"UserName","Comments","Signature","Email","Organization","FullName","Language","ExtraInfo",'
                '"HomePhone","WorkPhone","PagerPhone","MobilePhone","Address1","Address2","City","State","Zip",'
                '"Country","Disabled","Authentication","isPrivileged"',
                '"username",,,"privilegd_user@email.com",,"administrator",,,,,,,,,,,,,0,"AFA",1',
            ]
        assert fireflow_client.get_change_request_by_id(MagicMock()) == \
            mock_soap_client.service.getTicket.return_value.ticket

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_get_change_request_by_id__algobot_login_user_defined(self, mock_soap_client, fireflow_client):
        """Test usage of algobot's default user details"""
        fireflow_client.algobot_login_user_defined = True
        mock_soap_client.service.getTicket.return_value.ticket.requestorEmail = "another_user@email.com"
        response_patcher = mock.patch('algosec.api_clients.fire_flow.requests.get')
        mock_response = response_patcher.start()
        mock_response.return_value = MagicMock(name='mock_response')
        mock_response.return_value.text.splitlines.return_value = \
            [
                '"UserName","Comments","Signature","Email","Organization","FullName","Language","ExtraInfo",'
                '"HomePhone","WorkPhone","PagerPhone","MobilePhone","Address1","Address2","City","State","Zip",'
                '"Country","Disabled","Authentication","isPrivileged"',
                '"username",,,"privilegd_user@email.com",,"administrator",,,,,,,,,,,,,0,"AFA",1',
            ]
        assert fireflow_client.get_change_request_by_id(MagicMock()) == \
            mock_soap_client.service.getTicket.return_value.ticket

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_get_change_request_by_id__no_permissions(self, mock_soap_client, fireflow_client):
        """Make sure that api call failure result in AlgoSecAPIError being raised"""
        fireflow_client.algobot_login_user_defined = False
        mock_soap_client.service.getTicket.return_value.ticket.requestorEmail = "another_user@email.com"
        response_patcher = mock.patch('algosec.api_clients.fire_flow.requests.get')
        mock_response = response_patcher.start()
        mock_response.return_value = MagicMock(name='mock_response')
        mock_response.return_value.text.splitlines.return_value = \
            ['"UserName","Comments","Signature","Email","Organization","FullName","Language","ExtraInfo","HomePhone",'
             '"WorkPhone","PagerPhone","MobilePhone","Address1","Address2","City","State","Zip",'
             '"Country","Disabled","Authentication","isPrivileged"',
             '"admin",,,"admin-junk@algosec-junk.com-junk",,"administrator",,,,,,,,,,,,,0,"AFA",1',
             '"algodemoadm",,,"algodemoadm123@gmail.com",,"demo admin",,,,,,,,,,,,,0,"AFA",1',
             '"test-user",,,"testuser@algosec.com",,"TestUser",,,,,,,,,,,,,0,"AFA",1']
        with pytest.raises(UnauthorizedUserException, match=r".*{}.*".format(PERMISSION_ERROR_MSG)):
            fireflow_client.get_change_request_by_id(MagicMock())
