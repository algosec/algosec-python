import pytest
from mock import mock, MagicMock
from requests import status_codes

from algosec.api_clients.business_flow import BusinessFlowAPIClient
from algosec.errors import AlgoSecLoginError, EmptyFlowSearch


class TestBusinessFlowAPIClient(object):
    @pytest.fixture()
    def client(self, request):
        return BusinessFlowAPIClient(
            'server-ip',
            'username',
            'password',
            verify_ssl=True
        )

    @mock.patch('requests.session')
    @mock.patch('algosec.api_clients.business_flow.mount_algosec_adapter_on_session')
    def test_initiate_session(self, mock_session_adapter, mock_session, client, request):
        # Mock successful login
        login_response = mock_session.return_value.get.return_value
        login_response.status_code = status_codes.codes.OK

        client = BusinessFlowAPIClient(
            'server-ip',
            'username',
            'password',
            verify_ssl=MagicMock(),
        )

        new_session = client._initiate_session()

        assert new_session == mock_session.return_value
        assert new_session.verify == client.verify_ssl
        new_session.get.assert_called_once_with(
            "https://server-ip/BusinessFlow/rest/v1/login",
            auth=(
                'username',
                'password',
            )
        )
        mock_session_adapter.assert_called_once_with(new_session)

    @mock.patch('requests.session')
    def test_initiate_session__login_failed(self, mock_session, client, request):
        # Mock successful login
        login_response = mock_session.return_value.get.return_value
        login_response.status_code = "ANYTHING_BUT_OK"

        client = BusinessFlowAPIClient(
            'server-ip',
            'username',
            'password',
            verify_ssl=MagicMock(),
        )

        with pytest.raises(AlgoSecLoginError):
            client._initiate_session()

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_get_network_service_by_name(self, mock_session, mock_check_response, client):
        response = mock_session.get.return_value
        result = client.get_network_service_by_name('service-name')
        mock_session.get.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/network_services/service_name/service-name',
        )
        mock_check_response.assert_called_once_with(response)
        assert result == response.json.return_value

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_create_network_service(self, mock_session, mock_check_response, client):
        response = mock_session.post.return_value
        result = client.create_network_service('service-name', [('tcp', 50)])
        mock_session.post.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/network_services/new',
            json={
                'name': 'service-name',
                'content': [{'protocol': 'tcp', 'port': 50}],
                'custom_fields': []
            }
        )
        mock_check_response.assert_called_once_with(response)
        assert result == response.json.return_value

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_get_application_revision_id_by_name(self, mock_session, mock_check_response, client):
        response = mock_session.get.return_value
        result = client.get_application_revision_id_by_name('app-name')
        mock_session.get.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/applications/name/app-name',
        )
        mock_check_response.assert_called_once_with(response)
        assert result == response.json.return_value['revisionID']

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_search_network_objects(self, mock_session, mock_check_response, client):
        search_type = MagicMock()
        response = mock_session.get.return_value
        # Make sure that the search result is of list type
        search_result = [MagicMock()]
        response.json.return_value = search_result
        result = client.search_network_objects('ip-or-subnet', search_type)
        mock_session.get.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/network_objects/find',
            params={
                'address': 'ip-or-subnet',
                'type': search_type.value,
            }
        )
        mock_check_response.assert_called_once_with(response)
        assert result == search_result

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_search_network_objects__empty_search(self, mock_session, mock_check_response, client):
        search_type = MagicMock()
        response = mock_session.get.return_value
        result = client.search_network_objects('ip-or-subnet', search_type)
        mock_session.get.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/network_objects/find',
            params={
                'address': 'ip-or-subnet',
                'type': search_type.value,
            }
        )
        mock_check_response.assert_called_once_with(response)
        assert result == []

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_get_network_object_by_name(self, mock_session, mock_check_response, client):
        """Make sure that we support the return value of a list of one object"""
        network_object = {'name': 'some-object-name'}
        response = mock_session.get.return_value
        response.json.return_value = network_object
        result = client.get_network_object_by_name('network-object-name')
        mock_session.get.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/network_objects/name/network-object-name',
        )
        mock_check_response.assert_called_once_with(response)
        assert result == network_object

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_get_network_object_by_name__support_buggy_response(self, mock_session, mock_check_response, client):
        """Make sure that we support the return value of a list of one object"""
        network_object = {'name': 'some-object-name'}
        api_result = [network_object]
        response = mock_session.get.return_value
        response.json.return_value = api_result
        assert client.get_network_object_by_name('network-object-name') == network_object

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_create_network_object(self, mock_session, mock_check_response, client):
        network_object_type = MagicMock()
        response = mock_session.post.return_value
        result = client.create_network_object(network_object_type, 'object-content', 'object-name')
        mock_session.post.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/network_objects/new',
            json={
                'type': network_object_type.value,
                'name': 'object-name',
                'content': 'object-content',
            }
        )
        mock_check_response.assert_called_once_with(response)
        assert result == response.json.return_value
    #
    # @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    # @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    # def test_create_missing_network_objects(self, mock_session, mock_check_response, client):
    #     response = mock_session.get.return_value
    #     result = client.create_missing_network_objects()
    #     mock_session.get.assert_called_once_with(
    #         'url',
    #     )
    #     mock_check_response.assert_called_once_with(response)
    #     assert result == response.json.return_value

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.get_application_flows')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_get_flow_by_name(self, mock_session, mock_check_response, mock_get_application_flows, client):
        flow1 = {'name': 'flow1'}
        flow2 = {'name': 'flow2'}
        mock_get_application_flows.return_value = [flow1, flow2]
        result = client.get_flow_by_name('app-revision-id', 'flow1')
        assert result == flow1
        mock_get_application_flows.assert_called_once_with('app-revision-id')

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.get_application_flows')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_get_flow_by_name__flow_not_found(
            self,
            mock_session,
            mock_check_response,
            mock_get_application_flows,
            client
    ):
        mock_get_application_flows.return_value = [
            {'name': 'flow1'},
            {'name': 'flow2'},
        ]
        with pytest.raises(EmptyFlowSearch):
            client.get_flow_by_name('app-revision-id', 'flow3')

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_delete_flow_by_id(self, mock_session, mock_check_response, client):
        response = mock_session.delete.return_value
        client.delete_flow_by_id('app-revision-id', 'flow-id')
        mock_session.delete.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/applications/app-revision-id/flows/flow-id'
        )
        mock_check_response.assert_called_once_with(response)

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.get_flow_by_name')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.delete_flow_by_id')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_delete_flow_by_name(
            self,
            mock_session,
            mock_check_response,
            mock_delete_flow_by_id,
            mock_get_flow_by_name,
            client
    ):
        flow_id = 123
        flow_from_server = {'flowID': flow_id, 'name': 'flow-name'}
        mock_get_flow_by_name.return_value = flow_from_server

        client.delete_flow_by_name('app-revision-id', 'flow-name')
        mock_get_flow_by_name.assert_called_once_with('app-revision-id', 'flow-name')
        mock_delete_flow_by_id.assert_called_once_with('app-revision-id', flow_id)

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_get_application_flows(self, mock_session, mock_check_response, client):
        """Make sure that all application flows with APPLICATION_FLOW type are returned"""
        response = mock_session.get.return_value
        flow1 = {'name': 'flow1', 'flowType': 'APPLICATION_FLOW'}
        flow2 = {'name': 'flow2', 'flowType': 'APPLICATION_FLOW'}
        flow3_non_app_flow = {'name': 'flow3', 'flowType': 'SHARED_FLOW'}
        response.json.return_value = [flow1, flow2, flow3_non_app_flow]

        result = client.get_application_flows('app-revision-id')
        mock_session.get.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/applications/app-revision-id/flows',
        )
        mock_check_response.assert_called_once_with(response)
        assert result == [flow1, flow2]

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_get_flow_connectivity(self, mock_session, mock_check_response, client):
        response = mock_session.post.return_value
        result = client.get_flow_connectivity('app-revision-id', 'flow-id')
        mock_session.post.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/applications/app-revision-id/flows/flow-id/check_connectivity',
        )
        mock_check_response.assert_called_once_with(response)
        assert result == response.json.return_value
    #
    # @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    # @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    # def test_create_application_flow(self, mock_session, mock_check_response, client):
    #     response = mock_session.get.return_value
    #     result = client.create_application_flow()
    #     mock_session.get.assert_called_once_with(
    #         'url',
    #     )
    #     mock_check_response.assert_called_once_with(response)
    #     assert result == response.json.return_value

    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient._check_api_response')
    @mock.patch('algosec.api_clients.business_flow.BusinessFlowAPIClient.session')
    def test_apply_application_draft(self, mock_session, mock_check_response, client):
        response = mock_session.post.return_value
        client.apply_application_draft('app-revision-id')
        mock_session.post.assert_called_once_with(
            'https://server-ip/BusinessFlow/rest/v1/applications/app-revision-id/apply',
        )
        mock_check_response.assert_called_once_with(response)
