import pytest
from mock import mock, MagicMock
from suds import WebFault

from algosec.api_clients.fire_flow import FireFlowAPIClient
from algosec.errors import AlgoSecLoginError, AlgoSecAPIError
from algosec.models import ChangeRequestTrafficLine, ChangeRequestAction


class TestFireFlowAPIClient(object):
    @pytest.fixture()
    def fireflow_client(self):
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

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient._get_soap_client')
    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient._wsdl_url_path')
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
        mock_get_soap_client.return_value.service.authenticate.side_effect = WebFault('Login Error', document={})
        with mocker.patch.object(fireflow_client, '_get_soap_client', mock_get_soap_client):
            with pytest.raises(AlgoSecLoginError):
                fireflow_client._initiate_client()

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_get_change_request_by_id(self, mock_soap_client, fireflow_client):
        fireflow_client._session_id = MagicMock()
        change_request_id = MagicMock()
        ticket = fireflow_client.get_change_request_by_id(change_request_id)

        assert ticket == mock_soap_client.service.getTicket.return_value.ticket
        mock_soap_client.service.getTicket.assert_called_once_with(
            sessionId=fireflow_client._session_id,
            ticketId=change_request_id,
        )

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_get_change_request_by_id__faulty_request(self, mock_soap_client, fireflow_client):
        """Make sure that api call failure result in AlgoSecAPIError being raised"""
        mock_soap_client.service.getTicket.side_effect = WebFault(MagicMock(), document={})

        with pytest.raises(AlgoSecAPIError):
            fireflow_client.get_change_request_by_id(MagicMock())

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient._create_soap_traffic_line')
    def test_create_change_request(self, mock_create_traffic_line, mock_soap_client, fireflow_client):
        fireflow_client._session_id = MagicMock()
        MockTicket = MagicMock()
        MockTicket.trafficLines = []

        def get_ticket_mock(class_name):
            """Mock the factory.create classes returned by the soap client"""
            return {
                'ticket': MockTicket,
            }[class_name]

        mock_soap_client.factory.create.side_effect = get_ticket_mock

        subject = MagicMock()
        requestor_name = MagicMock()
        email = MagicMock()
        traffic_line1 = ChangeRequestTrafficLine(
            ChangeRequestAction.ALLOW,
            ['source1-1', 'source1-2'],
            ['dest1-1', 'dest1-2'],
            ['service1-1', 'service1-2'],
        )
        traffic_line2 = ChangeRequestTrafficLine(
            ChangeRequestAction.DROP,
            ['source2-1', 'source2-2'],
            ['dest2-1', 'dest2-2'],
            ['service2-1', 'service2-2'],
        )
        description = MagicMock()
        template = MagicMock()

        ticket_url = fireflow_client.create_change_request(
            subject=subject,
            requestor_name=requestor_name,
            email=email,
            traffic_lines=[
                traffic_line1,
                traffic_line2
            ],
            description=description,
            template=template,
        )

        mock_soap_client.service.createTicket.assert_called_once()
        assert ticket_url == mock_soap_client.service.createTicket(
            sessionId=fireflow_client._session_id,
            ticket=MockTicket,
        ).ticketDisplayURL
        assert MockTicket.description == description
        assert MockTicket.requestor == '{} {}'.format(requestor_name, email)
        assert MockTicket.subject == subject
        assert MockTicket.template == template
        assert MockTicket.trafficLines == [
            mock_create_traffic_line(traffic_line1),
            mock_create_traffic_line(traffic_line2),
        ]

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

    @mock.patch('algosec.api_clients.fire_flow.FireFlowAPIClient.client')
    def test_create_soap_traffic_line(self, mock_soap_client, fireflow_client):
        factory_instances = {}
        mock_traffic_line = factory_instances['trafficLine'] = MagicMock()
        mock_traffic_line.trafficSource = []
        mock_traffic_line.trafficDestination = []
        mock_traffic_line.trafficService = []

        def get_factory_class(class_name):
            """Mock the factory.create classes returned by the soap client"""
            if class_name == 'trafficLine':
                return mock_traffic_line
            instance = MagicMock()
            # Add to instance list by class name
            factory_instances.setdefault(class_name, []).append(instance)
            return instance

        mock_soap_client.factory.create.side_effect = get_factory_class

        traffic_line = ChangeRequestTrafficLine(
            ChangeRequestAction.ALLOW,
            ['source1', 'source2'],
            ['dest1', 'dest2'],
            ['service1', 'service2'],
        )

        soap_traffic_line = fireflow_client._create_soap_traffic_line(traffic_line)

        assert soap_traffic_line == mock_soap_client.factory.create('trafficLine')
        for i, obj in enumerate(soap_traffic_line.trafficSource):
            assert obj in factory_instances['trafficAddress']
            assert obj.address == traffic_line.sources[i]
        for i, obj in enumerate(soap_traffic_line.trafficDestination):
            assert obj in factory_instances['trafficAddress']
            assert obj.address == traffic_line.destinations[i]
        for i, obj in enumerate(soap_traffic_line.trafficService):
            assert obj in factory_instances['trafficService']
            assert obj.service == traffic_line.services[i]
