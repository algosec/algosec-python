from algosec.models import ChangeRequestTrafficLine, ChangeRequestAction
from tests.conftest import my_vcr


class TestFireFlowAPIClient(object):
    @my_vcr.use_cassette()
    def test_create_change_request__assert_returned_url(self, fireflow_client):
        """Test change request creation with real API communication."""
        traffic_line1 = ChangeRequestTrafficLine(
            ChangeRequestAction.ALLOW,
            ['10.0.0.1', '10.0.0.2'],
            ['192.168.1.3', '192.168.1.4'],
            ['http', 'https'],
        )
        traffic_line2 = ChangeRequestTrafficLine(
            ChangeRequestAction.DROP,
            ['192.168.1.1', '192.168.1.2'],
            ['10.0.0.3', '10.0.0.4'],
            ['ssh', 'tcp/50'],
        )

        ticket_url = fireflow_client.create_change_request(
            subject='Some ticket traffic',
            requestor_name='Tester First Name',
            email='email@testing.com',
            traffic_lines=[
                traffic_line1,
                traffic_line2
            ],
            description='Ticket created by the AlgoSec Python SDK Unit testing module',
            template=None,
        )

        assert ticket_url == 'https://testing.algosec.com/FireFlow/Ticket/Display.html?id=5456'

    @my_vcr.use_cassette()
    def test_get_change_request_by_id(self, fireflow_client):
        ticket_id_preexisting_on_demo_vm = 4575
        ticket = fireflow_client.get_change_request_by_id(ticket_id_preexisting_on_demo_vm)

        assert ticket.id == ticket_id_preexisting_on_demo_vm
        assert ticket.owner == 'ned'
        assert ticket.requestor == 'Ned NetOps'
        assert ticket.subject == 'access to web browsing via Proxy'
        assert ticket.status == 'approve'
        # TODO: Maybe be test for the rest of the attributes here to demonstrate the usage

    @my_vcr.use_cassette()
    def test_create_change_request__and_then_fetch_it_and_compare(self, fireflow_client):
        """Test change request creation with real API communication."""
        traffic_line1 = ChangeRequestTrafficLine(
            ChangeRequestAction.ALLOW,
            ['10.0.0.1', '10.0.0.2'],
            ['192.168.1.3', '192.168.1.4'],
            ['tcp/80', 'tcp/443'],
        )
        traffic_line2 = ChangeRequestTrafficLine(
            ChangeRequestAction.DROP,
            ['192.168.1.1', '192.168.1.2'],
            ['10.0.0.3', '10.0.0.4'],
            ['tcp/23', 'tcp/50'],
        )

        ticket_subject = 'Some traffic change request subject'
        requestor_name = 'Tester First Name'
        requestor_email = 'email@testing.com'
        ticket_description = 'Ticket created by the AlgoSec Python SDK Unit testing module'
        ticket_url = fireflow_client.create_change_request(
            subject=ticket_subject,
            requestor_name=requestor_name,
            email=requestor_email,
            traffic_lines=[
                traffic_line1,
                traffic_line2
            ],
            description=ticket_description,
            template=None,
        )

        ticket_id = int(ticket_url.split('id=')[1])
        ticket = fireflow_client.get_change_request_by_id(ticket_id)

        # assert the ticket details
        assert ticket.id == ticket_id
        assert ticket.requestor == requestor_email
        assert ticket.subject == ticket_subject
        assert ticket.status == 'plan'
        assert ticket.description == ticket_description

        # Assert each of the traffic lines and it's content
        assert len(ticket.trafficLines) == 2
        for line_index, local_traffic_line in enumerate([traffic_line1, traffic_line2]):
            traffic_line_in_ticket = ticket.trafficLines[line_index]
            sources_in_ticket = [i.address for i in traffic_line_in_ticket.trafficSource]
            dests_in_ticket = [i.address for i in traffic_line_in_ticket.trafficDestination]
            services_in_ticket = [i.service for i in traffic_line_in_ticket.trafficService]
            applications_in_ticket = [i.application for i in traffic_line_in_ticket.trafficApplication]
            action_in_ticket = traffic_line_in_ticket.action

            assert local_traffic_line.action.value.api_value == action_in_ticket
            assert local_traffic_line.sources == sources_in_ticket
            assert local_traffic_line.destinations == dests_in_ticket
            assert local_traffic_line.services == services_in_ticket
            assert applications_in_ticket == ['any']

    @my_vcr.use_cassette()
    def test_create_change_request___with_applications_and_then_fetch_it_and_compare(self, fireflow_client):
        """Test change request creation with real API communication."""
        local_traffic_line = ChangeRequestTrafficLine(
            ChangeRequestAction.ALLOW,
            ['10.0.0.1', '10.0.0.2'],
            ['192.168.1.3', '192.168.1.4'],
            ['tcp/80', 'tcp/443'],
            ['ping', 'facebook-chat'],
        )

        ticket_subject = 'Some traffic change request subject'
        requestor_name = 'Tester First Name'
        requestor_email = 'email@testing.com'
        ticket_description = 'Ticket created by the AlgoSec Python SDK Unit testing module'
        ticket_url = fireflow_client.create_change_request(
            subject=ticket_subject,
            requestor_name=requestor_name,
            email=requestor_email,
            traffic_lines=[local_traffic_line],
            description=ticket_description,
            template=None,
        )

        ticket_id = int(ticket_url.split('id=')[1])
        ticket = fireflow_client.get_change_request_by_id(ticket_id)

        # Assert each of the traffic lines and it's content
        assert len(ticket.trafficLines) == 1
        traffic_line_in_ticket = ticket.trafficLines[0]
        sources_in_ticket = [i.address for i in traffic_line_in_ticket.trafficSource]
        dests_in_ticket = [i.address for i in traffic_line_in_ticket.trafficDestination]
        services_in_ticket = [i.service for i in traffic_line_in_ticket.trafficService]
        applications_in_ticket = [i.application for i in traffic_line_in_ticket.trafficApplication]
        action_in_ticket = traffic_line_in_ticket.action

        assert action_in_ticket == local_traffic_line.action.value.api_value
        assert sources_in_ticket == local_traffic_line.sources
        assert dests_in_ticket == local_traffic_line.destinations
        assert services_in_ticket == local_traffic_line.services
        assert applications_in_ticket == local_traffic_line.applications
