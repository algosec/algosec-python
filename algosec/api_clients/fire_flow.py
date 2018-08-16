"""SOAP API client for AlgoSec **FireFlow**.


Examples:
    Once initiated, the client is used by calling any of its public functions::

        from algosec.api_clients import FireFlowAPIClient
        client = FireFlowAPIClient(ip, username, password)
        change_request = get_change_request_by_id(change_request_id)

    If the API call you were looking for is not yet implemented, you can send authenticated custom API call
    to the server using the client's ``session`` property.
    Please see specific API Client documentations to find out how.
"""
import logging

from suds import WebFault

from algosec.api_clients.base import SoapAPIClient
from algosec.errors import AlgoSecLoginError, AlgoSecAPIError

logger = logging.getLogger(__name__)


class FireFlowAPIClient(SoapAPIClient):
    """*FireFlow* SOAP API client.

    Used by initiating and calling its public methods or by sending custom calls using the ``client`` property.
    Client implementation is strictly based on AlgoSec's official API guide.

    Example:

        Using the public methods to send an API call::

            from algosec.api_clients import FireFlowAPIClient
            client = FireFlowAPIClient(ip, username, password)
            change_request = client.get_change_request_by_id(change_request_id)

    Args:
        server_ip (str): IP address of the AlgoSec server.
        user (str): Username used to log in to AlgoSec.
        password (str): The user's password, similar to the one used to log in to the UI.
        verify_ssl (bool): Turn on/off the connection's SSL certificate verification. Defaults to True.

    """

    @property
    def _wsdl_url_path(self):
        return "https://{}/WebServices/FireFlow.wsdl".format(self.server_ip)

    def _initiate_client(self):
        """Return a connected suds client and save the new session id to ``self._session_id``

        Raises:
            AlgoSecLoginError: If login using the username/password failed.

        Returns:
            suds.client.Client
        """
        client = self._get_soap_client(self._wsdl_url_path)
        try:
            authenticate = client.service.authenticate(
                username=self.user,
                password=self.password,
            )
        except WebFault:
            raise AlgoSecLoginError

        self._session_id = authenticate.sessionId
        return client

    def create_change_request(
            self,
            subject,
            requestor_name,
            email,
            traffic_lines,
            description="",
            template=None,
    ):
        """Create a new change request.

        Args:
            subject (str): The ticket subject, will be shown on FireFlow.
            requestor_name (str): The ticket creator name, will be shown on FireFlow.
            email (str): The email address of the requestor.
            traffic_lines (list[algosec.models.ChangeRequestTrafficLine]): List of traffic lines each describing its
                sources, destinations and services.
            description (str): description for the ticket, will be shown on FireFlow.
            template (str): When different than None, this template will be passed on to FireFlow to be used
                as the template for the new change requets.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If change request creation failed.

        Returns:
            str: The URL for the newley create change request on FireFlow
        """
        # Create ticket and traffic lines objects
        ticket = self.client.factory.create('ticket')

        ticket.description = description
        ticket.requestor = '{} {}'.format(requestor_name, email)
        ticket.subject = subject
        if template is not None:
            ticket.template = template

        for traffic_line in traffic_lines:
            soap_traffic_line = self.client.factory.create('trafficLine')

            soap_traffic_line.action = traffic_line.action.value.api_value

            for source in traffic_line.sources:
                traffic_address = self.client.factory.create('trafficAddress')
                traffic_address.address = source
                soap_traffic_line.trafficSource.append(traffic_address)

            for dest in traffic_line.destinations:
                traffic_address = self.client.factory.create('trafficAddress')
                traffic_address.address = dest
                soap_traffic_line.trafficDestination.append(traffic_address)

            for service in traffic_line.services:
                traffic_service = self.client.factory.create('trafficService')
                traffic_service.service = service
                soap_traffic_line.trafficService.append(traffic_service)

            ticket.trafficLines.append(soap_traffic_line)

        # Actually create the ticket
        try:
            ticket_added = self.client.service.createTicket(sessionId=self._session_id, ticket=ticket)
        except WebFault:
            raise AlgoSecAPIError

        ticket_url = ticket_added.ticketDisplayURL
        return ticket_url

    def get_change_request_by_id(self, change_request_id):
        """Get a change request by its ID.

        Useful for checking the status of a change request you opened through the API.

        Args:
            change_request_id: The ID of the change request to fetch.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If the change request was not found on the server or another
                error occurred while fetching the change request.

        Returns:
            The change request ticket object.
        """
        try:
            response = self.client.service.getTicket(sessionId=self._session_id, ticketId=change_request_id)
        except WebFault, e:
            if 'Can not get ticket for id' in e.fault.faultstring:
                raise AlgoSecAPIError("Change request was not found on the server.")
            # some other unknown error occurred
            raise AlgoSecAPIError
        return response.ticket