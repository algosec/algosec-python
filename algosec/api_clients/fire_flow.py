"""SOAP API client for AlgoSec **FireFlow**.


Examples:
    Once initiated, the client is used by calling any of its public functions::

        from algosec.api_clients.fire_flow import FireFlowAPIClient
        client = FireFlowAPIClient(ip, username, password)
        change_request = get_change_request_by_id(change_request_id)

    If the API call you were looking for is not yet implemented, you can send authenticated custom API call
    to the server using the client's ``session`` property.
    Please see specific API Client documentations to find out how.
"""
import logging
import requests
import six.moves.urllib as urllib

from algosec.api_clients.base import SoapAPIClient, APIClient
from algosec.errors import AlgoSecLoginError, AlgoSecAPIError, UnauthorizedUserException
from algosec.helpers import report_soap_failure
from algosec.constants import *
from zeep.exceptions import Fault

logger = logging.getLogger(__name__)

class FireFlowAPIClient(SoapAPIClient):
    """*FireFlow* SOAP API client.

    Used by initiating and calling its public methods or by sending custom calls using the ``client`` property.
    Client implementation is strictly based on AlgoSec's official API guide.

    Example:

        Using the public methods to send an API call::

            from algosec.api_clients.fire_flow import FireFlowAPIClient
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
        return 'https://{}/WebServices/FireFlow.wsdl'.format(self.server_ip)

    # might be useful to create another zeep ProxyService as done in afa client.
    @property
    def _soap_service_location(self):
        return 'https://{}/WebServices/WSDispatcher.pl'.format(self.server_ip)

    # default ffwsheader to avoid zeep exceptions where header is required.
    @property
    def _default_ffwsheader(self):
        return {"version":"", "opaque":""}

    @property
    def _users_list_url(self):
        return 'https://{}/FireFlow/REST/1.0/search/users?hide_privileged=0&get_extra_info=1'.format(self.server_ip)

    def _initiate_client(self):
        """Return a connected zeep client and save the new session id to ``self._session_id``

        Raises:
            AlgoSecLoginError: If login using the username/password failed.

        Returns:
            zeep.Client
        """
        self.algobot_login_user_defined = False
        client = self._get_soap_client(self._wsdl_url_path, location=self._soap_service_location)
        with report_soap_failure(AlgoSecLoginError):
            authenticate = client.service.authenticate(
                FFWSHeader=self._default_ffwsheader,
                username=self.user,
                password=self.password,
            )
            try:
                if self.algobot_login_user is not None and self.algobot_login_password is not None:
                    client.service.authenticate(
                        FFWSHeader=self._default_ffwsheader,
                        username=self.algobot_login_user,
                        password=self.algobot_login_password,
                    )
                    self.algobot_login_user_defined = True
                    logger.debug("AlgoBot login user successfully logged in to FireFlow")
            except Fault as e:
                logger.debug("AlgoBot login user failed to login to FireFlow")

        self._session_id = authenticate.sessionId
        return client

    def _create_soap_traffic_line(self, traffic_line):
        """
        Create new FireFlow traffic line based on TrafficLine object.

        Args:
            traffic_line (algosec.models.ChangeRequestTrafficLine): The traffic line to create.

        Returns: Soap traffic line object

        """
        factory = self.client.type_factory('ns0')
        soap_traffic_line = factory.trafficLine()
        soap_traffic_line.action = traffic_line.action.value.api_value
        for source in traffic_line.sources:
            traffic_address = factory.trafficAddress()
            traffic_address.address = source
            soap_traffic_line.trafficSource.append(traffic_address)
        for dest in traffic_line.destinations:
            traffic_address = factory.trafficAddress()
            traffic_address.address = dest
            soap_traffic_line.trafficDestination.append(traffic_address)
        for service in traffic_line.services:
            traffic_service = factory.trafficService()
            traffic_service.service = service
            soap_traffic_line.trafficService.append(traffic_service)
        if traffic_line.applications:
            for application_name in traffic_line.applications:
                traffic_application = factory.trafficApplication()
                traffic_application.application = application_name
                soap_traffic_line.trafficApplication.append(traffic_application)
        return soap_traffic_line

    def create_change_request(
            self,
            subject,
            requestor_name,
            email,
            traffic_lines,
            description="",
            template = DEFAULT_TICKET_TEMPLATE,
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
        factory = self.client.type_factory('ns0')
        ticket = factory.ticket()
        ticket.description = description
        ticket.requestor = '{} {}'.format(requestor_name, email)
        ticket.subject = subject
        ticket.template = DEFAULT_TICKET_TEMPLATE if template is None else template

        for traffic_line in traffic_lines:
            ticket.trafficLines.append(self._create_soap_traffic_line(traffic_line))

        logger.debug(self._api_info_string.format(
            "Create Change Request",
            self._wsdl_url_path + " op_name: createTicket",
            ticket,
        ))

        # Actually create the ticket
        with report_soap_failure(AlgoSecAPIError):
            ticket_added = self.client.service.createTicket(FFWSHeader=self._default_ffwsheader, sessionId=self._session_id, ticket=ticket)

        logger.debug("response: {}".format(ticket_added or API_CALL_FAILED_RESPONSE))

        ticket_url = ticket_added.ticketDisplayURL
        # normalize ticket url hostname that is sometimes incorrect from the FireFlow server (which uses it's own
        # internal IP to build this url.
        url = list(urllib.parse.urlsplit(ticket_url))
        url[1] = self.server_ip
        return urllib.parse.urlunsplit(url)

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
        logger.debug(self._api_info_string.format(
            "Change Request Status",
            self._wsdl_url_path + " op_name: getTicket",
            change_request_id,
        ))
        with report_soap_failure(AlgoSecAPIError):
            response = self.client.service.getTicket(FFWSHeader=self._default_ffwsheader,
                                                     sessionId=self._session_id, ticketId=change_request_id)
            if self.user_email and response.ticket.requestorEmail and self.user_email != response.ticket.requestorEmail:
                user_email = self.user_email or PLACEHOLDER_EMAIL
                ticket_requestor = response.ticket.requestor or ""
                ticket_requestor_email = response.ticket.requestorEmail or ""

                # get the list of fireflow users.
                cookie = {FIREFLOW_COOKIE_NAME: self._session_id}
                r = requests.get(self._users_list_url, cookies=cookie, verify=False)
                user_lines = r.text.splitlines()
                headers = user_lines[0].replace('"', "").split(',')
                full_name_index = headers.index('FullName')
                email_index = headers.index('Email')
                is_privileged_index = headers.index('isPrivileged')
                username_index = headers.index('UserName')

                logger.debug("Current user email is " + user_email + " and ticket requestor is " + ticket_requestor)
                possible_emails = []
                # go thorugh all users. (start from index 1 since first line is headers.)
                for user_line in user_lines[1:len(user_lines)]:
                    delimited_line = user_line.replace('"', "").split(',')
                    if (
                            len(delimited_line) == len(headers) and
                            (delimited_line[full_name_index] == ticket_requestor
                            or delimited_line[email_index] == ticket_requestor
                            or delimited_line[username_index] == ticket_requestor
                            or delimited_line[is_privileged_index])

                    ):
                        possible_emails.append(delimited_line[email_index])

                logger.debug("Possible users: " + str(possible_emails))

                if user_email not in possible_emails:
                    # if there is no algobot user defined in configuration file raise Unauthorized exception.
                    if not self.algobot_login_user_defined:
                        raise UnauthorizedUserException(PERMISSION_ERROR_MSG,
                                                        GET_TICKET_WRONG_REQUESTOR.format(PERMISSION_ERROR_MSG,
                                                                                          ticket_requestor_email,
                                                                                          user_email))

        logger.debug("response: {}".format(response or API_CALL_FAILED_RESPONSE))
        return response.ticket
