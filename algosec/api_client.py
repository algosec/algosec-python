"""API clients for the following AlgoSec services: **BusinessFlow**, **FireFlow** and **FirewallAnalyzer**.

The clients are intended to be imported, initiated and used in any python code.
Clients implementation is based on AlgoSec's official API guide.
Clients require three arguments to be initiated:

* AlgoSec server IP
* username
* password
* *verify_ssl* (optional)

Examples:
    Once initiated, the client is used by calling any of its public functions::

        from algosec.api_clients import FirewallAnalyzerAPIClient
        client = FirewallAnalyzerAPIClient(ip, username, password)
        query_result = client.run_traffic_simulation_query(
            source,
            dest,
            service
        )

    If the API call you were looking for is not yet implemented, you can send authenticated custom API call
    to the server using the client's ``session`` property.
    Please see specific API Client documentations to find out how.
"""

import httplib
import logging
import re
import traceback
from collections import OrderedDict
from httplib import BAD_REQUEST
from itertools import chain
from urllib import quote_plus

import requests
import suds_requests
from suds import client, WebFault

from algosec.errors import AlgoSecLoginError, AlgoSecAPIError, UnrecognizedAllowanceState, EmptyFlowSearch
from algosec.flow_comparison_logic import IsIncludedInFlowComparisonLogic
from algosec.helpers import mount_algosec_adapter_on_session, is_ip_or_subnet
from algosec.models import NetworkObjectSearchTypes, DeviceAllowanceState, NetworkObjectType

logger = logging.getLogger(__name__)


class APIClient(object):
    """An abstract class inherited by all other API Clients.

    All API clients require the same arguments to be initiated.

    Args:
        server_ip (str): IP address of the AlgoSec server.
        user (str): Username used to log in to AlgoSec.
        password (str): The user's password, similar to the one used to log in to the UI.

    Note:
        This class is intended to be inherited. It should not be initiated or used directly in your code.
    """
    def __init__(self, server_ip, user, password, verify_ssl=True):
        super(APIClient, self).__init__()
        self.server_ip = server_ip
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl


class RESTAPIClient(APIClient):
    def __init__(self, server_ip, user, password, verify_ssl=True):
        super(RESTAPIClient, self).__init__(server_ip, user, password, verify_ssl)
        # Will be initialized once the session is used
        self._session = None

    def _initiate_session(self):
        raise NotImplementedError()

    @property
    def session(self):
        """Return an authenticated ``requests`` session.

        The same session is returned on subsequent calls.

        Returns: Authenticated ``requests`` session.
        """
        if self._session is None:
            self._session = self._initiate_session()
        return self._session

    def _check_api_response(self, response):
        """Check an API response and raise AlgoSecAPIError if needed.

        Args:
            response: Response object returned from an API call.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If any error is found in the response object.

        Returns:
            Same response object passed in.
        """
        try:
            response.raise_for_status()
        except Exception:
            try:
                json = response.json()
            except ValueError:
                json = {}
            raise AlgoSecAPIError(
                "response code: {}, json: {}, exception: {}".format(
                    response.status_code,
                    json,
                    traceback.format_exc(),
                ),
                response=response,
                response_json=json,
            )
        return response


class BusinessFlowAPIClient(RESTAPIClient):
    """*BusinessFlow* RESTful API client.

    Used by calling its public methods or by sending custom calls using the ``session`` property.
    To ease the usability for custom API calls, a bunch of base urls were added as properties to this class
    (see example below).

    Examples:

        Using the public methods to send an API call::

            from algosec.api_clients import BusinessFlowAPIClient
            client = BusinessFlowAPIClient(ip, username, password)
            application_revision_id = client.get_application_revision_id_by_name("ApplicationName")

        Sending a custom API Call::

            from algosec.api_clients import BusinessFlowAPIClient
            client = BusinessFlowAPIClient(ip, username, password)
            response = client.session.get(
                "{}/name/{}".format(client.applications_base_url, application_name)
            )
    """

    def _initiate_session(self):
        """Return an authenticated session to the AlgoSec server.

        Raises:
            AlgoSecLoginError: If login using the username/password failed.

        Returns:
            requests.session.Session: An authenticated session with the server.
        """
        session = requests.session()
        mount_algosec_adapter_on_session(session)
        url = "https://{}/BusinessFlow/rest/v1/login".format(self.server_ip)
        logger.debug("logging in to AlgoSec servers: {}".format(url))
        session.verify = self.verify_ssl
        response = session.get(url, auth=(self.user, self.password))
        if response.status_code == httplib.OK:
            session.cookies.update({"JSESSIONID": response.json().get('jsessionid')})
            return session
        else:
            raise AlgoSecLoginError(
                "Unable to login into AlgoSec server at %s. HTTP Code: %s", url, response.status_code
            )

    @property
    def api_base_url(self):
        """str: Return the base url for all API calls."""
        return "https://{}/BusinessFlow/rest/v1".format(self.server_ip)

    @property
    def applications_base_url(self):
        """str: Return the base url for all application related API calls."""
        return "{}/applications".format(self.api_base_url)

    @property
    def network_objects_base_url(self):
        """str: Return the base url for all objects related API calls."""
        return "{}/network_objects".format(self.api_base_url)

    @property
    def network_services_base_url(self):
        """str: Return the base url for all services related API calls."""
        return "{}/network_services".format(self.api_base_url)

    def get_network_service_by_name(self, service_name):
        """Get a network service object by its name.

        Args:
            service_name (str): The name of the service.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If no such network service could be found by name.

        Returns:
            dict: NetworkObject as defined on the API Guide.

        """
        response = self.session.get("{}/service_name/{}".format(self.network_services_base_url, quote_plus(service_name)))
        self._check_api_response(response)
        return response.json()

    def create_network_service(self, service_name, content, custom_fields=None):
        """Create a network service.

        Args:
            service_name (str): The service object's service_name
            content (list[(str,int)]): List of (port, proto) pairs defining the services
            custom_fields: The custom fields to include for the object.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If network service creation failed.

        Returns:
            dict: The created NetworkService object as defined in the API Guide.
        """
        custom_fields = [] if custom_fields is None else custom_fields

        content = [
            {"protocol": service[0], "port": service[1]}
            for service in content
        ]

        response = self.session.post(
            "{}/new".format(self.network_services_base_url),
            json=dict(
                name=service_name,
                content=content,
                custom_fields=custom_fields,
            )
        )
        self._check_api_response(response)
        return response.json()

    def get_application_revision_id_by_name(self, app_name):
        """Return the latest revision id of an application by its name.

        Args:
            app_name (str): The application name to look for.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If no application matching the given name was found.

        Returns:
            int: The latest application revision ID.
        """
        response = self.session.get("{}/name/{}".format(self.applications_base_url, app_name))
        self._check_api_response(response)
        return response.json()['revisionID']

    def search_network_objects(self, ip_or_subnet, search_type):
        """Return network objects related to a given IP or subnet.

        Args:
            ip_or_subnet (str): The IP address or hostname of the object, or a subnet. (e.g: 192.1.1.1, 192.168.0.0/16)
            search_type (algosec.models.NetworkObjectSearchTypes): The enum for search type to perform.
                Could be one of :

                * *INTERSECT* - Search objects which their definition intersect with the given IP or subnet.
                * *CONTAINED* - Search for objects which the given IP or subnet is contained in.
                * *CONTAINING* - Search for objects contained within the given IP or subnet.
                * *EXACT* - Search the object which is defined exactly by (and only by) the given IP or subnet.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If an error occurred during the object search.

        Returns:
            list[dict]: List of network objects matching the given obj and search type.
                Each of the objects is a NetworkObject as defined in the API Guide.
        """
        response = self.session.get(
            "{}/find".format(self.network_objects_base_url),
            params=dict(address=ip_or_subnet, type=search_type.value),
        )
        self._check_api_response(response)

        # TODO: This check is being performed as currently the ABF api return weird response when no objects found
        # TODO: Should be removed once the API is fixed to return an empty list when no object are found
        if not isinstance(response.json(), list):
            logger.warning("search_network_objects: unsupported api response. Return empty result. (reponse: {})".format(
                response.json()
            ))
            return []
        return response.json()

    def get_network_object_by_name(self, object_name):
        """Return a network object by its name.

        Args:
            object_name (str): The object name to be searched.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If no network object matching the given name could be found.

        Returns:
            dict: The NetworkObject object matching the name lookup.
        """
        response = self.session.get(
            "{}/name/{}".format(self.network_objects_base_url, object_name),
        )
        self._check_api_response(response)
        result = response.json()
        if isinstance(result, dict):
            return result
        elif isinstance(result, list) and len(result) == 1:
            # TODO: Currently there is a bug in the API that returns a list of one object instead of the object itself
            return result[0]
        else:
            raise AlgoSecAPIError("Unable to get one network object by name. Server response was: {}".format(result))

    def create_network_object(self, type, content, name):
        """Create a new network object.

        Args:
            type (algosec.modiles.NetworkObjectType): The network object type
            content (str): The IP address, Range or CIDR of the object.
            name (str): Name of the new network object

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If the network object creation failed.

        Returns:
            dict: The newly create NetworkObject object.
        """
        response = self.session.post(
            "{}/new".format(self.network_objects_base_url),
            json=dict(type=type.value, name=name, content=content),
        )
        self._check_api_response(response)
        return response.json()

    def create_missing_network_objects(self, all_network_objects):
        """Create network objects if they are not already defined on the server.

        Args:
            all_network_objects (collections.Iterable[str]): List of the network objects to create if missing from the server.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If the one of the network objects creation failed.

        Returns:
            list[dict]: List of the created network objects.

        Note:
            If one of the given objects is not a valid IP address or subnet string, the object won't be created.
        """
        # Calculate which network objects we need to create before creating the flow
        objects_missing_for_algosec = [
            obj for obj in all_network_objects
            if is_ip_or_subnet(obj) and not self.search_network_objects(obj, NetworkObjectSearchTypes.EXACT)
        ]
        created_objects = []
        for obj in objects_missing_for_algosec:
            created_object = self.create_network_object(NetworkObjectType.HOST, obj, obj)
            created_objects.append(created_object)

        return created_objects

    def get_flow_by_name(self, app_revision_id, flow_name):
        """Return application flow by its name

        Args:
            app_revision_id (int|str): The application revision ID to fetch the flow from.
            flow_name (str): The name of the flow to fetch.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If fetching the full list of flows for the application revision failed
            :class:`~algosec.errors.EmptyFlowSearch`: If no flow matching that name could be found

        Returns:
            dict: Flow object as defined in the API Guide.
        """
        for flow in self.get_application_flows(app_revision_id):
            if flow["name"] == flow_name:
                return flow
        raise EmptyFlowSearch("Unable to locate flow ID by name: {}".format(flow_name))

    def delete_flow_by_id(self, app_revision_id, flow_id):
        """Delete an application flow given its id.

        Args:
            app_revision_id (int|str): The revision ID of the application to delete the flow from.
            flow_id (int|str): The ID of the flow to delete.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If the flow deletion failed.

        Returns:
            None
        """
        response = self.session.delete("{}/{}/flows/{}".format(self.applications_base_url, app_revision_id, flow_id))
        self._check_api_response(response)

    def delete_flow_by_name(self, app_revision_id, flow_name):
        """Delete an application flow given its name.

        Args:
            app_revision_id (int|str): The revision ID of the application to delete the flow from.
            flow_name (str): The name of the flow to delete.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If the flow deletion failed.
            :class:`~algosec.errors.EmptyFlowSearch`: If no flow matching that name could be found.

        Returns:
            None
        """
        flow_id = self.get_flow_by_name(app_revision_id, flow_name)['flowID']
        return self.delete_flow_by_id(app_revision_id, flow_id)

    def get_application_flows(self, app_revision_id):
        """Return all flows of the application revision.

        Note:
            Only flows with ``flowType`` of ``APPLICATION_FLOW`` are returned.
            The rest of the flows (e.g shared flows) are filtered out.

        Args:
            app_revision_id (str|int): The ID of the application revision to fetch the flows for

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If application flows list could not be fetched.

        Returns:
            list[dict]: List of Flow objects as defined in the API Guide.
        """
        response = self.session.get("{}/{}/flows".format(self.applications_base_url, app_revision_id))
        self._check_api_response(response)
        return [app for app in response.json() if app["flowType"] == "APPLICATION_FLOW"]

    def get_flow_connectivity(self, app_revision_id, flow_id):
        """Return a flow connectivity object for a flow given its ID.

        Args:
            app_revision_id (int|str): The ID of the application revision to lookup the flow in.
            flow_id (int|str): The ID of the flow to fetch ``FlowConnectivity`` for.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If error occurred while fetching the flow connectivity object.

        Returns:
            dict: FlowConnectivity object as defined in the API Guide.
        """
        response = self.session.post("{}/{}/flows/{}/check_connectivity".format(
            self.applications_base_url,
            app_revision_id,
            flow_id
        ))
        self._check_api_response(response)
        return response.json()

    def is_flow_contained_in_app(self, app_revision_id, requested_flow):
        """Return True if a certain RequestedFlow is already contained in a given application.

        If the requested_flow is already contained within one of the existing application flows, return True.

        Args:
            requested_flow (algosec.models.RequestedFlow): The definition of the flow to check containment for.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If error occurred while fetching the application flows.

        Returns:
            bool: True if this flow definition is contained within another existing flow in the application.
        """
        return any(
            IsIncludedInFlowComparisonLogic.is_included(requested_flow, flow)
            for flow in self.get_application_flows(app_revision_id)
        )

    def create_application_flow(self, app_revision_id, requested_flow, retry_for_missing_services=True):
        """Create an application flow.

        Args:
            app_revision_id (str): The application revision id as defined on ABF to create this flow on
            requested_flow(algosec.models.RequestedFlow): The flow to be created
            retry_for_missing_services (bool):

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If application flow creation failed.

        Returns:
            dict: An Application object as defined in the API Guide.
        """
        all_network_objects = chain(requested_flow.destinations, requested_flow.sources)
        self.create_missing_network_objects(all_network_objects)

        response = self.session.post(
            "{}/{}/flows/new".format(self.applications_base_url, app_revision_id),
            # We send a list since the API is looking for a list on NewFlows
            json=[requested_flow.get_json_flow_definition()],
        )
        try:
            self._check_api_response(response)
        except AlgoSecAPIError as api_error:
            # Handling the case when the failure is due to missing network_services from ABF
            # This code will try to create them and re-call this function again with retry=False
            # to make sure we are not getting into an inifinte look
            if not retry_for_missing_services:
                raise

            # Filter all of the cases where we are unable to recognize the readon for the failure
            if any([
                        api_error.response is None,
                        api_error.response_json is None,
                        type(api_error.response_json) != list,
                        api_error.response.status_code != BAD_REQUEST,
            ]):
                raise

            # Identify the missing services by parsing manually the service names from the json errors
            service_does_not_exist_pattern = "Service object named (UDP|TCP)/(\d+) does not exist"
            for error_line in api_error.response_json:
                match = re.match(service_does_not_exist_pattern, error_line, re.IGNORECASE)
                if match:
                    proto, port = match.groups()
                    self.create_network_service(
                        service_name="{}/{}".format(proto, port),
                        content=[(proto, port)]
                    )
            return self.create_application_flow(
                app_revision_id=app_revision_id,
                requested_flow=requested_flow,
                retry_for_missing_services=False
            )

        return response.json()

    def apply_application_draft(self, revision_id):
        """Apply an application draft and automatically create a FireFlow change request.

        Args:
            revision_id (int|str): The revision ID of the application to apply the draft for.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If error occurred while trying to apply the application draft.

        Returns:
            requests.models.Response: The API call response.
        """
        response = self.session.post("{}/{}/apply".format(self.applications_base_url, revision_id))
        return self._check_api_response(response)


class SoapAPIClient(APIClient):
    """Abstract SOAP API class inherited by all SOAP API clients.

    Note:
        This class should not be used directly but rather inherited to implement any new SOAP API clients.
    """
    def __init__(self, server_ip, user, password, verify_ssl=True):
        super(SoapAPIClient, self).__init__(server_ip, user, password, verify_ssl)
        self._client = None
        self._session_id = None

    def _initiate_client(self):
        raise NotImplementedError()

    @property
    def _wsdl_url_path(self):
        raise NotImplementedError()

    @property
    def client(self):
        """Return a suds SOAP client and make sure ``self._session_id`` is populated

        The same session is returned on subsequent calls.
        """
        if self._client is None:
            self._client = self._initiate_client()
        return self._client

    def _get_soap_client(self, wsdl_path, **kwargs):
        """.

        Args:
            wsdl_path (str): The url for the wsdl to connect to.
            **kwargs: Keyword-arguments that are forwarded to the suds client constructor.

        Returns:
            suds.client.Client: A suds SOAP client.
        """
        session = requests.Session()
        session.verify = self.verify_ssl
        # use ``requests`` based suds implementation to handle AlgoSec's self-signed certificate properly.
        return client.Client(wsdl_path, transport=suds_requests.RequestsTransport(session), **kwargs)


class FireFlowAPIClient(SoapAPIClient):
    """*FireFlow* SOAP API client.

    Args:
        server_ip (str): IP address of the AlgoSec server.
        user (str): Username used to log in to AlgoSec.
        password (str): The user's password, similar to the one used to log in to the UI.

    Used by calling its public methods or by sending custom calls using the ``client`` property.

    Example:

        Using the public methods to send an API call::

            from algosec.api_clients import FireFlowAPIClient
            client = FireFlowAPIClient(ip, username, password)
            change_request = client.get_change_request_by_id(change_request_id)
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
            action,
            subject,
            requestor_name,
            email,
            sources,
            destinations,
            services,
            description="",
            template=None,
    ):
        """Create a new change request.

        Args:
            action (algosec.models.ChangeRequestAction): action requested by this Change Request
                to allow or drop traffic.
            subject (str): The ticket subject, will be shown on FireFlow.
            requestor_name (str): The ticket creator name, will be shown on FireFlow.
            email (str): The email address of the requestor.
            sources (list[str]): List of IP address representing the source of the traffic.
            destinations (list[str]): List of IP address representing the destination of the traffic.
            services (list[str]): List of services which describe the type of traffic. Each service could be a service
                name as defined on AlgoSec servers or just a proto/port pair. (e.g. ssh, http, tcp/50, udp/700)
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

        traffic_line = self.client.factory.create('trafficLine')

        for source in sources:
            traffic_address = self.client.factory.create('trafficAddress')
            traffic_address.address = source
            traffic_line.trafficSource.append(traffic_address)

        for dest in destinations:
            traffic_address = self.client.factory.create('trafficAddress')
            traffic_address.address = dest
            traffic_line.trafficDestination.append(traffic_address)

        for service in services:
            traffic_service = self.client.factory.create('trafficService')
            traffic_service.service = service
            traffic_line.trafficService.append(traffic_service)

        traffic_line.action = action.value.api_value
        ticket.trafficLines.append(traffic_line)

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
            :class:`~algosec.errors.AlgoSecAPIError`: If the change request was not found on the server or another error occurred while
                fetching the change request.

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


class FirewallAnalyzerAPIClient(SoapAPIClient):
    """*FirewallAnalyzer* SOAP API client.

    Args:
        server_ip (str): IP address of the AlgoSec server.
        user (str): Username used to log in to AlgoSec.
        password (str): The user's password, similar to the one used to log in to the UI.

    Used by calling its public methods or by sending custom calls using the ``client`` property.

    Example:

        Using the public methods to send an API call::

            from algosec.api_clients import FirewallAnalyzerAPIClient
            client = FirewallAnalyzerAPIClient(ip, username, password)
            query_result = client.run_traffic_simulation_query(
                source,
                dest,
                service
            )
    """
    @property
    def _wsdl_url_path(self):
        return "https://{}/AFA/php/ws.php?wsdl".format(self.server_ip)

    def _initiate_client(self):
        """Return a connected suds client and save the new session id to ``self._session_id``

        Raises:
            AlgoSecLoginError: If login using the username/password failed.

        Returns:
            suds.client.Client
        """
        client = self._get_soap_client(self._wsdl_url_path, location=self._wsdl_url_path.split('?')[0])
        try:
            self._session_id = client.service.connect(
                UserName=self.user,
                Password=self.password,
                Domain=''
            )

        except WebFault:
            raise AlgoSecLoginError
        return client

    def _calc_aggregated_query_result(self, query_results):
        """Return aggregated calculated traffic query result.

        Since we had the "QueryResult" missing from the API before AlgoSec version 2017.02 we check here if it is
        part of the result. If not, we try and calculate the traffic query result based on the results we got
        for the various devices under the query.

        Returns:
            algosec.models.DeviceAllowanceState: Aggregated traffic simulation result.
        """
        # Understanding the value of the total result, is the traffic blocked or allowed or partially blocked?
        if query_results[DeviceAllowanceState.PARTIALLY_BLOCKED]:
            aggregated_result = DeviceAllowanceState.PARTIALLY_BLOCKED
        elif query_results[DeviceAllowanceState.BLOCKED]:
            if query_results[DeviceAllowanceState.ALLOWED]:
                aggregated_result = DeviceAllowanceState.PARTIALLY_BLOCKED
            else:
                aggregated_result = DeviceAllowanceState.BLOCKED
        else:
            aggregated_result = DeviceAllowanceState.ALLOWED
        return aggregated_result

    def run_traffic_simulation_query(self, source, destination, service):
        """Run a traffic simulation query and return its results.

        Args:
            source (str): Source of the simulated traffic. (e.g. IPs, subnet or an object name)
            destination (str): Destination of the simulated traffic. (e.g. IPs, subnet or an object name)
            service (str): Service of the simulated traffic (e.g: tcp/200, http)

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If any error occurred while executing the traffic simulation query.

        Returns:
            algosec.models.DeviceAllowanceState: Traffic simulation query result.
        """
        query_params = {'Source': source, 'Destination': destination, 'Service': service}
        try:
            query_result = self.client.service.query(
                SessionID=self._session_id,
                QueryInput=query_params
            ).QueryResult
        except WebFault:
            raise AlgoSecAPIError

        devices = []
        if query_result is not None:
            query_result = query_result[0]
            if query_result.QueryItem:
                # In case there is only one object in the result
                query_item = query_result.QueryItem
                devices = query_item.Device if type(query_item.Device) is list else [query_item.Device]

        # Making a dict from the result type to a list of devices. Keep it always ordered by the result type
        query_results = OrderedDict([
            (DeviceAllowanceState.BLOCKED, []),
            (DeviceAllowanceState.PARTIALLY_BLOCKED, []),
            (DeviceAllowanceState.ALLOWED, [])
        ])

        # Group the devices by groups according to their device result
        for device in devices:
            try:
                allowance_state = DeviceAllowanceState.from_string(device.IsAllowed)
            except UnrecognizedAllowanceState:
                logger.warning(
                    "Unknown device state found. Device: {}, state: {}".format(
                        device,
                        device.IsAllowed,
                    )
                )
            else:
                query_results[allowance_state].append(device)

        # Now calculate to the traffic query result.
        # Since we had the "QueryResult" missing from the API before AlgoSec version 2017.02 we check here if it is
        # part of the result. If not, we try and calculate the traffic query result based on the results we got
        # for the various devices under the query
        if hasattr(query_result, "QueryResult") and query_result.QueryResult:
            aggregated_result = DeviceAllowanceState.from_string(query_result.QueryResult)
        else:
            aggregated_result = self._calc_aggregated_query_result(query_results)

        return aggregated_result
