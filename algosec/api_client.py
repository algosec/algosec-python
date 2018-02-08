import httplib
import logging
import traceback
from collections import OrderedDict
from httplib import BAD_REQUEST
from itertools import chain

import re
import requests
import suds_requests
from suds import client, WebFault

from algosec.errors import AlgosecLoginError, AlgosecAPIError, UnrecognizedAllowanceState, EmptyFlowSearch
from algosec.flow_comparison_logic import IsIncludedInFlowComparisonLogic, IsEqualToFlowComparisonLogic
from algosec.helpers import mount_algosec_adapter_on_session, is_ip_or_subnet
from algosec.models import NetworkObjectSearchTypes, DeviceAllowanceState, NetworkObjectType

logger = logging.getLogger(__name__)


class AlgosecAPIClient(object):
    def __init__(self, server_ip, user, password):
        super(AlgosecAPIClient, self).__init__()
        self.server_ip = server_ip
        self.user = user
        self.password = password
        # Will be initialized once the session is used
        self._session = None

    @property
    def session(self):
        if self._session is None:
            self._session = self._initiate_session()
        return self._session

    def _check_api_response(self, response):
        """
        Check the api response and raise AlgosecAPIError if there is an issue

        """
        try:
            response.raise_for_status()
        except Exception:
            try:
                json = response.json()
            except ValueError:
                json = {}
            raise AlgosecAPIError(
                "response code: {}, json: {}, exception: {}".format(
                    response.status_code,
                    json,
                    traceback.format_exc(),
                ),
                response=response,
                response_json=json,
            )
        return response

    def _initiate_session(self):
        raise NotImplementedError()

    @staticmethod
    def get_soap_client(wsdl_path, **kwargs):
        """
        Create a soap client based on suds and python requests (to handle the AlgoSec's self-signed certificate properly

        :param kwargs: KWArgs that are forwarded to the suds client constructor
        """
        session = requests.Session()
        session.verify = False
        return client.Client(wsdl_path, transport=suds_requests.RequestsTransport(session), **kwargs)


class AlgosecBusinessFlowAPIClient(AlgosecAPIClient):
    """An extension for the handler to create ABF http session on creation"""

    def _initiate_session(self):
        session = requests.session()
        mount_algosec_adapter_on_session(session)
        url = "https://{}/BusinessFlow/rest/v1/login".format(self.server_ip)
        logger.debug("logging in to AlgoSec servers: {}".format(url))
        session.verify = False
        response = session.get(url, auth=(self.user, self.password))
        if response.status_code == httplib.OK:
            session.cookies.update({"JSESSIONID": response.json().get('jsessionid')})
            return session
        else:
            raise AlgosecLoginError(
                "Unable to login into AlgoSec server at %s. HTTP Code: %s", url, response.status_code
            )

    @property
    def api_base_url(self):
        return "https://{}/BusinessFlow/rest/v1".format(self.server_ip)

    @property
    def applications_base_url(self):
        return "{}/applications".format(self.api_base_url)

    @property
    def network_objects_base_url(self):
        return "{}/network_objects".format(self.api_base_url)

    @property
    def network_services_base_url(self):
        return "{}/network_services".format(self.api_base_url)

    def get_network_services_by_name(self, name):
        response = self.session.get("{}/name/{}".format(self.network_services_base_url, name))
        self._check_api_response(response)
        return response.json()

    def create_network_service(self, name, content, custom_fields=None):
        """
        Create a network service of ABF
        :param name: The service object's name
        :param list[(str,int)] content: List of (port, proto) pairs defining the services
        :param CustomField custom_fields: The custom fields to include for the object.
        :return: the created network service object
        """
        custom_fields = [] if custom_fields is None else custom_fields

        content = [
            {"protocol": service[0], "port": service[1]}
            for service in content
        ]

        response = self.session.post(
            "{}/new".format(self.network_services_base_url),
            json=dict(
                name=name,
                content=content,
                custom_fields=custom_fields,
            )
        )
        self._check_api_response(response)
        return response.json()

    def get_application_revision_id_by_name(self, app_name):
        """
        Query by application name and find the id for it's most recent revision
        :param string app_name: The application name to query for
        :return: The application ID
        """
        response = self.session.get("{}/name/{}".format(self.applications_base_url, app_name))
        self._check_api_response(response)
        return response.json()['revisionID']

    def find_network_objects(self, ip_or_subnet, search_type):
        """

        :param ip_or_subnet: The IP address or hostname of the object
        :param NetworkObjectSearchTypes search_type:
        :return: a list of network objects matching the search type and obj
        :rtype lst[NetworkObject]
        """
        response = self.session.get(
            "{}/find".format(self.network_objects_base_url),
            params=dict(address=ip_or_subnet, type=search_type.value),
        )
        self._check_api_response(response)

        # TODO: This check is being performed as currently the ABF api return weird response when no objects found
        # TODO: Should be removed once the API is fixed to return an empty list when no object are found
        if not isinstance(response.json(), list):
            logger.warning("find_network_objects: unsupported api response. Return empty result. (reponse: {})".format(
                response.json()
            ))
            return []
        return response.json()

    def get_network_object_by_name(self, object_name):
        """
        :param object_name: The object name
        :return: a network object matching the object name
        :rtype NetworkObject
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
            raise AlgosecAPIError("Unable to get one network object by name. Server response was: {}".format(result))

    def create_network_object(self, type, content, name):
        """
        Create a network object on ABF

        :param NetworkObjectType type: The network object type
        :param content: The IP address, Range or CIDR of the object
        :param name: Name for the new network object
        :return: NetworkObject api json
        """

        response = self.session.post(
            "{}/new".format(self.network_objects_base_url),
            json=dict(type=type.value, name=name, content=content),
        )
        self._check_api_response(response)
        return response.json()

    def create_missing_network_objects(self, all_network_objects):
        """
        Create object per object on ABF if the objects are not present on ABF

        If the one of the objects is not IP address or Subnet, do not try to create the network object

        :param collections.Iterable[str] all_network_objects: A list of network objects to create separately if missing
        from server
        :return: Nada
        """
        # Calculate which network objects we need to create before creating the flow
        objects_missing_for_algosec = [
            obj for obj in all_network_objects
            if is_ip_or_subnet(obj) and not self.find_network_objects(obj, NetworkObjectSearchTypes.EXACT)
        ]
        for obj in objects_missing_for_algosec:
            self.create_network_object(NetworkObjectType.HOST, obj, obj)

    def get_flow_by_name(self, app_id, flow_name):
        for flow in self.get_application_flows(app_id):
            if flow["name"] == flow_name:
                return flow
        raise EmptyFlowSearch("Unable to locate flow ID by name: {}".format(flow_name))

    def delete_flow_by_id(self, app_id, flow_id):
        response = self.session.delete("{}/{}/flows/{}".format(self.applications_base_url, app_id, flow_id))
        self._check_api_response(response)
        return True

    def delete_flow_by_name(self, app_id, flow_name):
        flow_id = self.get_flow_by_name(app_id, flow_name)['flowID']
        return self.delete_flow_by_id(app_id, flow_id)

    def get_application_flows(self, app_id):
        """
        Get all of the flows tied to a specific application flows with type of "APPLICATION_FLOW"
        :param app_id:
        :return:
        """
        response = self.session.get("{}/{}/flows".format(self.applications_base_url, app_id))
        self._check_api_response(response)
        return [app for app in response.json() if app["flowType"] == "APPLICATION_FLOW"]

    def does_flow_logicaly_exist(self, app_id, requested_flow):
        """
        Check if a certain flow definition is already defined or contained within another defined flow on ABF
        :param algosec.models.RequestedFlow requested_flow:
        :return:
        """
        return any(
            IsIncludedInFlowComparisonLogic.is_included(requested_flow, flow)
            for flow in self.get_application_flows(app_id)
        )

    def create_application_flow(self, app_id, requested_flow, retry_for_missing_services=True):
        """
        :param str app_id: The application id as defined on ABF to create this flow on
        :param algosec.models.RequestedFlow requested_flow: The flow to be created
        :param boolean retry_for_missing_services:
        :return:
        """
        all_network_objects = chain(requested_flow.destinations, requested_flow.sources)
        self.create_missing_network_objects(all_network_objects)

        response = self.session.post(
            "{}/{}/flows/new".format(self.applications_base_url, app_id),
            # We send a list since the API is looking for a list on NewFlows
            json=[requested_flow.new_flow_json_for_api],
        )
        try:
            self._check_api_response(response)
        except AlgosecAPIError as api_error:
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
                        name="{}/{}".format(proto, port),
                        content=[(proto, port)]
                    )
            return self.create_application_flow(
                app_id=app_id,
                requested_flow=requested_flow,
                retry_for_missing_services=False
            )

        return response.json()

    def apply_application_draft(self, revision_id):
        """
        Applies an application's draft revision
        :param revision_id:
        :return:
        """
        response = self.session.post("{}/{}/apply".format(self.applications_base_url, revision_id))
        return self._check_api_response(response)


class AlgosecFireFlowAPIClient(AlgosecAPIClient):
    def __init__(self, server_ip, user, password):
        super(AlgosecFireFlowAPIClient, self).__init__(server_ip, user, password)
        self.session_id = None

    def _initiate_session(self):
        client = self.get_soap_client(self.get_aff_wsdl_endpoint(self.server_ip))  # Authenticate
        try:
            authenticate = client.service.authenticate(
                username=self.user,
                password=self.password,
            )
        except WebFault:
            raise AlgosecLoginError

        self.session_id = authenticate.sessionId
        return client

    def create_change_request(
            self,
            action,
            subject,
            requester_name,
            email,
            sources,
            destinations,
            services,
            description="",
    ):
        """
        Create Change Request ticket on FireFlow

        :param ChangeRequestAction action: action requested by this Change Request to allow or drop traffic
        :param str subject: The ticket subject, will be shown on FireFlow
        :param str requester_name: The ticket creator name, will be shown on FireFlow
        :param str email: The email address of the requester
        :param list[str] sources: List of IP address representing the source of the traffic
        :param list[str] destinations: List of IP address representing the destination of the traffic
        :param list[str] services: List of services which describe the type of traffic. Each service could be a service
        name as defined on Algosec servers or just a proto/port pair. (e.g. ssh, http, tcp/50, udp/700)
        :param str description: description for the ticket, will be shown on Algosec
        :return: The created ticket URL
        """
        # Create ticket and traffic lines objects
        ticket = self.session.factory.create('ticket')

        ticket.description = description
        ticket.requestor = '{} {}'.format(requester_name, email)
        ticket.subject = subject

        traffic_line = self.session.factory.create('trafficLine')

        for source in sources:
            traffic_address = self.session.factory.create('trafficAddress')
            traffic_address.address = source
            traffic_line.trafficSource.append(traffic_address)

        for dest in destinations:
            traffic_address = self.session.factory.create('trafficAddress')
            traffic_address.address = dest
            traffic_line.trafficDestination.append(traffic_address)

        for service in services:
            traffic_service = self.session.factory.create('trafficService')
            traffic_service.service = service
            traffic_line.trafficService.append(traffic_service)

        traffic_line.action = action.value.api_value
        ticket.trafficLines.append(traffic_line)

        # Actually create the ticket
        ticket_added = self.session.service.createTicket(sessionId=self.session_id, ticket=ticket)
        ticket_url = ticket_added.ticketDisplayURL
        return ticket_url

    @staticmethod
    def get_aff_wsdl_endpoint(server_ip):
        """
        Algosec FireFlow SOAPAPI endpoint
        """
        AFF_WSDL = "https://{}/WebServices/FireFlow.wsdl"
        return AFF_WSDL.format(server_ip)


class AlgosecFirewallAnalyzerAPIClient(AlgosecAPIClient):
    def __init__(self, server_ip, user, password):
        super(AlgosecFirewallAnalyzerAPIClient, self).__init__(server_ip, user, password)
        self.session_id = None

    def _initiate_session(self):
        client = self.get_soap_client(
            self.get_afa_wsdl_path(self.server_ip),
            location=self.get_afa_wsdl_path(self.server_ip).split('?')[0]
        )
        try:
            self.session_id = client.service.connect(
                UserName=self.user,
                Password=self.password,
                Domain=''
            )

        except WebFault:
            raise AlgosecLoginError
        return client

    def calc_aggregated_query_result(self, query_results):
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

    def check_connectivity_status(self, source, dest, service):
        """

        :param str source:
        :param str dest:
        :param str service:
        :rtype: DeviceAllowanceState
        """
        query_params = {'Source': source, 'Destination': dest, 'Service': service}
        query_result = self.session.service.query(
            SessionID=self.session_id,
            QueryInput=query_params
        ).QueryResult

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
        # Since we had the "QueryResult" missing from the API before Algosec version 2017.02 we check here if it is
        # part of the result. If not, we try and calculate the traffic query result based on the results we got
        # for the various devices under the query
        if hasattr(query_result, "QueryResult") and query_result.QueryResult:
            aggregated_result = DeviceAllowanceState.from_string(query_result.QueryResult)
        else:
            aggregated_result = self.calc_aggregated_query_result(query_results)

        return aggregated_result

    @staticmethod
    def get_afa_wsdl_path(algosec_host):
        AFA_WSDL = "https://{}/AFA/php/ws.php?wsdl".format(algosec_host)
        return AFA_WSDL
