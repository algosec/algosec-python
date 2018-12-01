"""REST API client for AlgoSec **BusinessFlow**."""


import logging

import requests
from requests import status_codes
from six.moves.urllib.parse import quote_plus

from algosec.api_clients.base import RESTAPIClient
from algosec.errors import AlgoSecLoginError, AlgoSecAPIError, EmptyFlowSearch
from algosec.helpers import mount_algosec_adapter_on_session, is_ip_or_subnet
from algosec.models import NetworkObjectSearchTypes, NetworkObjectType

logger = logging.getLogger(__name__)


class BusinessFlowAPIClient(RESTAPIClient):
    """*BusinessFlow* RESTful API client.

    Used by initiating and calling its public methods or by sending custom calls using the ``session`` property.
    Client implementation is strictly based on AlgoSec's official API guide.
    To ease the usability for custom API calls, a bunch of base urls were added as properties to this class
    (see example below).

    Examples:

        Using the public methods to send an API call::

            from algosec.api_clients.business_flow import BusinessFlowAPIClient
            client = BusinessFlowAPIClient(ip, username, password)
            application_revision_id = client.get_application_revision_id_by_name("ApplicationName")

        Sending a custom API Call::

            from algosec.api_clients.business_flow import BusinessFlowAPIClient
            client = BusinessFlowAPIClient(ip, username, password)
            response = client.session.get(
                "{}/name/{}".format(client.applications_base_url, application_name)
            )

    Args:
        server_ip (str): IP address of the AlgoSec server.
        user (str): Username used to log in to AlgoSec.
        password (str): The user's password, similar to the one used to log in to the UI.
        verify_ssl (bool): Turn on/off the connection's SSL certificate verification. Defaults to True.

    """

    ABF_APPLICATION_DASHBOARD_URL = '/#!application/{}/dashboard'
    ASSOCIATED_APPLICATIONS_UI_QUERY = '/#!applications/query?q=%7B%22addresses%22%3A%5B%7B%22' \
                                       'address%22%3A%22{}%22%7D%5D%2C%22devices%22%3A%5B%5D%7D'

    def _initiate_session(self):
        """Return an authenticated session to the AlgoSec server.

        Raises:
            AlgoSecLoginError: If login using the username/password failed.

        Returns:
            requests.session.Session: An authenticated session with the server.
        """
        session = requests.session()
        mount_algosec_adapter_on_session(session)
        url = "{}/rest/v1/login".format(self.business_flow_base_url, self.server_ip)
        logger.debug("logging in to AlgoSec servers: {}".format(url))
        session.verify = self.verify_ssl
        response = session.get(url, auth=(self.user, self.password))
        if response.status_code == status_codes.codes.OK:
            return session
        else:
            raise AlgoSecLoginError(
                "Unable to login into AlgoSec server at %s. HTTP Code: %s", url, response.status_code
            )

    @property
    def business_flow_base_url(self):
        """str: Return the base url for BusinessFlow."""
        return 'https://{}/BusinessFlow'.format(self.server_ip)

    @property
    def api_base_url(self):
        """str: Return the base url for all API calls."""
        return "{}/rest/v1".format(self.business_flow_base_url, self.server_ip)

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
        response = self.session.get(
            "{}/service_name/{}".format(
                self.network_services_base_url, quote_plus(service_name)
            )
        )
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
            logger.warning(
                "search_network_objects: unsupported api response. Return empty result. (reponse: {})".format(
                    response.json()
                )
            )
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
            type (algosec.models.NetworkObjectType): The network object type
            content (str|list): Define the newly created network object. Content depend upon the selected type:

                - :class:`~algosec.models.NetworkObjectType.HOST`: Content is the IP address of the object.
                - :class:`~algosec.models.NetworkObjectType.RANGE`: Content is IP range or CIDR.
                - :class:`~algosec.models.NetworkObjectType.GROUP`: Content is a list of *ExistingNetworkObject* or
                    *NewNetworkObject* objects as defined in the API Guide.
                - :class:`~algosec.models.NetworkObjectType.ABSTRACT`: Content is None or an empty string.
            name (str): Name of the new network object

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If the network object creation failed.

        Returns:
            dict: The newly created ExistingNetworkObject object.
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
            all_network_objects (collections.Iterable[str]): List of the network objects to create if
                missing from the server.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If the one of the network objects creation failed.

        Returns:
            list[dict]: List of the created network objects.

        Note:
            If one of the given objects is not a valid IP address or subnet string, the object won't be created.
        """
        # Calculate which network objects we need to create before creating the flow
        objects_missing_from_algosec = []
        for obj in all_network_objects:
            if not is_ip_or_subnet(obj):
                continue
            search_objects = self.search_network_objects(obj, NetworkObjectSearchTypes.EXACT)
            if search_objects:
                # EXACT object search is by content, not by name.
                # Therefore, we make check if the exact object name was found
                # Even if the object exists under a different name, we want to make sure it is
                # marked for re-creation here.
                object_names = [search_object.get('name') for search_object in search_objects]
                if obj not in object_names:
                    objects_missing_from_algosec.append(obj)
            else:
                # No object was found, mark for creation
                objects_missing_from_algosec.append(obj)

        return [
            self.create_network_object(NetworkObjectType.HOST, obj, obj)
            for obj in objects_missing_from_algosec
        ]

    def get_flow_by_name(self, app_revision_id, flow_name):
        """Return application flow by its name

        Args:
            app_revision_id (int|str): The application revision ID to fetch the flow from.
            flow_name (str): The name of the flow to fetch.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If fetching the full list of flows for the application
                revision failed
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
        self.delete_flow_by_id(app_revision_id, flow_id)

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
        return [flow for flow in response.json() if flow["flowType"] == "APPLICATION_FLOW"]

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

    def create_application_flow(
            self,
            app_revision_id,
            requested_flow,
    ):
        """Create an application flow.

        Creates network services that were defined in the flow but
        are not currently exist on ABF.

        Args:
            app_revision_id (int): The application revision id as defined on ABF to create this flow on
            requested_flow(algosec.models.RequestedFlow): The flow to be created

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If application flow creation failed.

        Returns:
            dict: An Application object as defined in the API Guide.
        """
        all_network_objects = set(requested_flow.destinations + requested_flow.sources)
        self.create_missing_network_objects(all_network_objects)

        response = self.session.post(
            "{}/{}/flows/new".format(self.applications_base_url, app_revision_id),
            # We send a list since the API is looking for a list on NewFlows
            json=[requested_flow.get_json_flow_definition()],
        )
        self._check_api_response(response)
        return response.json()[0]

    def apply_application_draft(self, app_revision_id):
        """Apply an application draft and automatically create a FireFlow change request.

        Args:
            app_revision_id (int|str): The revision ID of the application to apply the draft for.

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If error occurred while trying to apply the application draft.

        Returns:
            requests.models.Response: The API call response.
        """
        response = self.session.post("{}/{}/apply".format(self.applications_base_url, app_revision_id))
        self._check_api_response(response)

    def get_abf_application_dashboard_url(self, application_revision_id):
        """
        Return URL for the application dashboard.

        This is the applications's dashboard on AlgoSec BusinessFlow and it can be viewed in the browser.

        Args:
            application_revision_id: The application revision ID to return the dashboard URL for.

        Returns:
            str: URL for the application dashboard on the AlgoSec BusinessFlow. An Example would look like that:
            https://10.0.0.12/BusinessFlow/#!application/293/dashboard
        """
        return self.business_flow_base_url + self.ABF_APPLICATION_DASHBOARD_URL.format(application_revision_id)

    def get_associated_applications_ui_query(self, queried_ip_address):
        """
        Return URL that can be used in the browser to view the associated applications query.

        Args:
            queried_ip_address: The IP address we wish to find associated applications for.

        Returns:
            str: URL for ssociated applications query that can be viewed in the browser.
        """
        return self.business_flow_base_url + self.ASSOCIATED_APPLICATIONS_UI_QUERY.format(queried_ip_address)

    @staticmethod
    def is_application_critical(application_json):
        """
        Return True if the application's json has the critical label set.

        Args:
            application_json: The application Json as returned from AlgoSec BusinessFlow APIs.

        Returns:
            bool: True if the application is marked as a critical application
        """
        return any(label['name'] == 'Critical' for label in application_json.get('labels', []))

    def get_associated_applications(self, ip_address):
        """
        Return all applications containing network objects related to IP addresses.

        Args:
            ip_address (str): The IP address to search associated applications for

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If error occurred while trying to fetch associated applications.

        Returns:
            list: List of dictionaries each representing an associated application.

        """
        response = self.session.get(
            "{}/find/applications?address={}".format(self.network_objects_base_url, ip_address),
        )
        self._check_api_response(response)
        return response.json()
