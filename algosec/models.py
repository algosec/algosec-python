"""Define models and enums used by the API clients.

Note:
    Most developers will not have to use any of the contents of this module directly.
"""
from collections import namedtuple

from enum import Enum

from algosec.errors import AlgoSecAPIError, UnrecognizedAllowanceState, UnrecognizedServiceString
from algosec.helpers import is_ip_or_subnet, LiteralService


class RequestedFlow(object):
    """Represents a NewFlow model from the API Guide.

    This model is used by the :class:`~algosec.api_client.BusinessFlowAPIClient` to
    create and handle different operations regarding new and existing flows.

    Examples:
        1. It is used to represent a new flow that is about to be created.
        2. It is used to check if any flow definition is already contained within other existing flows.

    Args:
        name (str): The name of the new flow.
        sources (list[str]): Sources for the flow.
        destinations (list[str]): Destinations for the flow.
        network_users (list[str]): Network user names for the flow.
        network_applications (list[str]): Names of network application for the flow.
        network_services (list[str]): Names of network services names for the flow.
        comment (str): Any comment to save alongside the flow.
        custom_fields: Custom fields for the new flow
        type (str): Optional. The type of the flow to create. Default to *APPLICATION*.
    """
    def __init__(
            self,
            name,
            sources,
            destinations,
            network_users,
            network_applications,
            network_services,
            comment,
            custom_fields=None,
            type="APPLICATION",
    ):
        self.name = name
        self.sources = sources
        self.destinations = destinations
        self.network_users = network_users
        self.network_applications = network_applications
        self.network_services = network_services
        self.comment = comment
        self.custom_fields = custom_fields or []
        self.type = type

        # Mapped and normalized objects to be populated later on
        self.source_to_containing_object_ids = {}
        self.destination_to_containing_object_ids = {}
        self.aggregated_network_services = set()

        self._normalize_network_services()

    # TODO: Could be removed when all of the issues with case sensitivity are cleared on the BusinessFlow API
    def _normalize_network_services(self):
        # A new list to store normalized network services names. proto/port definition are made capital case
        # Currently AlgoSec servers support only uppercase protocol names across the board
        # For example: Trying to create a flow with service "tcp/54" will fail if there is only service named "TCP/54"
        # But then creating the exact same service "tcp/54" will give an exception that the service already exists
        normalized_network_services = []
        for service in self.network_services:
            if LiteralService.is_protocol_string(service):
                service = service.upper()
            normalized_network_services.append(service)
        self.network_services = normalized_network_services

    def _api_named_object(self, lst):
        """
        ABF expect to get most simple objects as a dict pointing to their name
        this is a helper function to achieve that

        :param lst:
        :return:
        """
        return [{"name": obj} for obj in lst]

    @classmethod
    def _build_mapping_from_network_objects_to_containing_object_ids(cls, abf_client, network_objects):
        """
        Return a mapping from IPs and Subnets to their containing object IDs

        If the one of the provided network objects in the list is not an IP or a Subnet,
        the method assumes it is a network object name. Then the method will query ABF
        for the IP addresses that coprise this network object. Then the function will handle
        of the comprising IPs as if they were provided as part of the network objects passed to the function.
        It means you will see them as keys in the returned mapping.

        :param list[str] network_objects: list of IPs, subnets and network object names
        :return:  mapping from IPs and Subnets to their containing object IDs
        """
        network_objects_to_containing_object_ids = {}
        for network_object in network_objects:
            if is_ip_or_subnet(network_object):
                ips_and_subnets = [network_object]
            else:
                # translate network object name to the ip addresses it is comprised of
                try:
                    ips_and_subnets = abf_client.get_network_object_by_name(network_object)['ipAddresses']
                except AlgoSecAPIError:
                    raise AlgoSecAPIError("Unable to resolve network object by name: {}".format(network_object))

            for ip_or_subnet in ips_and_subnets:
                network_objects_to_containing_object_ids[ip_or_subnet] = {
                    containing_object["objectID"] for containing_object in
                    abf_client.search_network_objects(ip_or_subnet, NetworkObjectSearchTypes.CONTAINED)
                }

        return network_objects_to_containing_object_ids

    def get_json_flow_definition(self):
        """Return a dict object representing a NewFlow as expected by the API.

        Returns:
            dict: NewFlow object.
        """
        return dict(
            type=self.type,
            name=self.name,
            sources=self._api_named_object(self.sources),
            destinations=self._api_named_object(self.destinations),
            users=self.network_users,
            network_applications=self._api_named_object(self.network_applications),
            services=self._api_named_object(self.network_services),
            comment=self.comment,
            custom_fields=self.custom_fields,
        )

    # TODO: Remove this method, and the rest of the "is flow contained" logic.
    def _populate(self, abf_client):
        """Populate the mappings and normalization objects based on the AlgoSec APIs

        :param BusinessFlowAPIClient abf_client:
        """
        # Build a map from each source to the object ids of the network objects that contain it
        self.source_to_containing_object_ids = self._build_mapping_from_network_objects_to_containing_object_ids(
            abf_client,
            self.sources,
        )

        # Build a map from each destination to the object ids of the network objects that contain it
        self.destination_to_containing_object_ids = self._build_mapping_from_network_objects_to_containing_object_ids(
            abf_client,
            self.destinations,
        )

        for service in self.network_services:
            try:
                self.aggregated_network_services.add(LiteralService(service))
            except UnrecognizedServiceString:
                # We need to resolve the service names so we'll be able to check if their definition is included
                # within other network services that will be defined on AlgoSec.
                try:
                    network_service = abf_client.get_network_services_by_name(service)
                    for service_str in network_service["services"]:
                        self.aggregated_network_services.add(LiteralService(service_str))
                except AlgoSecAPIError:
                    raise AlgoSecAPIError("Unable to resolve definition for requested service: {}".format(service))


AllowanceInfo = namedtuple("AllowanceInfo", ["text", "title"])


class NetworkObjectSearchTypes(Enum):
    """Enum used for :py:meth:`~algosec.api_clients.BusinessFlowAPIClient.search_network_objects`"""
    INTERSECT = "INTERSECT"
    CONTAINED = "CONTAINED"
    CONTAINING = "CONTAINING"
    EXACT = "EXACT"


class DeviceAllowanceState(Enum):
    """Enum representing different device allowance states as defined on BusinessFlow.

    Attributes:
        PARTIALLY_BLOCKED:
        BLOCKED:
        ALLOWED:
        NOT_ROUTED:

    """
    PARTIALLY_BLOCKED = AllowanceInfo("Partially Blocked", "Partially blocking devices")
    BLOCKED = AllowanceInfo("Blocked", "Blocking devices")
    ALLOWED = AllowanceInfo("Allowed", "Allowed devices")
    NOT_ROUTED = AllowanceInfo("Not Routed", "Not routed devices")

    @classmethod
    def from_string(cls, string):
        """Return an enum corresponding to the given string.

        Example:
            ::
                DeviceAllowanceState.from_string("Blocked") # Returns ``DeviceAllowanceState.BLOCKED``

        Raises:
            UnrecognizedAllowanceState: If the given string could not be matched to any of the enum members.

        Returns:
            DeviceAllowanceState: The relevant enum matching the given string.
        """
        if string.lower().startswith('partially'):
            return cls.PARTIALLY_BLOCKED
        elif string.lower().startswith('blocked'):
            return cls.BLOCKED
        elif string.lower().startswith('allowed'):
            return cls.ALLOWED
        elif string.lower().startswith('not routed'):
            return cls.NOT_ROUTED
        else:
            raise UnrecognizedAllowanceState("Unable to get DeviceAllowanceState from string state: {}".format(string))


ChangeRequestActionInfo = namedtuple("ChangeRequestActionInfo", ["api_value", "text"])


class ChangeRequestAction(Enum):
    """Enum representing a change request expected action.

    Attributes:
        ALLOW: This enum will mark the change request to allow the requested traffic
        DROP: This enum will mark the change request to block the requested traffic
    """
    ALLOW = ChangeRequestActionInfo("1", "allow")
    DROP = ChangeRequestActionInfo("0", "drop")


class NetworkObjectType(Enum):
    """Enum representing a ``NetworkObject`` type as defined on the API Guide.

    Used by various API clients to communicate with the AlgoSec servers.

    Attributes:
        HOST:
        RANGE:
        GROUP:
        ABSTRACT:
    """
    HOST = "Host"
    RANGE = "Range"
    # Currently not supported by "create_network_object" on ABF client
    GROUP = "Group"
    ABSTRACT = ""
