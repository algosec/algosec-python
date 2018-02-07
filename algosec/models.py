from collections import namedtuple

from enum import Enum

from algosec.errors import AlgosecAPIError, UnrecognizedAllowanceState, UnrecognizedServiceString
from algosec.helpers import is_ip_or_subnet, LiteralService


class AlgosecProducts(Enum):
    BUSINESS_FLOW = "BusinessFlow"
    FIRE_FLOW = "FireFlow"


class NetworkObjectSearchTypes(Enum):
    INTERSECT = "INTERSECT"
    CONTAINED = "CONTAINED"
    CONTAINING = "CONTAINING"
    EXACT = "EXACT"


class RequestedFlow(object):
    """
    Represents the attributes of a flow that is being requested by the user
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
    ):
        self.name = name
        self.sources = sources
        self.destinations = destinations
        self.network_users = network_users
        self.network_applications = network_applications
        self.network_services = network_services
        self.comment = comment
        self.custom_fields = custom_fields or []

        # Mapped and normalized objects to be populated later on
        self.source_to_containing_object_ids = {}
        self.destination_to_containing_object_ids = {}
        self.aggregated_network_services = set()

        self.normalize_network_services()

    def normalize_network_services(self):
        # A new list to store normalized network services names. proto/port definition are made capital case
        # Currently Algosec servers support only uppercase protocol names across the board
        # For example: Trying to create a flow with service "tcp/54" will fail if there is only service named "TCP/54"
        # But then creating the exact same service "tcp/54" will give an exception that the service already exists
        normalized_network_services = []
        for service in self.network_services:
            if LiteralService.is_protocol_string(service):
                service = service.upper()
            normalized_network_services.append(service)
        self.network_services = normalized_network_services

    @property
    def new_flow_json_for_api(self):
        return dict(
            type="APPLICATION",
            name=self.name,
            sources=self._api_named_object(self.sources),
            destinations=self._api_named_object(self.destinations),
            users=self.network_users,
            network_applications=self._api_named_object(self.network_applications),
            services=self._api_named_object(self.network_services),
            comment=self.comment,
            custom_fields=self.custom_fields,
        )

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
                except AlgosecAPIError:
                    raise AlgosecAPIError("Unable to resolve network object by name: {}".format(network_object))

            for ip_or_subnet in ips_and_subnets:
                network_objects_to_containing_object_ids[ip_or_subnet] = {
                    containing_object["objectID"] for containing_object in
                    abf_client.find_network_objects(ip_or_subnet, NetworkObjectSearchTypes.CONTAINED)
                }

        return network_objects_to_containing_object_ids

    def populate(self, abf_client):
        """
        Populate the mappings and normalization objects based on the Algosec APIs

        :param AlgosecBusinessFlowAPIClient abf_client:
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
                # within other network services that will be defined on Algosec.
                try:
                    network_service = abf_client.get_network_services_by_name(service)
                    for service_str in network_service["services"]:
                        self.aggregated_network_services.add(LiteralService(service_str))
                except AlgosecAPIError:
                    raise AlgosecAPIError("Unable to resolve definition for requested service: {}".format(service))


AllowanceInfo = namedtuple("AllowanceInfo", ["text", "title"])


class DeviceAllowanceState(Enum):
    """Used for the query in IsTrafficAllowedCheck to identify state of each device"""
    PARTIALLY_BLOCKED = AllowanceInfo("Partially Blocked", "Partially blocking devices")
    BLOCKED = AllowanceInfo("Blocked", "Blocking devices")
    ALLOWED = AllowanceInfo("Allowed", "Allowed devices")
    NOT_ROUTED = AllowanceInfo("Not Routed", "Not routed devices")

    @classmethod
    def from_string(cls, string):
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
    """This object is representing whether the CR we are creating is ALLOW or DROP"""
    ALLOW = ChangeRequestActionInfo("1", "allow")
    DROP = ChangeRequestActionInfo("0", "drop")


class NetworkObjectType(Enum):
    HOST = "Host"
    RANGE = "Range"
    # Currently not supported by "create_network_object" on ABF client
    GROUP = "Group"
    ABSTRACT = ""
