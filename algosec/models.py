import re
from collections import namedtuple

from enum import Enum

from algosec.errors import AlgosecAPIError, UnrecognizedAllowanceState, UnrecognizedServiceString
from algosec.helpers import is_ip_or_subnet


class AlgosecProducts(Enum):
    BUSINESS_FLOW = "BusinessFlow"
    FIRE_FLOW = "FireFlow"


class NetworkObjectSearchTypes(Enum):
    INTERSECT = "INTERSECT"
    CONTAINED = "CONTAINED"
    CONTAINING = "CONTAINING"
    EXACT = "EXACT"


# An object defined by the API to denote that every object will match here
ANY_OBJECT = {u'id': 0, u'name': u'Any'}

PROTO_PORT_PATTERN = "(?P<protocol>(?:UDP|TCP))/(?P<port>\d+|\*)"


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

        # A new list to store normalized network services names. proto/port definition are made capital case
        # Currently Algosec servers support only uppercase protocol names across the board
        # For example: Trying to create a flow with service "tcp/54" will fail if there is only service named "TCP/54"
        # But then creating the exact same service "tcp/54" will give an exception that the service already exists
        normalized_network_services = []
        for service in self.network_services:
            try:
                self.aggregated_network_services.add(LiteralService(service))
                # normalize the service proto/port to upper case
                service = service.upper()
            except UnrecognizedServiceString:
                # We need to resolve the service names so we'll be able to check if their definition is included
                # within other network services that will be defined on Algosec.
                try:
                    network_service = abf_client.get_network_services_by_name(service)
                    for service_str in network_service["services"]:
                        self.aggregated_network_services.add(LiteralService(service_str))
                except AlgosecAPIError:
                    raise AlgosecAPIError("Unable to resolve definition for requested service: {}".format(service))

            # the service variable might be normalized, and is re-added here
            normalized_network_services.append(service)

        self.network_services = normalized_network_services

    @staticmethod
    def _are_sources_included_in_flow(sourcs_to_containing_object_ids, network_flow):
        existing_source_object_ids = {obj['objectID'] for obj in network_flow['sources']}

        return all(
            containing_object_ids.intersection(existing_source_object_ids)
            for containing_object_ids in sourcs_to_containing_object_ids.values()
        )

    @staticmethod
    def _are_destinations_included_in_flow(destinations_to_containing_object_ids, network_flow):
        existing_destination_object_ids = {obj['objectID'] for obj in network_flow['destinations']}

        return all(
            containing_object_ids.intersection(existing_destination_object_ids)
            for containing_object_ids in destinations_to_containing_object_ids.values()
        )

    @staticmethod
    def _are_network_services_included_in_flow(current_network_services, network_flow):
        # Mark all of the services that are allowed for all ports with an asterisk
        allowed_protocols = set()

        aggregated_flow_network_services = set()
        for network_service in network_flow["services"]:
            for service_str in network_service["services"]:
                service = LiteralService(service_str)
                aggregated_flow_network_services.add(service)
                # In case that all protocols and ports are allowed, return True
                # Such cases could be when a service with the '*' definition is defined as part of the flow
                if service.protocol == LiteralService.ALL and service.port == LiteralService.ALL:
                    return True
                if service.port == LiteralService.ALL:
                    allowed_protocols.add(service.protocol)

        # Generate a list of the network services which are not part of the 'allowed_protocols'
        services_to_check = set()
        for service in current_network_services:
            if service.protocol not in allowed_protocols:
                services_to_check.add(service)

        return services_to_check.issubset(aggregated_flow_network_services)

    @staticmethod
    def _are_network_applications_included_in_flow(existing_network_applications, network_flow):
        if network_flow["networkApplications"] == ANY_OBJECT:
            return True

        flow_applications = [
            network_application["name"]
            for network_application in network_flow["networkApplications"]
        ]

        return set(existing_network_applications).issubset(flow_applications)

    @staticmethod
    def _are_network_users_included_in_flow(network_users, network_flow):
        if network_flow["networkUsers"] == ANY_OBJECT:
            return True

        flow_users = [
            network_user["name"]
            for network_user in network_flow["networkUsers"]
        ]

        return set(network_users).issubset(flow_users)

    def is_included_in(self, network_flow):
        """
        Check if self (RequestedFlow) is contained within a given existing flow

        For each source, destination, user, network_application and service check if that it is contained within
        the flow's relevant attribute.
        If all of the above are true, it means that the new definition is already a subset of the exiting flow

        To check if a specific source/dest (IP/subnet) is contained
        within the flow's sources/destinations we do the following:
            - Query ABF for all of the network_object CONTAINING this IP/Subnet
            - If one of those objects is present in the current definition of soruces/destinations, it means
            that this source/dest if contained within the current flow.

        :return: True if included, else Flse
        """
        return all([
            self._are_sources_included_in_flow(self.source_to_containing_object_ids, network_flow),
            self._are_destinations_included_in_flow(self.destination_to_containing_object_ids, network_flow),
            self._are_network_services_included_in_flow(self.aggregated_network_services, network_flow),
            self._are_network_applications_included_in_flow(self.network_applications, network_flow),
            self._are_network_users_included_in_flow(self.network_users, network_flow),
        ])


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


class LiteralService(object):
    """
    Represent a protocol/proto service originated in a simple string

    e.g: tcp/50, tcp/*, *
    """
    ALL = "*"

    def __init__(self, service):
        # We upper the service since services are represented with upper when returned from Algosec
        self.service = service.upper()

        protocol, port = self._parse_string(self.service)
        self.protocol = protocol
        self.port = port

    @classmethod
    def _parse_string(cls, string):
        # If the string if just *, both the protocol and port are *
        if string == cls.ALL:
            return cls.ALL, cls.ALL

        # Now try and match and parse regular "protocol/port" pattern
        proto_port_match = re.match(PROTO_PORT_PATTERN, string, re.IGNORECASE)
        if not proto_port_match:
            raise UnrecognizedServiceString("Unable to parse literal service name: {}".format(string))

        port = proto_port_match.groupdict()["port"]
        protocol = proto_port_match.groupdict()["protocol"]
        return protocol, port

    def __hash__(self):
        return hash(self.service)

    def __eq__(self, other):
        return self.service == other.service

    def __ne__(self, other):
        # Not strictly necessary, but to avoid having both x==y and x!=y
        # True at the same time
        return not (self == other)

    def __str__(self):
        return self.service

    def __repr__(self):
        return "<LiteralService {}>".format(self.service)


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
