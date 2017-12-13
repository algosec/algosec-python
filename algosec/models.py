import re
from collections import namedtuple

from enum import Enum

from algosec.errors import AlgosecAPIError, UnrecognizedAllowanceState, UnrecognizedServiceString

ALL_PORTS = "*"


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

    def _get_api_service_names(self, lst):
        """"""

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

    def populate(self, abf_client):
        """
        Populate the mappings and normalization objects based on the Algosec APIs

        :param AlgosecBusinessFlowAPIClient abf_client:
        """
        self.source_to_containing_object_ids = {
            source: {
                containing_object["objectID"]
                for containing_object in abf_client.find_network_objects(source, NetworkObjectSearchTypes.CONTAINING)
            }
            for source in self.sources
        }

        self.destination_to_containing_object_ids = {
            destination: {
                containing_object["objectID"]
                for containing_object in abf_client.find_network_objects(destination, NetworkObjectSearchTypes.CONTAINING)
            }
            for destination in self.destinations
        }

        # A new list to store normalized network services names. proto/port definition are made capital case
        normalized_network_services = []
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
                except:
                    raise AlgosecAPIError("Unable to resolve definition for requested service: {}".format(service))

            # the service variable might be normalized, and is re-added here
            normalized_network_services.append(service)

        self.network_services = normalized_network_services

    @staticmethod
    def _are_sources_included_in_flow(source_to_containing_object_ids, network_flow):
        existing_source_object_ids = {obj['objectID'] for obj in network_flow['sources']}

        return all(
            containing_object_ids.intersection(existing_source_object_ids)
            for containing_object_ids in source_to_containing_object_ids.values()
        )

    @staticmethod
    def _are_destinations_included_in_flow(destination_to_containing_object_ids, network_flow):
        existing_destination_object_ids = {obj['objectID'] for obj in network_flow['destinations']}

        return all(
            containing_object_ids.intersection(existing_destination_object_ids)
            for containing_object_ids in destination_to_containing_object_ids.values()
        )

    @staticmethod
    def _are_network_services_included_in_flow(current_network_services, network_flow):
        # TODO: Support TCP/* UDP/* service definitions on both sides of checking containment
        # Mark all of the services that are allowed for all ports with an asterisk
        allowed_protocols = set()

        aggregated_flow_network_services = set()
        for network_service in network_flow["services"]:
            for service_str in network_service["services"]:
                service = LiteralService(service_str)
                aggregated_flow_network_services.add(service)
                if service.port == ALL_PORTS:
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

    e.g: tcp/50
    """
    def __init__(self, service):
        # We upper the service since services are represented with upper when returned from Algosec
        self.service = service.upper()
        proto_port_match = re.match(PROTO_PORT_PATTERN, self.service, re.IGNORECASE)
        if not proto_port_match:
            raise UnrecognizedServiceString("Unable to parse literal service name: {}".format(service))

        self.port = proto_port_match.groupdict()["port"]
        self.protocol = proto_port_match.groupdict()["protocol"]

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
