import re
from collections import namedtuple

from enum import Enum

from algosec.errors import AlgosecAPIError, UnrecognizedAllowanceState


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


class RequestedFlow(object):
    """
    Represents the attributes of a flow that is being requested by the user
    """

    PROTO_PORT_PATTERN = "(?P<proto>(?:UDP|TCP))/(?P<port>\d+)"

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
        self.sources = set(sources)
        self.destinations = set(destinations)
        self.network_users = set(network_users)
        self.network_applications = set(network_applications)
        self.network_services = set(network_services)
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
            sources=self._network_application_objects(self.sources),
            destinations=self._network_application_objects(self.destinations),
            users=self.network_users,
            network_applications=self._network_application_objects(self.network_applications),
            services=self._network_application_objects(self.network_services),
            comment=self.comment,
            custom_fields=self.custom_fields,
        )

    def _network_application_objects(self, lst):
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

        for service in self.network_services:
            proto_port_match = re.match(self.PROTO_PORT_PATTERN, service)
            if proto_port_match:
                # We upper the service since services are represented as
                self.aggregated_network_services.add(service.upper())
            else:
                try:
                    network_service = abf_client.get_network_services_by_name(service)
                    self.aggregated_network_services.update(network_service["services"])
                except:
                    raise AlgosecAPIError("Unable to resolve definition for requested service: {}".format(service))

    def _sources_are_included_in(self, network_flow):
        existing_source_object_ids = {obj['objectID'] for obj in network_flow['sources']}

        return all(
            containing_object_ids.intersection(existing_source_object_ids)
            for containing_object_ids in self.source_to_containing_object_ids.values()
        )

    def _destinations_are_included_in(self, network_flow):
        existing_destination_object_ids = {obj['objectID'] for obj in network_flow['destinations']}

        return all(
            containing_object_ids.intersection(existing_destination_object_ids)
            for containing_object_ids in self.destination_to_containing_object_ids.values()
        )

    def _network_services_are_included_in(self, network_flow):
        # TODO: The service normalization code should be executed way early on the process and not repeated stupidly here
        # TODO: over and over again.

        ### TODO: Support TCP/* UDP/* service definitions on both sides of checking containment
        aggregated_flow_network_services = {
            network_service["services"]
            for network_service in network_flow["services"]
        }

        return self.aggregated_network_services.issubset(aggregated_flow_network_services)

    def _network_applications_are_included_in(self, network_flow):
        if network_flow["networkApplications"] == ANY_OBJECT:
            return True

        flow_applications = [
            network_application["name"]
            for network_application in network_flow["networkApplications"]
        ]

        return self.network_applications.issubset(flow_applications)

    def _network_users_are_included_in(self, network_flow):
        if network_flow["networkUsers"] == ANY_OBJECT:
            return True

        flow_users = [
            network_user["name"]
            for network_user in network_flow["networkUsers"]
        ]

        return self.network_users.issubset(flow_users)

    def is_included_in(self, network_flow):
        """
        To check if the new flow definition is contained within the existing flow

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
            self._sources_are_included_in(network_flow),
            self._destinations_are_included_in(network_flow),
            self._network_services_are_included_in(network_flow),
            self._network_applications_are_included_in(network_flow),
            self._network_users_are_included_in(network_flow),
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


class ChangeRequestAction(Enum):
    """This object is representing whether the CR we are creating is ALLOW or DROP"""
    ALLOW = ChangeRequestActionInfo("1", "allow")
    DROP = ChangeRequestActionInfo("0", "drop")
