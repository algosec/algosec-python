"""Define models and enums used by the API clients.

Note:
    Most developers will not have to use any of the contents of this module directly.
"""
from collections import namedtuple

from enum import Enum

from algosec.errors import UnrecognizedAllowanceState


class RequestedFlow(object):
    """Represents a NewFlow model from the API Guide.

    This model is used by the :class:`~algosec.api_clients.business_flow.BusinessFlowAPIClient` to
    create and handle different operations regarding new and existing flows.

    It is used to represent a new flow that is about to be created.

    Args:
        name (str): The name of the new flow.
        sources (list[str]): Sources for the flow.
        destinations (list[str]): Destinations for the flow.
        network_users (list[str]): Network user names for the flow.
        network_applications (list[str]): Names of network application for the flow.
        network_services (list[str]): Names of network services names for the flow.
        comment (str): Any comment to save alongside the flow.
        custom_fields (list): Custom fields for the new flow
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

    @staticmethod
    def _api_named_object(lst):
        """
        ABF expect to get most simple objects as a dict pointing to their name
        this is a helper function to achieve that

        :param lst:
        :return:
        """
        return [{"name": obj} for obj in lst]

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


AllowanceInfo = namedtuple("AllowanceInfo", ["text", "title"])


class NetworkObjectSearchTypes(Enum):
    """Enum used for :py:meth:`~algosec.api_clients.business_flow.BusinessFlowAPIClient.search_network_objects`"""
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
        HOST: Denotes an object that is defined by it's IP address.
        RANGE: Denotes an object that is defined by an IP range or CIDR.
        GROUP: Denotes an object that is defined by a list of ExistingNetworkObject or NewNetworkObject objects.
        ABSTRACT: Denotes an object that is devoid of any particular definition. Defined with empty content.
    """
    HOST = "Host"
    RANGE = "Range"
    # Currently not supported by "create_network_object" on ABF client
    GROUP = "Group"
    ABSTRACT = ""


class ChangeRequestTrafficLine(object):
    def __init__(self, action, sources, destinations, services):
        """
        Represent a traffic line while creating a change request by the api client.

        Args:
            action (algosec.models.ChangeRequestAction): action requested by this traffic line
                to allow or drop traffic.
            sources (list[str]): List of IP address representing the source of the traffic.
            destinations (list[str]): List of IP address representing the destination of the traffic.
            services (list[str]): List of services which describe the type of traffic. Each service could be a service
                name as defined on AlgoSec servers or just a proto/port pair. (e.g. ssh, http, tcp/50, udp/700)
        """
        self.action = action
        self.sources = sources
        self.destinations = destinations
        self.services = services
