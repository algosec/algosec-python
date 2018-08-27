"""Internal logic for computing different relations between application flows.

Note:
    Most developers will not have to use any of the contents of this module directly.

By the usage of the BusinessFlowAPIClient, the client is handling new and existing application flows from API flow.
The new flows are represented by the :class:`~algosec.models.RequestedFlow` class,
while the existing flows are represented as :class:`dict` objects fetched directly from the server.

The client have to make decisions from time to time to see if a new flow is equal or contained within a given
existing flow. To carry this exact task, a few comparison logic classes are implemented in this module.
"""

# An object defined by the API to denote that every object will match here
ANY_OBJECT = {u"id": 0, u"name": u"Any"}
ANY_NETWORK_APPLICATION = {u'revisionID': 0, u'name': u'Any'}


class IsEqualToFlowComparisonLogic(object):
    """Used to check if a new flow is included within an existing flow.

    The new flow is represented by a :class:`~algosec.models.RequestedFlow` object.
    The existing flow is represented by a :class:`dict` object fetched from the AlgoSec server.

    Note:
     The class is used statically with no need to initiate it.
    """
    @staticmethod
    def _are_sources_equal_in_flow(source_object_names, server_flow_sources):
        network_flow_source_object_names = {obj["name"] for obj in server_flow_sources}
        return set(source_object_names) == set(network_flow_source_object_names)

    @staticmethod
    def _are_destinations_equal_in_flow(destination_object_names, server_flow_destinations):
        network_flow_destination_object_names = {obj["name"] for obj in server_flow_destinations}
        return set(destination_object_names) == set(network_flow_destination_object_names)

    @staticmethod
    def _are_network_services_equal_in_flow(network_service_names, server_flow_services):
        network_flow_service_names = {obj["name"] for obj in server_flow_services}
        return set(network_service_names) == set(network_flow_service_names)

    @staticmethod
    def _are_network_applications_equal_in_flow(network_application_names, network_flow):
        if network_flow in ([ANY_NETWORK_APPLICATION], []):
            return network_application_names == []

        flow_application_names = [
            network_application["name"]
            for network_application in network_flow
        ]

        return set(network_application_names) == set(flow_application_names)

    @staticmethod
    def _are_network_users_equal_in_flow(network_users, network_flow):
        if network_flow in ([ANY_OBJECT], []):
            return network_users == []

        flow_users = [
            network_user["name"]
            for network_user in network_flow
        ]

        return set(network_users) == set(flow_users)

    @classmethod
    def is_equal(cls, requested_flow, flow_from_server):
        """Return True if a RequestedFlow is equal to an existing flow from BusinessFlow.

        For each source, destination, user, network_application and service check if that it is equal to
        the flow's relevant attribute.
        If all of the above are true, it means that the requested flow equals to the existing one.

        Args:
            requested_flow (algosec.models.RequestedFlow): The new flow to check if included in the existing flow.
            flow_from_server (dict): The existing flow from BusinessFlow.

        Returns:
            bool:  True if the requested flow is equal to the existing flow.
        """
        return all([
            cls._are_sources_equal_in_flow(
                requested_flow.sources,
                flow_from_server['sources'],
            ),
            cls._are_destinations_equal_in_flow(
                requested_flow.destinations,
                flow_from_server['destinations'],
            ),
            cls._are_network_services_equal_in_flow(
                requested_flow.network_services,
                flow_from_server['services'],
            ),
            cls._are_network_applications_equal_in_flow(
                requested_flow.network_applications,
                flow_from_server.get('networkApplications', []),
            ),
            cls._are_network_users_equal_in_flow(
                requested_flow.network_users,
                flow_from_server.get('networkUsers', []),
            ),
        ])
