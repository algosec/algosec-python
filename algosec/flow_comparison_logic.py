from algosec.helpers import LiteralService


# An object defined by the API to denote that every object will match here
ANY_OBJECT = {u"id": 0, u"name": u"Any"}
ANY_NETWORK_APPLICATION = {u'revisionID': 0, u'name': u'Any'}


class FlowComparisonLogic(object):
    pass


class IsIncludedInFlowComparisonLogic(FlowComparisonLogic):
    @staticmethod
    def are_sources_included_in_flow(sourcs_to_containing_object_ids, network_flow):
        existing_source_object_ids = {obj["objectID"] for obj in network_flow["sources"]}

        return all(
            containing_object_ids.intersection(existing_source_object_ids)
            for containing_object_ids in sourcs_to_containing_object_ids.values()
        )

    @staticmethod
    def are_destinations_included_in_flow(destinations_to_containing_object_ids, network_flow):
        existing_destination_object_ids = {obj["objectID"] for obj in network_flow["destinations"]}

        return all(
            containing_object_ids.intersection(existing_destination_object_ids)
            for containing_object_ids in destinations_to_containing_object_ids.values()
        )

    @staticmethod
    def are_network_services_included_in_flow(current_network_services, network_flow):
        # Mark all of the services that are allowed for all ports with an asterisk
        allowed_protocols = set()

        aggregated_flow_network_services = set()
        for network_service in network_flow["services"]:
            for service_str in network_service["services"]:
                service = LiteralService(service_str)
                aggregated_flow_network_services.add(service)
                # In case that all protocols and ports are allowed, return True
                # Such cases could be when a service with the "*" definition is defined as part of the flow
                if service.protocol == LiteralService.ALL and service.port == LiteralService.ALL:
                    return True
                if service.port == LiteralService.ALL:
                    allowed_protocols.add(service.protocol)

        # Generate a list of the network services which are not part of the "allowed_protocols"
        services_to_check = set()
        for service in current_network_services:
            if service.protocol not in allowed_protocols:
                services_to_check.add(service)

        return services_to_check.issubset(aggregated_flow_network_services)

    @staticmethod
    def are_network_applications_included_in_flow(network_applications, network_flow):
        if network_flow["networkApplications"] == [ANY_NETWORK_APPLICATION]:
            return True

        flow_applications = [
            network_application["name"]
            for network_application in network_flow["networkApplications"]
        ]

        return set(network_applications).issubset(flow_applications)

    @staticmethod
    def are_network_users_included_in_flow(network_users, network_flow):
        if network_flow["networkUsers"] == [ANY_OBJECT]:
            return True

        flow_users = [
            network_user["name"]
            for network_user in network_flow["networkUsers"]
        ]

        return set(network_users).issubset(flow_users)

    @classmethod
    def is_included(cls, requested_flow, existing_network_flow):
        """
        Check if a RequestedFlow is contained within a given existing flow on BusinessFlow

        For each source, destination, user, network_application and service check if that it is contained within
        the flow's relevant attribute.
        If all of the above are true, it means that the new definition is already a subset of the exiting flow

        To check if a specific source/dest (IP/subnet) is contained
        within the flow's sources/destinations we do the following:
            - Query ABF for all of the network_object CONTAINING this IP/Subnet
            - If one of those objects is present in the current definition of soruces/destinations, it means
            that this source/dest if contained within the current flow.

        :param algosec.models.RequestedFlow requested_flow:
        :return: True if included, else False
        """
        return all([
            cls.are_sources_included_in_flow(requested_flow.source_to_containing_object_ids, existing_network_flow),
            cls.are_destinations_included_in_flow(requested_flow.destination_to_containing_object_ids, existing_network_flow),
            cls.are_network_services_included_in_flow(requested_flow.aggregated_network_services, existing_network_flow),
            cls.are_network_applications_included_in_flow(requested_flow.network_applications, existing_network_flow),
            cls.are_network_users_included_in_flow(requested_flow.network_users, existing_network_flow),
        ])


class IsEqualToFlowComparisonLogic(FlowComparisonLogic):
    @staticmethod
    def are_sources_equal_in_flow(source_object_names, network_flow):
        network_flow_source_object_names = {obj["name"] for obj in network_flow["sources"]}
        return set(source_object_names) == set(network_flow_source_object_names)

    @staticmethod
    def are_destinations_equal_in_flow(destination_object_names, network_flow):
        network_flow_destination_object_names = {obj["name"] for obj in network_flow["destinations"]}
        return set(destination_object_names) == set(network_flow_destination_object_names)

    @staticmethod
    def are_network_services_equal_in_flow(network_service_names, network_flow):
        network_flow_service_names = {obj["name"] for obj in network_flow["services"]}
        return set(network_service_names) == set(network_flow_service_names)

    @staticmethod
    def are_network_applications_equal_in_flow(network_application_names, network_flow):
        if network_flow["networkApplications"] == [ANY_NETWORK_APPLICATION]:
            return network_application_names == []

        flow_application_names = [
            network_application["name"]
            for network_application in network_flow["networkApplications"]
        ]

        return set(network_application_names) == set(flow_application_names)

    @staticmethod
    def are_network_users_equal_in_flow(network_users, network_flow):
        if network_flow["networkUsers"] == [ANY_OBJECT]:
            return network_users == []

        flow_users = [
            network_user["name"]
            for network_user in network_flow["networkUsers"]
        ]

        return set(network_users) == set(flow_users)

    @classmethod
    def is_equal(cls, requested_flow, existing_network_flow):
        """
        Check if a RequestedFlow is equal to a given existing flow on BusinessFlow

        For each source, destination, user, network_application and service check if that it is equal to
        the flow's relevant attribute.
        If all of the above are true, it means that the requested flow equals to the existing one.

        :param algosec.models.RequestedFlow requested_flow:
        :return: True if the requested flow is equal to the existing one, else False
        """
        return all([
            cls.are_sources_equal_in_flow(requested_flow.sources, existing_network_flow),
            cls.are_destinations_equal_in_flow(requested_flow.destinations, existing_network_flow),
            cls.are_network_services_equal_in_flow(requested_flow.network_services, existing_network_flow),
            cls.are_network_applications_equal_in_flow(requested_flow.network_applications, existing_network_flow),
            cls.are_network_users_equal_in_flow(requested_flow.network_users, existing_network_flow),
        ])
