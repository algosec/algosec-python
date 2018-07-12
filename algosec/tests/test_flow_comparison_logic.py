from hamcrest.core import assert_that
from hamcrest.core.core import is_
from hamcrest.core.core.isequal import equal_to
from mock import Mock, patch

from algosec.flow_comparison_logic import (
    ANY_OBJECT,
    IsIncludedInFlowComparisonLogic,
    IsEqualToFlowComparisonLogic,
    ANY_NETWORK_APPLICATION,
)
from algosec.helpers import LiteralService


class TestIsIncludedInFlowComparisonLogic(object):
    def setup(self):
        pass

    def test__are_sources_included_in_flow(self):
        assert_that(
            IsIncludedInFlowComparisonLogic._are_sources_included_in_flow(
                {"SOURCE-IP": {"objectID1", "objectID2"}, "SOURCE-IP2": {"objectID2", "objectID3"}},
                [{"objectID": "objectID2"}],
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_sources_included_in_flow(
                {"SOURCE-IP": {"UnknownObject"}},
                [{"objectID": "objectID1"}, {"objectID": "objectID2"}],
            ),
            is_(equal_to(False))
        )

    def test__are_destinations_included_in_flow(self):
        assert_that(
            IsIncludedInFlowComparisonLogic._are_destinations_included_in_flow(
                {"DEST-IP": {"objectID1", "objectID2"}, "DEST-IP2": {"objectID2", "objectID3"}},
                [{"objectID": "objectID2"}],
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_destinations_included_in_flow(
                {"DEST-IP": {"UnknownObject"}},
                [{"objectID": "objectID1"}, {"objectID": "objectID2"}],
            ),
            is_(equal_to(False))
        )

    def test__are_network_applications_included_in_flow(self):
        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_applications_included_in_flow(
                ["app1", "app2"],
                [{"name": "app1"}, {"name": "app2"}, {"name": "app3"}]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_applications_included_in_flow(
                ["app1", "UnknownApp"],
                [{"name": "app1"}, {"name": "app2"}, {"name": "app3"}]
            ),
            is_(equal_to(False))
        )

        # Test the case where the network applications are set to ANY on the server
        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_applications_included_in_flow(
                ["app1", "UnknownApp"],
                [ANY_NETWORK_APPLICATION]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_applications_included_in_flow(
                [],
                [ANY_NETWORK_APPLICATION]
            ),
            is_(equal_to(True))
        )

        # Test the case where the network applications are missing from the server
        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_applications_included_in_flow(
                ["app1", "UnknownApp"],
                []
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_applications_included_in_flow(
                [],
                []
            ),
            is_(equal_to(True))
        )

    def test__are_network_users_included_in_flow(self):
        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_users_included_in_flow(
                ["user1", "user2"],
                [{"name": "user1"}, {"name": "user2"}, {"name": "user3"}]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_users_included_in_flow(
                ["user1", "UnknownUser"],
                [{"name": "user1"}, {"name": "user2"}, {"name": "user3"}]
            ),
            is_(equal_to(False))
        )

        # Test the case where the network users are set to ANY on the server
        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_users_included_in_flow(
                ["user1", "UnknownUser"],
                [ANY_OBJECT]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_users_included_in_flow(
                [],
                [ANY_OBJECT]
            ),
            is_(equal_to(True))
        )

        # Test the case where the network users are missing from the server
        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_users_included_in_flow(
                ["user1", "UnknownUser"],
                []
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_users_included_in_flow(
                [],
                []
            ),
            is_(equal_to(True))
        )

    def test__are_network_services_included_in_flow(self):
        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_services_included_in_flow(
                [LiteralService("TCP/123"), LiteralService("UDP/456")],
                [{"services": ["TCP/123", "UDP/456"]}, {"services": ["TCP/456", "UDP/123"]}]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_services_included_in_flow(
                [LiteralService("TCP/1111")],
                [{"services": ["TCP/123", "UDP/456"]}, {"services": ["TCP/456", "UDP/123"]}]
            ),
            is_(equal_to(False))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_services_included_in_flow(
                [LiteralService("TCP/123"), LiteralService("UDP/456")],
                [{"services": ["TCP/*", "UDP/*", "TCP/123"]}]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsIncludedInFlowComparisonLogic._are_network_services_included_in_flow(
                [LiteralService("TCP/123"), LiteralService("UDP/456")],
                [{"services": ["*"]}]
            ),
            is_(equal_to(True))
        )

    @patch.object(IsIncludedInFlowComparisonLogic, '_are_network_users_included_in_flow')
    @patch.object(IsIncludedInFlowComparisonLogic, '_are_network_applications_included_in_flow')
    @patch.object(IsIncludedInFlowComparisonLogic, '_are_network_services_included_in_flow')
    @patch.object(IsIncludedInFlowComparisonLogic, '_are_destinations_included_in_flow')
    @patch.object(IsIncludedInFlowComparisonLogic, '_are_sources_included_in_flow')
    def test__is_included_all_fields_are_checked(
            self,
            m_are_sources_included_in_flow,
            m_are_destinations_included_in_flow,
            m_are_network_services_included_in_flow,
            m_are_network_applications_included_in_flow,
            m_are_network_users_included_in_flow,
    ):
        requested_flow = Mock()
        server_flow = Mock()
        server_flow.__getitem__ = Mock()
        IsIncludedInFlowComparisonLogic.is_included(requested_flow, server_flow)

        m_are_sources_included_in_flow.assert_called_once_with(
            requested_flow.source_to_containing_object_ids, server_flow['sources']
        )
        m_are_destinations_included_in_flow.assert_called_once_with(
            requested_flow.destination_to_containing_object_ids, server_flow['destinations']
        )
        m_are_network_services_included_in_flow.assert_called_once_with(
            requested_flow.aggregated_network_services, server_flow['services']
        )
        m_are_network_applications_included_in_flow.assert_called_once_with(
            requested_flow.network_applications, server_flow.get('networkApplications', [])
        )
        m_are_network_users_included_in_flow.assert_called_once_with(
            requested_flow.network_users, server_flow.get('networkUsers', [])
        )


class TestIsEqualToFlowComparisonLogic(object):

    def test__are_sources_equal_in_flow(self):
        assert_that(
            IsEqualToFlowComparisonLogic._are_sources_equal_in_flow(
                ["objectName1", "objectName2"],
                [{"name": "objectName1"}, {"name": "objectName2"}],
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsEqualToFlowComparisonLogic._are_sources_equal_in_flow(
                ["objectName1"],
                [{"name": "UnknownObjectName"}],
            ),
            is_(equal_to(False))
        )

    def test__are_destinations_equal_in_flow(self):
        assert_that(
            IsEqualToFlowComparisonLogic._are_destinations_equal_in_flow(
                ["objectName1", "objectName2"],
                [{"name": "objectName1"}, {"name": "objectName2"}],
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsEqualToFlowComparisonLogic._are_destinations_equal_in_flow(
                ["objectName1"],
                [{"name": "UnknownObjectName"}],
            ),
            is_(equal_to(False))
        )

    def test__are_network_applications_equal_in_flow(self):
        assert_that(
            IsEqualToFlowComparisonLogic._are_network_applications_equal_in_flow(
                ["app1", "app2"],
                [{"name": "app1"}, {"name": "app2"}]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsEqualToFlowComparisonLogic._are_network_applications_equal_in_flow(
                ["app1", "app2", "app3"],
                [{"name": "app1"}, {"name": "app2"}]
            ),
            is_(equal_to(False))
        )

        # Test the case where the network applications are set to ANY on the server
        assert_that(
            IsEqualToFlowComparisonLogic._are_network_applications_equal_in_flow(
                [],
                [ANY_NETWORK_APPLICATION]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsEqualToFlowComparisonLogic._are_network_applications_equal_in_flow(
                ["app1"],
                [ANY_NETWORK_APPLICATION]
            ),
            is_(equal_to(False))
        )

        # Test the case where the network applications are missing from the server
        assert_that(
            IsEqualToFlowComparisonLogic._are_network_applications_equal_in_flow(
                [],
                []
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsEqualToFlowComparisonLogic._are_network_applications_equal_in_flow(
                ["app1"],
                []
            ),
            is_(equal_to(False))
        )

    def test__are_network_users_equal_in_flow(self):
        assert_that(
            IsEqualToFlowComparisonLogic._are_network_users_equal_in_flow(
                ["user1", "user2"],
                [{"name": "user1"}, {"name": "user2"}]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsEqualToFlowComparisonLogic._are_network_users_equal_in_flow(
                ["user1", "UnknownUser"],
                [{"name": "user1"}, {"name": "user2"}]
            ),
            is_(equal_to(False))
        )

        # Test the case where the network users are set to ANY on the server
        assert_that(
            IsEqualToFlowComparisonLogic._are_network_users_equal_in_flow(
                ["user1"],
                [ANY_OBJECT]
            ),
            is_(equal_to(False))
        )

        assert_that(
            IsEqualToFlowComparisonLogic._are_network_users_equal_in_flow(
                [],
                [ANY_OBJECT]
            ),
            is_(equal_to(True))
        )

        # Test the case where the network users are missing from the server
        assert_that(
            IsEqualToFlowComparisonLogic._are_network_users_equal_in_flow(
                ["user1"],
                []
            ),
            is_(equal_to(False))
        )

        assert_that(
            IsEqualToFlowComparisonLogic._are_network_users_equal_in_flow(
                [],
                []
            ),
            is_(equal_to(True))
        )

    def test__are_network_services_equal_in_flow(self):
        # TODO: Make sure that we have no issues with case sensitiveness of TCP/80 vs tcp/80 for any of the protocols
        assert_that(
            IsEqualToFlowComparisonLogic._are_network_services_equal_in_flow(
                ["service1", "service2"],
                [{"name": "service2"}, {"name": "service1"}]
            ),
            is_(equal_to(True))
        )

        assert_that(
            IsEqualToFlowComparisonLogic._are_network_services_equal_in_flow(
                ["service2"],
                [{"name": "service1"}],
            ),
            is_(equal_to(False))
        )

    @patch.object(IsEqualToFlowComparisonLogic, '_are_network_users_equal_in_flow')
    @patch.object(IsEqualToFlowComparisonLogic, '_are_network_applications_equal_in_flow')
    @patch.object(IsEqualToFlowComparisonLogic, '_are_network_services_equal_in_flow')
    @patch.object(IsEqualToFlowComparisonLogic, '_are_destinations_equal_in_flow')
    @patch.object(IsEqualToFlowComparisonLogic, '_are_sources_equal_in_flow')
    def test__is_equal_all_fields_are_checked(
            self,
            m_are_sources_equal_in_flow,
            m_are_destinations_equal_in_flow,
            m_are_network_services_equal_in_flow,
            m_are_network_applications_equal_in_flow,
            m_are_network_users_equal_in_flow,
    ):
        requested_flow = Mock()
        server_flow = Mock()
        server_flow.__getitem__ = Mock()
        IsEqualToFlowComparisonLogic.is_equal(requested_flow, server_flow)

        m_are_sources_equal_in_flow.assert_called_once_with(
            requested_flow.sources, server_flow['sources']
        )
        m_are_destinations_equal_in_flow.assert_called_once_with(
            requested_flow.destinations, server_flow['destinations']
        )
        m_are_network_services_equal_in_flow.assert_called_once_with(
            requested_flow.network_services, server_flow['services']
        )
        m_are_network_applications_equal_in_flow.assert_called_once_with(
            requested_flow.network_applications, server_flow.get('networkApplications', [])
        )
        m_are_network_users_equal_in_flow.assert_called_once_with(
            requested_flow.network_users, server_flow.get('networkUsers', [])
        )
