from hamcrest.core import assert_that
from hamcrest.core.core import is_
from hamcrest.core.core.isequal import equal_to

from algosec.models import RequestedFlow, ANY_OBJECT, LiteralService


class TestRequestedFlow(object):
    def setup(self):
        pass

    def test__are_sources_included_in_flow(self):
        assert_that(
            RequestedFlow._are_sources_included_in_flow(
                {"SOURCE-IP": {"objectID1", "objectID2"}, "SOURCE-IP2": {"objectID2", "objectID3"}},
                {'sources': [{"objectID": "objectID2"}]},
            ),
            is_(equal_to(True))
        )

        assert_that(
            RequestedFlow._are_sources_included_in_flow(
                {"SOURCE-IP": {"UnknownObject"}},
                {'sources': [{"objectID": "objectID1"}, {"objectID": "objectID2"}]},
            ),
            is_(equal_to(False))
        )

    def test__are_destinations_included_in_flow(self):
        assert_that(
            RequestedFlow._are_destinations_included_in_flow(
                {"DEST-IP": {"objectID1", "objectID2"}, "DEST-IP2": {"objectID2", "objectID3"}},
                {'destinations': [{"objectID": "objectID2"}]},
            ),
            is_(equal_to(True))
        )

        assert_that(
            RequestedFlow._are_destinations_included_in_flow(
                {"DEST-IP": {"UnknownObject"}},
                {'destinations': [{"objectID": "objectID1"}, {"objectID": "objectID2"}]},
            ),
            is_(equal_to(False))
        )

    def test__are_network_applications_included_in_flow(self):
        assert_that(
            RequestedFlow._are_network_applications_included_in_flow(
                ["app1", "app2"],
                {"networkApplications": [{"name": "app1"}, {"name": "app2"}, {"name": "app3"}]}
            ),
            is_(equal_to(True))
        )

        assert_that(
            RequestedFlow._are_network_applications_included_in_flow(
                ["app1", "UnknownApp"],
                {"networkApplications": [{"name": "app1"}, {"name": "app2"}, {"name": "app3"}]}
            ),
            is_(equal_to(False))
        )

        # Test the case where the network applications are set to ANY on the server
        assert_that(
            RequestedFlow._are_network_applications_included_in_flow(
                ["app1", "UnknownApp"],
                {"networkApplications": ANY_OBJECT}
            ),
            is_(equal_to(True))
        )

    def test__are_network_users_included_in_flow(self):
        assert_that(
            RequestedFlow._are_network_users_included_in_flow(
                ["user1", "user2"],
                {"networkUsers": [{"name": "user1"}, {"name": "user2"}, {"name": "user3"}]}
            ),
            is_(equal_to(True))
        )

        assert_that(
            RequestedFlow._are_network_users_included_in_flow(
                ["user1", "UnknownUser"],
                {"networkUsers": [{"name": "user1"}, {"name": "user2"}, {"name": "user3"}]}
            ),
            is_(equal_to(False))
        )

        # Test the case where the network users are set to ANY on the server
        assert_that(
            RequestedFlow._are_network_users_included_in_flow(
                ["user1", "UnknownUser"],
                {"networkUsers": ANY_OBJECT}
            ),
            is_(equal_to(True))
        )

    def test__are_network_services_included_in_flow(self):
        assert_that(
            RequestedFlow._are_network_services_included_in_flow(
                [LiteralService("TCP/123"), LiteralService("UDP/456")],
                {
                    "services": [
                        {"services": ["TCP/123", "UDP/456"]},
                        {"services": ["TCP/456", "UDP/123"]}]
                }
            ),
            is_(equal_to(True))
        )

        assert_that(
            RequestedFlow._are_network_services_included_in_flow(
                [LiteralService("TCP/1111")],
                {
                    "services": [
                        {"services": ["TCP/123", "UDP/456"]},
                        {"services": ["TCP/456", "UDP/123"]}]
                }
            ),
            is_(equal_to(False))
        )

        assert_that(
            RequestedFlow._are_network_services_included_in_flow(
                [LiteralService("TCP/123"), LiteralService("UDP/456")],
                {
                    "services": [
                        {"services": ["TCP/*", "UDP/*", "TCP/123"]}]
                }
            ),
            is_(equal_to(True))
        )
