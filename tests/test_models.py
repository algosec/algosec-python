import pytest

from algosec.errors import UnrecognizedAllowanceState
from algosec.models import DeviceAllowanceState, RequestedFlow, ChangeRequestTrafficLine, ChangeRequestAction


class TestRequestedFlow(object):
    def test_api_named_object(self):
        assert RequestedFlow._api_named_object(['1', '2', '3']) == [
            {'name': '1'},
            {'name': '2'},
            {'name': '3'},
        ]

    def test_get_json_flow_definition(self, mocker):
        with mocker.patch.object(RequestedFlow, '_api_named_object'):
            flow = RequestedFlow(
                name='name',
                sources=['source1', 'source2'],
                destinations=['dest1', 'dest2'],
                network_users=['user1', 'user2'],
                network_applications=['app1', 'app2'],
                network_services=['service1', 'service2'],
                comment='comment',
                type='type',
            )

            assert flow.get_json_flow_definition() == dict(
                type=flow.type,
                name=flow.name,
                sources=flow._api_named_object(flow.sources),
                destinations=flow._api_named_object(flow.destinations),
                users=flow.network_users,
                network_applications=flow._api_named_object(flow.network_applications),
                services=flow._api_named_object(flow.network_services),
                comment=flow.comment,
                custom_fields=flow.custom_fields,
            )


class TestDeviceAllowanceState(object):
    @pytest.mark.parametrize("string,expected", [
        ("Partially Allowed", DeviceAllowanceState.PARTIALLY_BLOCKED),
        ("blocked", DeviceAllowanceState.BLOCKED),
        ("allowed", DeviceAllowanceState.ALLOWED),
        ("Not routed", DeviceAllowanceState.NOT_ROUTED),
    ])
    def test_from_string(self, string, expected):
        # Make sure we have no case sensitivity
        assert DeviceAllowanceState.from_string(string) == expected
        assert DeviceAllowanceState.from_string(string.lower()) == expected
        assert DeviceAllowanceState.from_string(string.upper()) == expected

    @pytest.mark.parametrize("string,exception", [
        ("UnknownState", UnrecognizedAllowanceState),
    ])
    def test_from_string_on_excpetion(self, string, exception):
        # Check the handling of unknown state
        with pytest.raises(exception):
            DeviceAllowanceState.from_string(string)


class TestChangeRequestTrafficLine(object):
    def test_init(self):
        ChangeRequestTrafficLine(
            ChangeRequestAction.ALLOW,
            ['source1', 'source2'],
            ['dest1', 'dest2'],
            ['service1', 'service2'],
        )
