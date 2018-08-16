from inspect import isclass

import pytest
import requests
import six

from algosec.errors import UnrecognizedServiceString
from algosec.helpers import mount_algosec_adapter_on_session, AlgoSecServersHTTPAdapter, is_ip_or_subnet, LiteralService


def test_algosec_servers_http_adapter(mocker):
    adapter = AlgoSecServersHTTPAdapter()
    with mocker.patch('__builtin__.super') as mock_super:
        adapter.send()

        assert super.return_value.send.call_args == mocker.call(
            timeout=(
                AlgoSecServersHTTPAdapter.ALGOSEC_SERVER_CONNECT_TIMEOUT,
                AlgoSecServersHTTPAdapter.ALGOSEC_SERVER_READ_TIMEOUT
            )
        )
        assert mock_super(AlgoSecServersHTTPAdapter, adapter).calls[0]


def test_mount_algosec_adapter_on_session(mocker):
    session = requests.Session()
    mocker.spy(session, 'mount')
    mocker.patch.object(AlgoSecServersHTTPAdapter, '__init__', lambda x: None)

    mount_algosec_adapter_on_session(session)

    # This whole nasty loop is just to verify that it was called with proper args
    # I didn't find an elegant way to assert that the function is called twice with
    # an *Instance* of AlgoSecServersHTTPAdapter.
    for i, protocol in enumerate(['https', 'http']):
        assert session.mount.call_args_list[i][0][0] == '{}://'.format(protocol)
        assert isinstance(session.mount.call_args_list[i][0][1], AlgoSecServersHTTPAdapter)


@pytest.mark.parametrize("string,expected", [
    ("192.1.1.2", True),
    ("10.0.0.0/24", True),
    ("0.0.0.0", True),
    ("10.0.0.1/24", False),
    ("1.1.1.1/36", False),
    ("256.265.256.256", False),
    ("something", False),
])
def test_is_ip_or_subnet(string, expected):
    assert is_ip_or_subnet(string) == expected


class TestLiteralService(object):
    @pytest.mark.parametrize("string,expected", [
        ("tcp/50", ("tcp", "50")),
        ("udp/504", ("udp", "504")),
        ("tcp/*", ("tcp", "*")),
        ("udp/*", ("udp", "*")),
        ("*", ("*", "*")),
    ])
    def test_parse_string(self, string, expected):
        assert LiteralService._parse_string(string) == expected

    @pytest.mark.parametrize("string,exception", [
        ("unsupported-service-name", UnrecognizedServiceString),
    ])
    def test_parse_string_exception(self, string, exception):
        with pytest.raises(exception):
            LiteralService._parse_string(string)

    @pytest.mark.parametrize("string,expected,parse_string_result", [
        ("unsupported-service-name", False, UnrecognizedServiceString),
        ("udp/504", True, ("udp", "504")),
    ])
    def test_is_protocol_string(self, mocker, string, expected, parse_string_result):
        with mocker.patch.object(LiteralService, "_parse_string"):
            # Mock the return value of the parse string function
            if isclass(parse_string_result) and issubclass(parse_string_result, Exception):
                LiteralService._parse_string.side_effect = parse_string_result
            else:
                LiteralService._parse_string.return_value = parse_string_result

            assert LiteralService.is_protocol_string(string) == expected

    def test_repr(self):
        assert repr(LiteralService('tcp/50')) == "<LiteralService TCP/50>"

    def test_str(self):
        assert six.text_type(LiteralService('tcp/50')) == "TCP/50"

    def test_equal(self):
        assert LiteralService('tcp/50') == LiteralService('TCP/50')
        assert LiteralService('udp/50') == LiteralService('udp/50')

    def test_not_equal(self):
        assert LiteralService('tcp/50') != LiteralService('tcp/60')
        assert LiteralService('udp/50') != LiteralService('tcp/50')

    def test_hash(self):
        # Just make sure we can use it as dictionary key
        {LiteralService('tcp/50'): 5}
