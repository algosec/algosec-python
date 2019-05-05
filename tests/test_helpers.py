import logging

import mock
import pytest
import requests
from suds.plugin import MessageContext

from algosec.helpers import (
    mount_adapter_on_session,
    AlgoSecServersHTTPAdapter,
    is_ip_or_subnet,
    LogSOAPMessages,
)


@mock.patch("six.moves.builtins.super")
def test_algosec_servers_http_adapter(mock_super, mocker):
    adapter = AlgoSecServersHTTPAdapter()
    adapter.send()
    assert super.return_value.send.call_args == mocker.call(
        timeout=(
            AlgoSecServersHTTPAdapter.ALGOSEC_SERVER_CONNECT_TIMEOUT,
            AlgoSecServersHTTPAdapter.ALGOSEC_SERVER_READ_TIMEOUT,
        )
    )
    assert mock_super(AlgoSecServersHTTPAdapter, adapter).calls[0]


def test_mount_algosec_adapter_on_session(mocker):
    session = requests.Session()
    mocker.spy(session, "mount")
    mocker.patch.object(AlgoSecServersHTTPAdapter, "__init__", lambda x: None)

    adapter = AlgoSecServersHTTPAdapter()
    mount_adapter_on_session(session, adapter)

    # This whole nasty loop is just to verify that it was called with proper args
    # I didn't find an elegant way to assert that the function is called twice with
    # an *Instance* of AlgoSecServersHTTPAdapter.
    for i, protocol in enumerate(["https", "http"]):
        assert session.mount.call_args_list[i][0][0] == "{}://".format(protocol)
        assert session.mount.call_args_list[i][0][1] == adapter


@pytest.mark.parametrize(
    "string,expected",
    [
        ("192.1.1.2", True),
        ("10.0.0.0/24", True),
        ("0.0.0.0", True),
        ("10.0.0.1/24", False),
        ("1.1.1.1/36", False),
        ("256.265.256.256", False),
        ("something", False),
    ],
)
def test_is_ip_or_subnet(string, expected):
    assert is_ip_or_subnet(string) == expected


class TestLogSOAPMessages(object):
    @classmethod
    def setup_class(cls):
        logging.getLogger().setLevel(logging.DEBUG)

    @classmethod
    def teardown_class(cls):
        logging.getLogger().setLevel(logging.INFO)

    @pytest.mark.parametrize("message", [b"some bits", True, 123, "some string"])
    def test_sending(self, caplog, message):
        context = MessageContext()
        context.envelope = message

        logging_plugin = LogSOAPMessages()
        logging_plugin.sending(context)

        log_records = list(caplog.records)
        assert len(log_records) == 1
        log_record = log_records[0]

        assert log_record.levelno == logging.DEBUG
        assert log_record.message == "Sending SOAP message: {}".format(str(message))

    @pytest.mark.parametrize("message", [b"some bits", True, 123, "some string"])
    def test_received(self, caplog, message):
        context = MessageContext()
        context.reply = message

        logging_plugin = LogSOAPMessages()
        logging_plugin.received(context)

        log_records = list(caplog.records)
        assert len(log_records) == 1
        log_record = log_records[0]

        assert log_record.levelno == logging.DEBUG
        assert log_record.message == "Received SOAP message: {}".format(str(message))
