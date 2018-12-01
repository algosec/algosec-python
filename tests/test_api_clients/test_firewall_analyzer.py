import mock
import pytest
from mock import MagicMock
from suds import WebFault

from algosec.api_clients.firewall_analyzer import FirewallAnalyzerAPIClient
from algosec.errors import AlgoSecLoginError, UnrecognizedAllowanceState, AlgoSecAPIError
from algosec.models import DeviceAllowanceState


class TestFirewallAnalyzerAPIClient(object):
    @pytest.fixture()
    def analyzer_client(self, request):
        return FirewallAnalyzerAPIClient(
            'server-ip',
            'username',
            'password',
            verify_ssl=True
        )

    @pytest.mark.parametrize('host,expected', [
        ('127.0.0.1', 'https://127.0.0.1/AFA/php/ws.php?wsdl'),
        ('local.algosec.com', 'https://local.algosec.com/AFA/php/ws.php?wsdl'),
    ])
    def test_wsdl_url_path_property(self, analyzer_client, host, expected):
        analyzer_client.server_ip = host
        assert analyzer_client._wsdl_url_path == expected

    def test_initiate_client(self, mocker, analyzer_client):
        with mocker.patch.object(analyzer_client, "_get_soap_client"):
            client = analyzer_client._initiate_client()

            # Assert that the soap client was created properly
            assert client == analyzer_client._get_soap_client.return_value
            analyzer_client._get_soap_client.assert_called_once_with(
                'https://{}/AFA/php/ws.php?wsdl'.format(analyzer_client.server_ip),
                location='https://{}/AFA/php/ws.php'.format(analyzer_client.server_ip)
            )

            # Assert that the soap client was logged in and the session id was saved
            assert analyzer_client._session_id == client.service.connect.return_value
            assert client.service.connect.call_args == mocker.call(
                Domain='',
                Password=analyzer_client.password,
                UserName=analyzer_client.user,
            )

    def test_initiate_client_login_error(self, mocker, analyzer_client):
        mock_get_soap_client = MagicMock()
        mock_get_soap_client.return_value.service.connect.side_effect = WebFault("Login Error", document={})
        with mocker.patch.object(analyzer_client, "_get_soap_client", mock_get_soap_client):
            with pytest.raises(AlgoSecLoginError):
                analyzer_client._initiate_client()

    def test_calc_aggregated_query_result(self):
        assert FirewallAnalyzerAPIClient._calc_aggregated_query_result({
            DeviceAllowanceState.PARTIALLY_BLOCKED: ['partially-blocked'],
            DeviceAllowanceState.BLOCKED: ['blocked-device'],
            DeviceAllowanceState.ALLOWED: ['allowed-device']
        }) == DeviceAllowanceState.PARTIALLY_BLOCKED

        assert FirewallAnalyzerAPIClient._calc_aggregated_query_result({
            DeviceAllowanceState.PARTIALLY_BLOCKED: ['some-device'],
            DeviceAllowanceState.BLOCKED: [],
            DeviceAllowanceState.ALLOWED: []
        }) == DeviceAllowanceState.PARTIALLY_BLOCKED

        assert FirewallAnalyzerAPIClient._calc_aggregated_query_result({
            DeviceAllowanceState.PARTIALLY_BLOCKED: [],
            DeviceAllowanceState.BLOCKED: ['blocked-device'],
            DeviceAllowanceState.ALLOWED: ['allowed-device']
        }) == DeviceAllowanceState.PARTIALLY_BLOCKED

        assert FirewallAnalyzerAPIClient._calc_aggregated_query_result({
            DeviceAllowanceState.PARTIALLY_BLOCKED: [],
            DeviceAllowanceState.BLOCKED: ['blocked-device'],
            DeviceAllowanceState.ALLOWED: []
        }) == DeviceAllowanceState.BLOCKED

        assert FirewallAnalyzerAPIClient._calc_aggregated_query_result({
            DeviceAllowanceState.PARTIALLY_BLOCKED: [],
            DeviceAllowanceState.BLOCKED: [],
            DeviceAllowanceState.ALLOWED: ['allowed-device']
        }) == DeviceAllowanceState.ALLOWED

        assert FirewallAnalyzerAPIClient._calc_aggregated_query_result({
            DeviceAllowanceState.PARTIALLY_BLOCKED: [],
            DeviceAllowanceState.BLOCKED: [],
            DeviceAllowanceState.ALLOWED: []
        }) == DeviceAllowanceState.ALLOWED

    def test_prepare_simulation_query_results(self, mocker):
        device_1 = MagicMock()
        device_2 = MagicMock()
        device_3 = MagicMock()

        def mock_device_to_allowance_state(device):
            return {
                device_1.IsAllowed: DeviceAllowanceState.PARTIALLY_BLOCKED,
                device_2.IsAllowed: DeviceAllowanceState.BLOCKED,
                device_3.IsAllowed: DeviceAllowanceState.ALLOWED,
            }[device]

        # Mock the from_string method return values per device
        with mocker.patch.object(DeviceAllowanceState, "from_string", side_effect=mock_device_to_allowance_state):
            query_results = FirewallAnalyzerAPIClient._prepare_simulation_query_results([
                device_1,
                device_2,
                device_3
            ])

            assert query_results[DeviceAllowanceState.PARTIALLY_BLOCKED] == [device_1]
            assert query_results[DeviceAllowanceState.BLOCKED] == [device_2]
            assert query_results[DeviceAllowanceState.ALLOWED] == [device_3]

    def test_prepare_simulation_query_results__ordered_result_keys(self):
        """Assert that the result keys are sorted for later preview requirements"""
        query_results = FirewallAnalyzerAPIClient._prepare_simulation_query_results([])
        assert (
            list(query_results.keys())
            ==
            [DeviceAllowanceState.BLOCKED, DeviceAllowanceState.PARTIALLY_BLOCKED, DeviceAllowanceState.ALLOWED]
        )

    @mock.patch("algosec.api_clients.firewall_analyzer.logger")
    def test_prepare_simulation_query_results__unknown_allowance_state(self, mock_module_logger, mocker):
        """Make sure that a warning is logged when the allowance state is unrecognized"""
        device_1 = MagicMock()
        with mocker.patch.object(DeviceAllowanceState, "from_string", side_effect=UnrecognizedAllowanceState):
            assert mock_module_logger.warning.call_count == 0
            FirewallAnalyzerAPIClient._prepare_simulation_query_results([device_1])
            assert mock_module_logger.warning.call_count == 1

    def test_get_summarized_query_result__api_result_missing(self, analyzer_client, mocker):
        # Mock missing attribute "QueryResult" from the query response
        query_response = MagicMock(spec=[])
        query_results = MagicMock()
        with mocker.patch.object(FirewallAnalyzerAPIClient, "_calc_aggregated_query_result"):
            aggregated_result = analyzer_client._get_summarized_query_result(query_response, query_results)

        analyzer_client._calc_aggregated_query_result.assert_called_once_with(query_results)
        assert aggregated_result == analyzer_client._calc_aggregated_query_result.return_value

    @mock.patch('algosec.models.DeviceAllowanceState.from_string')
    def test__get_summarized_query_result__api_result_present(self, mock_from_string, analyzer_client):
        query_response = MagicMock(spec=["QueryResult"])
        query_results = MagicMock()

        aggregated_result = analyzer_client._get_summarized_query_result(query_response, query_results)

        mock_from_string.assert_called_once_with(query_response.QueryResult)
        assert aggregated_result == mock_from_string.return_value

    @mock.patch('algosec.api_clients.firewall_analyzer.FirewallAnalyzerAPIClient._prepare_simulation_query_results')
    @mock.patch('algosec.api_clients.firewall_analyzer.FirewallAnalyzerAPIClient._get_summarized_query_result')
    def test_run_traffic_simulation_query(
            self,
            mock_get_summarized_query,
            mock_prepare_results,
            mocker,
            analyzer_client
    ):
        # Mock the client and it's response content
        query_response_devices = [MagicMock()]
        simulation_query_response = MagicMock()
        simulation_query_response[0].QueryItem.Device = query_response_devices
        mock_soap_client = MagicMock()
        mock_soap_client.service.query.return_value.QueryResult = simulation_query_response
        analyzer_client._session_id = MagicMock()

        # mock the simulation input
        source = MagicMock()
        dest = MagicMock()
        service = MagicMock()
        with mocker.patch.object(analyzer_client, "_client", mock_soap_client):
            simulation_result = analyzer_client.run_traffic_simulation_query(source, dest, service)

            # assert return value
            assert simulation_result == mock_get_summarized_query.return_value

            # assert internal simulation query call
            mock_soap_client.service.query.assert_called_once_with(
                SessionID=analyzer_client._session_id,
                QueryInput={
                    'Source': source,
                    'Destination': dest,
                    'Service': service
                }
            )

            # assert internal helper calls
            mock_prepare_results.assert_called_once_with(query_response_devices)
            mock_get_summarized_query.assert_called_once_with(
                simulation_query_response[0],
                mock_prepare_results.return_value
            )

    @mock.patch('algosec.api_clients.firewall_analyzer.FirewallAnalyzerAPIClient._prepare_simulation_query_results')
    @mock.patch('algosec.api_clients.firewall_analyzer.FirewallAnalyzerAPIClient._get_summarized_query_result')
    def test_run_traffic_simulation_query__one_device_in_result(
            self,
            mock_get_summarized_query,
            mock_prepare_results,
            mocker,
            analyzer_client
    ):
        """Make sure that one device in the query is interpreted as a list"""
        # Mock the client and it's response content
        query_response_devices = MagicMock()
        simulation_query_response = MagicMock()
        simulation_query_response[0].QueryItem.Device = query_response_devices
        mock_soap_client = MagicMock()
        mock_soap_client.service.query.return_value.QueryResult = simulation_query_response

        with mocker.patch.object(analyzer_client, "_client", mock_soap_client):
            analyzer_client.run_traffic_simulation_query(MagicMock(), MagicMock(), MagicMock())

            # assert that the single device was converted to list
            mock_prepare_results.assert_called_once_with([query_response_devices])

    @mock.patch('algosec.api_clients.firewall_analyzer.FirewallAnalyzerAPIClient._prepare_simulation_query_results')
    @mock.patch('algosec.api_clients.firewall_analyzer.FirewallAnalyzerAPIClient._get_summarized_query_result')
    def test_run_traffic_simulation_query__empty_query_result(
            self,
            mock_get_summarized_query,
            mock_prepare_results,
            mocker,
            analyzer_client
    ):
        """Make sure that function can handle no devices in result"""
        # Mock the client and it's response content
        simulation_query_response = MagicMock()
        simulation_query_response[0].QueryItem = None
        mock_soap_client = MagicMock()
        mock_soap_client.service.query.return_value.QueryResult = simulation_query_response

        with mocker.patch.object(analyzer_client, "_client", mock_soap_client):
            analyzer_client.run_traffic_simulation_query(MagicMock(), MagicMock(), MagicMock())

            # assert that the device list was assumed to be empty
            mock_prepare_results.assert_called_once_with([])

    def test_run_traffic_simulation_query__faulty_query(self, mocker, analyzer_client):
        mock_soap_client = MagicMock()
        mock_soap_client.service.query.side_effect = WebFault("Query Error", document={})

        with mocker.patch.object(analyzer_client, "_client", mock_soap_client):
            with pytest.raises(AlgoSecAPIError):
                analyzer_client.run_traffic_simulation_query(MagicMock(), MagicMock(), MagicMock())

    @mock.patch('algosec.api_clients.firewall_analyzer.FirewallAnalyzerAPIClient._prepare_simulation_query_results')
    @mock.patch('algosec.api_clients.firewall_analyzer.FirewallAnalyzerAPIClient._get_summarized_query_result')
    def test_execute_traffic_simulation_query(
            self,
            mock_get_summarized_query,
            mock_prepare_results,
            mocker,
            analyzer_client
    ):
        # Mock the client and it's response content
        query_response_devices = [MagicMock()]
        query_response_url = [MagicMock()]
        simulation_query_response = MagicMock()
        simulation_query_response[0].QueryItem.Device = query_response_devices
        simulation_query_response[0].QueryHTMLPath = query_response_url
        mock_soap_client = MagicMock()
        mock_soap_client.service.query.return_value.QueryResult = simulation_query_response
        analyzer_client._session_id = MagicMock()

        # mock the simulation input
        source = MagicMock()
        dest = MagicMock()
        service = MagicMock()
        with mocker.patch.object(analyzer_client, "_client", mock_soap_client):
            simulation_result = analyzer_client.execute_traffic_simulation_query(source, dest, service)

            # assert return value
            assert simulation_result == {
                'result': mock_get_summarized_query.return_value,
                'query_url': query_response_url,
            }

            # assert internal simulation query call
            mock_soap_client.service.query.assert_called_once_with(
                SessionID=analyzer_client._session_id,
                QueryInput={
                    'Source': source,
                    'Destination': dest,
                    'Service': service
                }
            )

            # assert internal helper calls
            mock_prepare_results.assert_called_once_with(query_response_devices)
            mock_get_summarized_query.assert_called_once_with(
                simulation_query_response[0],
                mock_prepare_results.return_value
            )
