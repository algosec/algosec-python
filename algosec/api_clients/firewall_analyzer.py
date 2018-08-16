"""SOAP API client AlgoSec **FirewallAnalyzer**.


Clients require three arguments to be initiated (and total of four):

* AlgoSec server IP
* username
* password
* *verify_ssl* (optional)

Examples:
    Once initiated, the client is used by calling any of its public functions::

        from algosec.api_clients import FirewallAnalyzerAPIClient
        client = FirewallAnalyzerAPIClient(ip, username, password)
        query_result = client.run_traffic_simulation_query(
            source,
            dest,
            service
        )

    If the API call you were looking for is not yet implemented, you can send authenticated custom API call
    to the server using the client's ``session`` property.
    Please see specific API Client documentations to find out how.
"""
import logging
from collections import OrderedDict

from suds import WebFault

from algosec.api_clients.base import SoapAPIClient
from algosec.errors import AlgoSecLoginError, AlgoSecAPIError, UnrecognizedAllowanceState
from algosec.models import DeviceAllowanceState

logger = logging.getLogger(__name__)


class FirewallAnalyzerAPIClient(SoapAPIClient):
    """*FirewallAnalyzer* SOAP API client.

    Used by initiating and calling its public methods or by sending custom calls using the ``client`` property.
    Client implementation is strictly based on AlgoSec's official API guide.

    Example:

        Using the public methods to send an API call::

            from algosec.api_clients import FirewallAnalyzerAPIClient
            client = FirewallAnalyzerAPIClient(ip, username, password)
            query_result = client.run_traffic_simulation_query(source, dest, service)

    Args:
        server_ip (str): IP address of the AlgoSec server.
        user (str): Username used to log in to AlgoSec.
        password (str): The user's password, similar to the one used to log in to the UI.
        verify_ssl (bool): Turn on/off the connection's SSL certificate verification. Defaults to True.

    """

    @property
    def _wsdl_url_path(self):
        return "https://{}/AFA/php/ws.php?wsdl".format(self.server_ip)

    def _initiate_client(self):
        """Return a connected suds client and save the new session id to ``self._session_id``

        Raises:
            AlgoSecLoginError: If login using the username/password failed.

        Returns:
            suds.client.Client
        """
        client = self._get_soap_client(self._wsdl_url_path, location=self._wsdl_url_path.split('?')[0])
        try:
            self._session_id = client.service.connect(
                UserName=self.user,
                Password=self.password,
                Domain=''
            )

        except WebFault:
            raise AlgoSecLoginError
        return client

    def _calc_aggregated_query_result(self, query_results):
        """Return aggregated calculated traffic query result.

        Since we had the "QueryResult" missing from the API before AlgoSec version 2017.02 we check here if it is
        part of the result. If not, we try and calculate the traffic query result based on the results we got
        for the various devices under the query.

        Returns:
            algosec.models.DeviceAllowanceState: Aggregated traffic simulation result.
        """
        # Understanding the value of the total result, is the traffic blocked or allowed or partially blocked?
        if query_results[DeviceAllowanceState.PARTIALLY_BLOCKED]:
            aggregated_result = DeviceAllowanceState.PARTIALLY_BLOCKED
        elif query_results[DeviceAllowanceState.BLOCKED]:
            if query_results[DeviceAllowanceState.ALLOWED]:
                aggregated_result = DeviceAllowanceState.PARTIALLY_BLOCKED
            else:
                aggregated_result = DeviceAllowanceState.BLOCKED
        else:
            aggregated_result = DeviceAllowanceState.ALLOWED
        return aggregated_result

    def run_traffic_simulation_query(self, source, destination, service):
        """Run a traffic simulation query given it's traffic lines

        Args:
            source (str): Source of the simulated traffic. (e.g. IPs, subnet or an object name)
            destination (str): Destination of the simulated traffic. (e.g. IPs, subnet or an object name)
            service (str): Service of the simulated traffic (e.g: tcp/200, http)

        Raises:
            :class:`~algosec.errors.AlgoSecAPIError`: If any error occurred while executing the traffic
                simulation query.

        Returns:
            algosec.models.DeviceAllowanceState: Traffic simulation query result.
        """
        query_params = {'Source': source, 'Destination': destination, 'Service': service}
        try:
            query_result = self.client.service.query(
                SessionID=self._session_id,
                QueryInput=query_params
            ).QueryResult
        except WebFault:
            raise AlgoSecAPIError

        devices = []
        if query_result is not None:
            query_result = query_result[0]
            if query_result.QueryItem:
                # In case there is only one object in the result
                query_item = query_result.QueryItem
                devices = query_item.Device if type(query_item.Device) is list else [query_item.Device]

        # Making a dict from the result type to a list of devices. Keep it always ordered by the result type
        query_results = OrderedDict([
            (DeviceAllowanceState.BLOCKED, []),
            (DeviceAllowanceState.PARTIALLY_BLOCKED, []),
            (DeviceAllowanceState.ALLOWED, [])
        ])

        # Group the devices by groups according to their device result
        for device in devices:
            try:
                allowance_state = DeviceAllowanceState.from_string(device.IsAllowed)
            except UnrecognizedAllowanceState:
                logger.warning(
                    "Unknown device state found. Device: {}, state: {}".format(
                        device,
                        device.IsAllowed,
                    )
                )
            else:
                query_results[allowance_state].append(device)

        # Now calculate to the traffic query result.
        # Since we had the "QueryResult" missing from the API before AlgoSec version 2017.02 we check here if it is
        # part of the result. If not, we try and calculate the traffic query result based on the results we got
        # for the various devices under the query
        if hasattr(query_result, "QueryResult") and query_result.QueryResult:
            aggregated_result = DeviceAllowanceState.from_string(query_result.QueryResult)
        else:
            aggregated_result = self._calc_aggregated_query_result(query_results)

        return aggregated_result