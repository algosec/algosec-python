"""Runnable example code to create a change request if AlgoSec FireFlow"""


from algosec.api_clients.fire_flow import FireFlowAPIClient
from algosec.models import ChangeRequestTrafficLine, ChangeRequestAction

if __name__ == "__main__":
    client = FireFlowAPIClient('local.algosec.com', 'admin', 'algosec', False)

    # Define the traffic lines that will be in the change request
    traffic_lines = [
        ChangeRequestTrafficLine(
            ChangeRequestAction.ALLOW,
            # IP, IP subnets and object names that are defined on AFF
            ['192.168.16.1', '192.168.12.1/16'],
            ['10.0.0.1'],
            ['TCP/50', 'ssh']
        ),
        ChangeRequestTrafficLine(
            ChangeRequestAction.DROP,
            ['192.168.15.1'],
            ['10.0.0.1'],
            ['http']
        )
    ]

    change_request_url = client.create_change_request(
        "Example code Change Request",
        "almogco",
        "almogco@example.com",
        traffic_lines,
        description="This change request was created by the live example code of AlgoSec's python SDK"
        # You can also specify the template here
        # template="Something"
    )
    print("New Change Request created! Check it out here: {}".format(change_request_url))
