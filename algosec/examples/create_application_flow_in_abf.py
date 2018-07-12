"""Runnable example code to create an application flow in Business flow

"""
from algosec.api_client import BusinessFlowAPIClient
from algosec.models import RequestedFlow

if __name__ == "__main__":
    client = BusinessFlowAPIClient('local.algosec.com', 'admin', 'algosec', False)

    # First
    rev = client.get_application_revision_id_by_name('TEST')

    requested_flow = RequestedFlow(
        'almog-flow-1',
        ['192.168.1.1'],
        ['192.168.1.1'],
        ['someUser'],
        [],
        ['tcp/50'],
        'comment'
    )

    client.create_application_flow(rev, requested_flow)
