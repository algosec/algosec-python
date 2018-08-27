"""Runnable example code to create an application flow in Business flow

"""
from algosec.api_clients.business_flow import BusinessFlowAPIClient
from algosec.models import RequestedFlow

if __name__ == "__main__":
    client = BusinessFlowAPIClient('local.algosec.com', 'admin', 'algosec', False)

    # First fetch the application revision id
    rev = client.get_application_revision_id_by_name('TEST')

    # define the new flow you would like to create on ABF
    requested_flow = RequestedFlow(
        'almog-flow-1',
        ['192.168.1.1'],
        ['192.168.1.1'],
        ['someUser'],
        [],
        ['tcp/50'],
        'comment'
    )

    # Create it :) Network Objects and services will be automatically created on the server.
    client.create_application_flow(rev, requested_flow)
