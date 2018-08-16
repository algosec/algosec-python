"""Runnable example code to fetch the application flows from ABF"""

from algosec.api_clients.business_flow import BusinessFlowAPIClient

if __name__ == "__main__":
    client = BusinessFlowAPIClient('local.algosec.com', 'admin', 'algosec', False)

    # First fetch the application revision id
    rev = client.get_application_revision_id_by_name('TEST')

    # Then fetch its flows
    flows = client.get_application_flows(rev)
