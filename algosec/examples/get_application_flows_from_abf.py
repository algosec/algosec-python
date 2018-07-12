"""Runnable example code to fetch the application flows from ABF"""


from algosec.api_client import BusinessFlowAPIClient

if __name__ == "__main__":
    client = BusinessFlowAPIClient('local.algosec.com', 'admin', 'algosec', False)

    # First
    rev = client.get_application_revision_id_by_name('TEST')
    flows = client.get_application_flows(rev)
