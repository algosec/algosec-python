from requests.adapters import HTTPAdapter


class AlgosecServersHTTPAdapter(HTTPAdapter):
    """
    This adapter is used to customize http requests sessions we have with Algosec's servers

    Setting the default connect and read timeout. This timeout will prevent the bot from being stuck when the server
    is not responsive
    """
    ALGOSEC_SERVER_CONNECT_TIMEOUT = 5
    ALGOSEC_SERVER_READ_TIMEOUT = None

    def __init__(self, *args, **kwargs):
        super(AlgosecServersHTTPAdapter, self).__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs['timeout'] = (self.ALGOSEC_SERVER_CONNECT_TIMEOUT, self.ALGOSEC_SERVER_READ_TIMEOUT)
        return super(AlgosecServersHTTPAdapter, self).send(*args, **kwargs)


def mount_algosec_adapter_on_session(session):
    session.mount('https://', AlgosecServersHTTPAdapter())
    session.mount('http://', AlgosecServersHTTPAdapter())
