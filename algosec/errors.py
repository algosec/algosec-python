# TODO: Explain what this file is about, that it is probably not to be used by developers directly.
# TODO: Are those errors relevant to SOAP?


class AlgoSecAPIError(Exception):
    def __init__(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop('response', None)
        self.response = response
        response_json = kwargs.pop('response_json', None)
        self.response_json = response_json
        super(AlgoSecAPIError, self).__init__(*args, **kwargs)


class AlgoSecLoginError(AlgoSecAPIError):
    pass


class AlgoSecBusinessFlowAPIError(AlgoSecAPIError):
    pass


class UnrecognizedAllowanceState(AlgoSecAPIError):
    pass


class UnrecognizedServiceString(Exception):
    pass


class EmptyFlowSearch(AlgoSecBusinessFlowAPIError):
    pass
