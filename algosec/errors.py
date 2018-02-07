

class AlgosecAPIError(Exception):
    def __init__(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop('response', None)
        self.response = response
        response_json = kwargs.pop('response_json', None)
        self.response_json = response_json
        super(AlgosecAPIError, self).__init__(*args, **kwargs)


class AlgosecLoginError(AlgosecAPIError):
    pass


class AlgosecBusinessFlowAPIError(AlgosecAPIError):
    pass


class UnrecognizedAllowanceState(AlgosecAPIError):
    pass


class UnrecognizedServiceString(Exception):
    pass


class EmptyFlowSearch(AlgosecBusinessFlowAPIError):
    pass
