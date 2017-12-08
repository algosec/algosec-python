

class AlgosecAPIError(Exception):
    pass


class AlgosecLoginError(AlgosecAPIError):
    pass


class AlgosecBusinessFlowAPIError(AlgosecAPIError):
    pass


class UnrecognizedAllowanceState(AlgosecAPIError):
    pass
