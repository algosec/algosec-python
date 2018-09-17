"""Exception and error classes used and thrown by the API clients.

Developers will might use the exceptions and errors in their code while working with the API clients.
Each of public methods of the API client document which errors may raise by their use.
Then, developers can ``try``-``except`` in their code using the AlgoSec defined errors
for better clarity of their code.
"""


class AlgoSecAPIError(Exception):
    """Root parent AlgoSec API error subclassed by all other API errors.

    Attributes:
        response: The response object that caused the error.
            If it was not passed to the constructor, will be None.
        response_content (dict|str): The content of the response that caused the error.
            If it is a JSON, a JSON will be stored and not the raw content. Will be None if is not passed.
        status_code (int): The status code of the response of the failed API call. (Optional)

    Keyword Args:
        response: The response object that caused the error. (Optional)
        response_content (dict): The content of the response of the failed API call. (Optional)
        status_code (int): The status code of the response of the failed API call. (Optional)
    """
    def __init__(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        self.response = kwargs.pop('response', None)
        self.status_code = kwargs.pop('status_code', None)
        self.response_content = kwargs.pop('response_content', None)
        super(AlgoSecAPIError, self).__init__(*args, **kwargs)


class AlgoSecLoginError(AlgoSecAPIError):
    """Raised when login to AlgoSec API fails"""
    pass


class AlgoSecBusinessFlowAPIError(AlgoSecAPIError):
    """Raised for any BusinessFlow related API errors.

    This error is also subclassed by other more specific BusinessFlow related errors.
    """
    pass


class EmptyFlowSearch(AlgoSecBusinessFlowAPIError):
    """Raised when flow search by exact name fails."""
    pass


class UnrecognizedAllowanceState(AlgoSecAPIError):
    """Raised when parsing unknown device allowance state strings."""
    pass


class UnrecognizedServiceString(Exception):
    """Raised when parsing invalid network service definition strings"""
    pass
