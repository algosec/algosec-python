from algosec.errors import AlgoSecAPIError, UnauthorizedUserException


class TestAlgoSecAPIError(object):
    def test_with_response_object(self, mocker):
        status_code, response_content, response = 12345, "some-response-content", mocker.MagicMock()
        error = AlgoSecAPIError(

            status_code=status_code,
            response_content=response_content,
            response=response,
        )

        assert error.status_code == status_code
        assert error.response_content == response_content
        assert error.response == response

    def test_with_no_response_object(self):
        error = AlgoSecAPIError()
        assert error.status_code is None
        assert error.response_content is None
        assert error.response is None

class TestUnauthorizedUserException(object):
    def test_with_msg_and_details(self):
        msg, details = "random msg", "extra details"
        error = UnauthorizedUserException(msg,details)
        assert error.message == msg
        assert error.extra_details == details


    def test_without_msg_and_details(self):
        error = UnauthorizedUserException()
        assert error.message == ""
        assert error.extra_details == ""
