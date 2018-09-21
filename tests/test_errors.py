from algosec.errors import AlgoSecAPIError


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
