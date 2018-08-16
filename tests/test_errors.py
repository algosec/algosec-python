from algosec.errors import AlgoSecAPIError


class TestAlgoSecAPIError(object):
    def test_with_response_object(self):
        response, response_json = "some-respone-obj", "some-response-json"
        error = AlgoSecAPIError(
            response=response,
            response_json=response_json
        )

        assert error.response == response
        assert error.response_json == response_json

    def test_with_no_response_object(self):
        error = AlgoSecAPIError()
        assert error.response is None
        assert error.response_json is None
