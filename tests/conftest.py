import os
from typing import Callable

import pytest
import vcr

from algosec.api_clients.fire_flow import FireFlowAPIClient

ALGOSEC_VERIFY_SSL = False
ALGOSEC_PASSWORD = 'algosec'
ALGOSEC_USERNAME = 'admin'
ALGOSEC_SERVER = 'testing.algosec.com'


tests_dir = os.path.dirname(os.path.realpath(__file__))
fixtures_dir = os.path.join(tests_dir, 'fixtures')


def cassette_filename_generator(test_function):  # type: (Callable) -> str
    filename = test_function.__name__
    test_prefix = 'test_'
    if filename.startswith(test_prefix):
        filename = filename[len(test_prefix):]
    return '{}.yaml'.format(filename)


my_vcr = vcr.VCR(
    cassette_library_dir=os.path.join(fixtures_dir, 'cassettes'),
    func_path_generator=cassette_filename_generator,
)


@pytest.fixture()
def fireflow_client():
    return FireFlowAPIClient(
        ALGOSEC_SERVER,
        ALGOSEC_USERNAME,
        ALGOSEC_PASSWORD,
        verify_ssl=ALGOSEC_VERIFY_SSL,
    )
