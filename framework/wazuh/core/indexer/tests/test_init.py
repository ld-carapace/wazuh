from unittest import mock

import pytest
from opensearchpy import AsyncOpenSearch
from wazuh.core.exception import WazuhIndexerError
from wazuh.core.indexer import Indexer, create_indexer


@pytest.fixture
def indexer_instance() -> Indexer:
    return Indexer(host='test', user='user_test', password='password_test')


@pytest.fixture
def indexer_instance_with_mocked_client(indexer_instance) -> Indexer:
    indexer_instance._client = mock.AsyncMock()
    return indexer_instance


class TestIndexer:
    def test_indexer_init(self, indexer_instance):
        """Check the correct initalization of the `Indexer` class."""

        assert isinstance(indexer_instance._client, AsyncOpenSearch)

    async def test_initialize(self, indexer_instance_with_mocked_client):
        """Check the correct function of `initialize` method."""

        indexer_instance_with_mocked_client._client.ping.return_value = True
        await indexer_instance_with_mocked_client.initialize()

        indexer_instance_with_mocked_client._client.ping.assert_called_once()

    async def test_initialize_ko(self, indexer_instance_with_mocked_client):
        """Check the correct raise of `initialize` method."""

        indexer_instance_with_mocked_client._client.ping.return_value = False

        with pytest.raises(WazuhIndexerError, match='.*2200.*'):
            await indexer_instance_with_mocked_client.initialize()

    async def test_close(self, indexer_instance_with_mocked_client):
        """Check the correct function of `close` method."""

        await indexer_instance_with_mocked_client.close()

        indexer_instance_with_mocked_client._client.close.assert_called_once()


@mock.patch('wazuh.core.indexer.Indexer', autospec=True)
async def test_create_indexer(indexer_mock: mock.AsyncMock):
    """Check the correct function of `create_index`."""

    host = 'test'
    user = 'user_test'
    password = 'password_test'

    instance_mock = await create_indexer(host=host, user=user, password=password)
    indexer_mock.assert_called_once_with(host=host, user=user, password=password, port=9200)
    instance_mock.initialize.assert_called_once()


@pytest.mark.parametrize('retries', [2, 4])
@mock.patch('wazuh.core.indexer.Indexer', autospec=True)
async def test_create_indexer_ko(indexer_mock: mock.AsyncMock, retries: int):
    """Check the correct raise of `create_index`."""

    host = 'test'
    user = 'user_test'
    password = 'password_test'

    instance_mock = mock.AsyncMock()
    instance_mock.initialize.side_effect = WazuhIndexerError(2200)
    indexer_mock.return_value = instance_mock

    with mock.patch('wazuh.core.indexer.sleep') as sleep_mock:
        with pytest.raises(WazuhIndexerError, match='.*2200.*'):
            instance_mock = await create_indexer(host=host, user=user, password=password, retries=retries)

        assert instance_mock.initialize.call_count == retries + 1
        instance_mock.close.assert_called_once()
        assert sleep_mock.call_count == retries
