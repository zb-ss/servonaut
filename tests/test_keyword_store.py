"""Tests for keyword store."""

import pytest

from servonaut.services.keyword_store import KeywordStore


class TestKeywordStore:

    @pytest.fixture
    def store(self, tmp_path):
        return KeywordStore(str(tmp_path / 'keywords.json'))

    @pytest.fixture
    def populated_store(self, store):
        store.save_results('i-abc123', [
            {
                'source': 'path:~/shared/',
                'content': 'file1.txt\nfile2.txt\nfile3.txt',
                'timestamp': '2024-01-01T00:00:00',
            },
            {
                'source': 'command:pm2 list',
                'content': 'myapp│running│pid:1234',
                'timestamp': '2024-01-01T00:00:00',
            },
        ])
        store.save_results('i-def456', [
            {
                'source': 'path:/var/log/',
                'content': 'access.log\nerror.log',
                'timestamp': '2024-01-01T00:00:00',
            },
        ])
        return store


class TestSaveAndGet(TestKeywordStore):

    def test_save_and_get(self, store):
        results = [{'source': 'test', 'content': 'data'}]
        store.save_results('i-123', results)
        assert store.get_results('i-123') == results

    def test_get_nonexistent(self, store):
        assert store.get_results('i-nonexistent') == []

    def test_overwrite(self, store):
        store.save_results('i-123', [{'content': 'old'}])
        store.save_results('i-123', [{'content': 'new'}])
        assert store.get_results('i-123') == [{'content': 'new'}]


class TestSearch(TestKeywordStore):

    def test_search_finds_match(self, populated_store):
        matches = populated_store.search('file1')
        assert len(matches) == 1
        assert matches[0]['server_id'] == 'i-abc123'

    def test_search_case_insensitive(self, populated_store):
        matches = populated_store.search('FILE1')
        assert len(matches) == 1

    def test_search_across_servers(self, populated_store):
        matches = populated_store.search('log')
        assert len(matches) >= 1
        server_ids = [m['server_id'] for m in matches]
        assert 'i-def456' in server_ids

    def test_search_no_match(self, populated_store):
        assert populated_store.search('nonexistent_xyz') == []

    def test_search_returns_matching_lines(self, populated_store):
        matches = populated_store.search('file1')
        assert 'file1' in matches[0]['content'].lower()

    def test_search_empty_store(self, store):
        assert store.search('anything') == []


class TestPrune(TestKeywordStore):

    def test_prune_removes_stale(self, populated_store):
        count = populated_store.prune_stale(['i-abc123'])
        assert count == 1
        assert populated_store.get_results('i-def456') == []
        assert populated_store.get_results('i-abc123') != []

    def test_prune_nothing_to_remove(self, populated_store):
        count = populated_store.prune_stale(['i-abc123', 'i-def456'])
        assert count == 0


class TestMisc(TestKeywordStore):

    def test_get_all_server_ids(self, populated_store):
        ids = populated_store.get_all_server_ids()
        assert set(ids) == {'i-abc123', 'i-def456'}

    def test_clear(self, populated_store):
        populated_store.clear()
        assert populated_store.get_all_server_ids() == []

    def test_corrupted_file(self, tmp_path):
        store_path = tmp_path / 'keywords.json'
        store_path.write_text('not json{{{')
        store = KeywordStore(str(store_path))
        assert store.get_results('anything') == []
