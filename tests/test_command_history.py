"""Tests for command history service."""

import pytest

from servonaut.services.command_history import CommandHistoryService, MAX_INSTANCE_HISTORY, MAX_GLOBAL_HISTORY


class TestCommandHistory:

    @pytest.fixture
    def service(self, tmp_path):
        return CommandHistoryService(str(tmp_path / 'history.json'))


class TestAddToHistory(TestCommandHistory):

    def test_add_and_get_instance(self, service):
        service.add_to_history('i-abc123', 'ls -la')
        assert service.get_instance_history('i-abc123') == ['ls -la']

    def test_add_multiple(self, service):
        service.add_to_history('i-abc123', 'ls')
        service.add_to_history('i-abc123', 'pwd')
        assert service.get_instance_history('i-abc123') == ['ls', 'pwd']

    def test_dedup_consecutive(self, service):
        service.add_to_history('i-abc123', 'ls')
        service.add_to_history('i-abc123', 'ls')
        assert service.get_instance_history('i-abc123') == ['ls']

    def test_allow_non_consecutive_dup(self, service):
        service.add_to_history('i-abc123', 'ls')
        service.add_to_history('i-abc123', 'pwd')
        service.add_to_history('i-abc123', 'ls')
        assert service.get_instance_history('i-abc123') == ['ls', 'pwd', 'ls']

    def test_global_history_populated(self, service):
        service.add_to_history('i-abc123', 'ls')
        service.add_to_history('i-def456', 'pwd')
        assert service.get_global_history() == ['ls', 'pwd']

    def test_separate_instance_histories(self, service):
        service.add_to_history('i-abc123', 'ls')
        service.add_to_history('i-def456', 'pwd')
        assert service.get_instance_history('i-abc123') == ['ls']
        assert service.get_instance_history('i-def456') == ['pwd']

    def test_empty_instance(self, service):
        assert service.get_instance_history('i-nonexistent') == []

    def test_empty_global(self, service):
        assert service.get_global_history() == []

    def test_instance_history_trimmed(self, service):
        for i in range(MAX_INSTANCE_HISTORY + 20):
            service.add_to_history('i-abc123', f'cmd{i}')
        history = service.get_instance_history('i-abc123')
        assert len(history) == MAX_INSTANCE_HISTORY
        assert history[-1] == f'cmd{MAX_INSTANCE_HISTORY + 19}'

    def test_global_history_trimmed(self, service):
        for i in range(MAX_GLOBAL_HISTORY + 20):
            service.add_to_history('i-abc123', f'cmd{i}')
        history = service.get_global_history()
        assert len(history) == MAX_GLOBAL_HISTORY


class TestSavedCommands(TestCommandHistory):

    def test_save_and_get(self, service):
        service.save_command('Disk Usage', 'df -h')
        saved = service.get_saved_commands()
        assert len(saved) == 1
        assert saved[0] == {'name': 'Disk Usage', 'command': 'df -h'}

    def test_save_multiple(self, service):
        service.save_command('Disk', 'df -h')
        service.save_command('Memory', 'free -m')
        saved = service.get_saved_commands()
        assert len(saved) == 2

    def test_overwrite_same_name(self, service):
        service.save_command('Status', 'pm2 list')
        service.save_command('Status', 'pm2 status')
        saved = service.get_saved_commands()
        assert len(saved) == 1
        assert saved[0]['command'] == 'pm2 status'

    def test_delete_saved(self, service):
        service.save_command('Disk', 'df -h')
        service.save_command('Memory', 'free -m')
        assert service.delete_saved_command('Disk') is True
        saved = service.get_saved_commands()
        assert len(saved) == 1
        assert saved[0]['name'] == 'Memory'

    def test_delete_nonexistent(self, service):
        assert service.delete_saved_command('nope') is False

    def test_empty_saved(self, service):
        assert service.get_saved_commands() == []


class TestPersistence(TestCommandHistory):

    def test_survives_reload(self, tmp_path):
        path = str(tmp_path / 'history.json')
        svc1 = CommandHistoryService(path)
        svc1.add_to_history('i-abc123', 'ls')
        svc1.save_command('Test', 'echo hello')

        svc2 = CommandHistoryService(path)
        assert svc2.get_instance_history('i-abc123') == ['ls']
        assert svc2.get_saved_commands() == [{'name': 'Test', 'command': 'echo hello'}]

    def test_corrupted_file(self, tmp_path):
        path = tmp_path / 'history.json'
        path.write_text('not json{{{')
        service = CommandHistoryService(str(path))
        assert service.get_instance_history('anything') == []
        assert service.get_saved_commands() == []
