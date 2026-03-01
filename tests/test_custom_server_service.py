"""Tests for CustomServerService."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from servonaut.config.schema import AppConfig, CustomServer
from servonaut.services.custom_server_service import CustomServerService


def _make_service(custom_servers=None):
    """Create a CustomServerService backed by a mock ConfigManager."""
    config = AppConfig(custom_servers=custom_servers or [])
    config_manager = MagicMock()
    config_manager.get.return_value = config
    config_manager.save.side_effect = lambda c: setattr(config_manager, '_saved', c)
    return CustomServerService(config_manager), config, config_manager


class TestAddServer:
    def test_add_new_server(self):
        service, config, cm = _make_service()
        server = CustomServer(name='vps1', host='10.0.0.1')
        service.add_server(server)
        cm.save.assert_called_once()
        assert config.custom_servers[0].name == 'vps1'

    def test_add_duplicate_raises(self):
        existing = CustomServer(name='vps1', host='10.0.0.1')
        service, config, cm = _make_service([existing])
        with pytest.raises(ValueError, match="already exists"):
            service.add_server(CustomServer(name='vps1', host='10.0.0.2'))

    def test_add_does_not_mutate_on_error(self):
        existing = CustomServer(name='vps1', host='10.0.0.1')
        service, config, _ = _make_service([existing])
        try:
            service.add_server(CustomServer(name='vps1', host='10.0.0.2'))
        except ValueError:
            pass
        assert len(config.custom_servers) == 1


class TestRemoveServer:
    def test_remove_existing(self):
        server = CustomServer(name='vps1', host='10.0.0.1')
        service, config, cm = _make_service([server])
        result = service.remove_server('vps1')
        assert result is True
        assert config.custom_servers == []
        cm.save.assert_called_once()

    def test_remove_nonexistent_returns_false(self):
        service, config, cm = _make_service()
        result = service.remove_server('nonexistent')
        assert result is False
        cm.save.assert_not_called()

    def test_remove_only_target(self):
        s1 = CustomServer(name='vps1', host='10.0.0.1')
        s2 = CustomServer(name='vps2', host='10.0.0.2')
        service, config, _ = _make_service([s1, s2])
        service.remove_server('vps1')
        assert len(config.custom_servers) == 1
        assert config.custom_servers[0].name == 'vps2'


class TestUpdateServer:
    def test_update_existing(self):
        server = CustomServer(name='vps1', host='10.0.0.1')
        service, config, cm = _make_service([server])
        updated = CustomServer(name='vps1', host='10.0.0.99', port=2222)
        result = service.update_server('vps1', updated)
        assert result is True
        assert config.custom_servers[0].host == '10.0.0.99'
        assert config.custom_servers[0].port == 2222
        cm.save.assert_called_once()

    def test_update_nonexistent_returns_false(self):
        service, config, cm = _make_service()
        result = service.update_server('ghost', CustomServer(name='ghost', host='1.2.3.4'))
        assert result is False
        cm.save.assert_not_called()


class TestListAndGet:
    def test_list_servers_empty(self):
        service, _, _ = _make_service()
        assert service.list_servers() == []

    def test_list_servers_returns_all(self):
        servers = [
            CustomServer(name='a', host='1.1.1.1'),
            CustomServer(name='b', host='2.2.2.2'),
        ]
        service, _, _ = _make_service(servers)
        result = service.list_servers()
        assert len(result) == 2

    def test_get_existing(self):
        server = CustomServer(name='vps1', host='10.0.0.1')
        service, _, _ = _make_service([server])
        found = service.get_server('vps1')
        assert found is not None
        assert found.host == '10.0.0.1'

    def test_get_nonexistent_returns_none(self):
        service, _, _ = _make_service()
        assert service.get_server('ghost') is None


class TestToInstanceDict:
    def test_basic_fields(self):
        server = CustomServer(
            name='my-vps',
            host='203.0.113.10',
            username='ubuntu',
            ssh_key='~/.ssh/vps.pem',
            port=2222,
            provider='DigitalOcean',
            group='web',
            tags={'env': 'prod'},
        )
        service, _, _ = _make_service()
        d = service.to_instance_dict(server)
        assert d['id'] == 'custom-my-vps'
        assert d['name'] == 'my-vps'
        assert d['type'] == 'custom'
        assert d['state'] == 'unknown'
        assert d['public_ip'] == '203.0.113.10'
        assert d['private_ip'] == '203.0.113.10'
        assert d['region'] == 'DigitalOcean'
        assert d['provider'] == 'DigitalOcean'
        assert d['group'] == 'web'
        assert d['port'] == 2222
        assert d['username'] == 'ubuntu'
        assert d['key_name'] == '~/.ssh/vps.pem'
        assert d['is_custom'] is True
        assert d['tags'] == {'env': 'prod'}

    def test_empty_provider_defaults_to_custom(self):
        server = CustomServer(name='x', host='1.2.3.4', provider='')
        service, _, _ = _make_service()
        d = service.to_instance_dict(server)
        assert d['provider'] == 'custom'
        assert d['region'] == 'custom'


class TestListAsInstances:
    def test_returns_instance_dicts(self):
        servers = [
            CustomServer(name='a', host='1.1.1.1'),
            CustomServer(name='b', host='2.2.2.2'),
        ]
        service, _, _ = _make_service(servers)
        result = service.list_as_instances()
        assert len(result) == 2
        assert all(d['is_custom'] for d in result)
        assert result[0]['id'] == 'custom-a'
        assert result[1]['id'] == 'custom-b'

    def test_empty_returns_empty_list(self):
        service, _, _ = _make_service()
        assert service.list_as_instances() == []
