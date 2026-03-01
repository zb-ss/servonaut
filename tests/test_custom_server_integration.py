"""Integration tests for custom server pipeline and match_utils."""

from __future__ import annotations

import pytest

from servonaut.config.schema import CustomServer
from servonaut.utils.match_utils import matches_conditions


# ---------------------------------------------------------------------------
# Instance pipeline: custom server instance dicts look correct
# ---------------------------------------------------------------------------

def _make_instance_dict(name='vps1', host='10.0.0.1', provider='DigitalOcean',
                        group='web', port=22, tags=None):
    return {
        'id': f'custom-{name}',
        'name': name,
        'type': 'custom',
        'state': 'unknown',
        'public_ip': host,
        'private_ip': host,
        'region': provider or 'custom',
        'key_name': '',
        'provider': provider or 'custom',
        'group': group,
        'tags': tags or {},
        'port': port,
        'username': 'root',
        'is_custom': True,
    }


class TestCustomServerInstancePipeline:
    def test_custom_instance_has_is_custom_flag(self):
        inst = _make_instance_dict()
        assert inst['is_custom'] is True

    def test_aws_instance_has_no_is_custom_flag(self):
        aws = {
            'id': 'i-abc123', 'name': 'web', 'type': 't3.medium',
            'state': 'running', 'public_ip': '1.2.3.4', 'private_ip': '10.0.0.1',
            'region': 'us-east-1', 'key_name': 'prod-key',
        }
        assert not aws.get('is_custom')

    def test_custom_state_is_unknown(self):
        inst = _make_instance_dict()
        assert inst['state'] == 'unknown'

    def test_custom_type_is_custom(self):
        inst = _make_instance_dict()
        assert inst['type'] == 'custom'

    def test_custom_id_prefix(self):
        inst = _make_instance_dict(name='my-vps')
        assert inst['id'] == 'custom-my-vps'

    def test_empty_provider_defaults_to_custom(self):
        inst = _make_instance_dict(provider='')
        assert inst['provider'] == 'custom'
        assert inst['region'] == 'custom'


# ---------------------------------------------------------------------------
# match_utils: provider, group, tag conditions
# ---------------------------------------------------------------------------

class TestMatchUtilsProvider:
    def test_provider_exact_match(self):
        inst = _make_instance_dict(provider='DigitalOcean')
        assert matches_conditions(inst, {'provider': 'DigitalOcean'})

    def test_provider_no_match(self):
        inst = _make_instance_dict(provider='Hetzner')
        assert not matches_conditions(inst, {'provider': 'DigitalOcean'})

    def test_provider_aws_default(self):
        aws = {
            'id': 'i-abc', 'name': 'web', 'type': 't3.micro',
            'state': 'running', 'public_ip': '1.2.3.4', 'private_ip': '10.0.0.1',
            'region': 'us-east-1', 'key_name': 'key',
        }
        assert not matches_conditions(aws, {'provider': 'DigitalOcean'})
        assert matches_conditions(aws, {'provider': 'AWS'})


class TestMatchUtilsGroup:
    def test_group_exact_match(self):
        inst = _make_instance_dict(group='web')
        assert matches_conditions(inst, {'group': 'web'})

    def test_group_no_match(self):
        inst = _make_instance_dict(group='database')
        assert not matches_conditions(inst, {'group': 'web'})

    def test_group_empty_string(self):
        inst = _make_instance_dict(group='')
        assert matches_conditions(inst, {'group': ''})
        assert not matches_conditions(inst, {'group': 'web'})


class TestMatchUtilsTags:
    def test_tag_exact_match(self):
        inst = _make_instance_dict(tags={'env': 'prod', 'role': 'web'})
        assert matches_conditions(inst, {'tag:env': 'prod'})

    def test_tag_no_match(self):
        inst = _make_instance_dict(tags={'env': 'staging'})
        assert not matches_conditions(inst, {'tag:env': 'prod'})

    def test_tag_missing_key(self):
        inst = _make_instance_dict(tags={})
        assert not matches_conditions(inst, {'tag:env': 'prod'})

    def test_multiple_tags_and_logic(self):
        inst = _make_instance_dict(tags={'env': 'prod', 'role': 'db'})
        assert matches_conditions(inst, {'tag:env': 'prod', 'tag:role': 'db'})
        assert not matches_conditions(inst, {'tag:env': 'prod', 'tag:role': 'web'})

    def test_tag_with_no_tags_field(self):
        inst = {'id': 'x', 'name': 'x', 'type': 'custom', 'state': 'unknown',
                'public_ip': '1.2.3.4', 'private_ip': '1.2.3.4', 'region': 'custom'}
        assert not matches_conditions(inst, {'tag:env': 'prod'})


class TestMatchUtilsCombined:
    def test_provider_and_group(self):
        inst = _make_instance_dict(provider='Hetzner', group='database')
        assert matches_conditions(inst, {'provider': 'Hetzner', 'group': 'database'})
        assert not matches_conditions(inst, {'provider': 'Hetzner', 'group': 'web'})

    def test_name_contains_and_provider(self):
        inst = _make_instance_dict(name='prod-db', provider='DigitalOcean')
        assert matches_conditions(inst, {'name_contains': 'prod', 'provider': 'DigitalOcean'})
        assert not matches_conditions(inst, {'name_contains': 'prod', 'provider': 'AWS'})
