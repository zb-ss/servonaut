"""Tests for instance matching utilities."""

from servonaut.utils.match_utils import matches_conditions


class TestMatchesConditions:

    def test_empty_conditions_match_everything(self, sample_instances):
        for inst in sample_instances:
            assert matches_conditions(inst, {}) is True

    def test_name_contains_match(self):
        instance = {'name': 'web-server-prod', 'id': 'i-123'}
        assert matches_conditions(instance, {'name_contains': 'web'}) is True
        assert matches_conditions(instance, {'name_contains': 'WEB'}) is True
        assert matches_conditions(instance, {'name_contains': 'api'}) is False

    def test_name_regex_match(self):
        instance = {'name': 'web-server-prod-01', 'id': 'i-123'}
        assert matches_conditions(instance, {'name_regex': r'web-.*-\d+'}) is True
        assert matches_conditions(instance, {'name_regex': r'^api'}) is False

    def test_id_exact_match(self):
        instance = {'name': 'test', 'id': 'i-abc123'}
        assert matches_conditions(instance, {'id': 'i-abc123'}) is True
        assert matches_conditions(instance, {'id': 'i-xyz789'}) is False

    def test_region_match(self):
        instance = {'name': 'test', 'id': 'i-123', 'region': 'us-east-1'}
        assert matches_conditions(instance, {'region': 'us-east-1'}) is True
        assert matches_conditions(instance, {'region': 'eu-west-1'}) is False

    def test_type_contains_match(self):
        instance = {'name': 'test', 'id': 'i-123', 'type': 't3.medium'}
        assert matches_conditions(instance, {'type_contains': 't3'}) is True
        assert matches_conditions(instance, {'type_contains': 'T3'}) is True
        assert matches_conditions(instance, {'type_contains': 'm5'}) is False

    def test_has_public_ip_true(self):
        instance = {'name': 'test', 'id': 'i-123', 'public_ip': '1.2.3.4'}
        assert matches_conditions(instance, {'has_public_ip': 'true'}) is True
        assert matches_conditions(instance, {'has_public_ip': 'false'}) is False

    def test_has_public_ip_false(self):
        instance = {'name': 'test', 'id': 'i-123', 'public_ip': None}
        assert matches_conditions(instance, {'has_public_ip': 'false'}) is True
        assert matches_conditions(instance, {'has_public_ip': 'true'}) is False

    def test_and_logic_all_must_match(self):
        instance = {
            'name': 'web-prod',
            'id': 'i-123',
            'region': 'us-east-1',
            'type': 't3.medium',
            'public_ip': '1.2.3.4',
        }
        assert matches_conditions(instance, {
            'name_contains': 'web',
            'region': 'us-east-1',
            'type_contains': 't3',
        }) is True
        assert matches_conditions(instance, {
            'name_contains': 'web',
            'region': 'eu-west-1',
        }) is False

    def test_unknown_condition_ignored(self):
        instance = {'name': 'test', 'id': 'i-123'}
        assert matches_conditions(instance, {'unknown_key': 'value'}) is True

    def test_missing_instance_fields(self):
        instance = {'id': 'i-123'}
        assert matches_conditions(instance, {'name_contains': 'anything'}) is False
