"""Unit tests for parameter parser and payload injector."""

from injexion.core.models import ParameterType
from injexion.engine.parameter import ParameterParser


def test_extract_targets_from_url_with_query_params():
    url = "http://example.com/search.php?q=security&page=2&sort=asc"
    targets = ParameterParser.extract_targets_from_url(url)
    assert len(targets) == 3
    names = {t.parameter for t in targets}
    assert names == {"q", "page", "sort"}
    for t in targets:
        assert t.param_type == ParameterType.QUERY
        assert t.url == "http://example.com/search.php"


def test_extract_targets_from_url_without_query_params():
    url = "http://example.com/products/123"
    targets = ParameterParser.extract_targets_from_url(url)
    assert len(targets) == 1
    assert targets[0].param_type == ParameterType.PATH
    assert targets[0].parameter == "__path__"


def test_build_mutated_request_replace_mode():
    url = "http://example.com/item.php?id=10&cat=electronics"
    targets = ParameterParser.extract_targets_from_url(url)
    target_id = next(t for t in targets if t.parameter == "id")

    mutated = ParameterParser.build_mutated_request(target_id, "' OR 1=1--", url, mode="replace")
    assert mutated["params"]["id"] == "' OR 1=1--"
    assert mutated["params"]["cat"] == "electronics"


def test_build_mutated_request_append_mode():
    url = "http://example.com/item.php?id=10&cat=electronics"
    targets = ParameterParser.extract_targets_from_url(url)
    target_id = next(t for t in targets if t.parameter == "id")

    mutated = ParameterParser.build_mutated_request(target_id, "'", url, mode="append")
    assert mutated["params"]["id"] == "10'"
    assert mutated["params"]["cat"] == "electronics"

