"""Endpoint catalog normalization and query-value minimization tests."""

from finlexpurple.recon.endpoint_catalog import EndpointCatalog


def test_catalog_deduplicates_paths_and_merges_parameter_names_only() -> None:
    catalog = EndpointCatalog()
    catalog.add("get", "https://EXAMPLE.com/search?q=first&token=secret", content_type="text/html")
    catalog.add("GET", "https://example.com/search?q=second&page=2", parameters={"filter"})

    assert len(catalog) == 1
    endpoint = catalog.endpoints[0]
    assert endpoint.method == "GET"
    assert endpoint.url == "https://example.com/search"
    assert endpoint.parameters == ("filter", "page", "q", "token")
    assert endpoint.content_type == "text/html"
    assert "first" not in repr(endpoint)
    assert "secret" not in repr(endpoint)
