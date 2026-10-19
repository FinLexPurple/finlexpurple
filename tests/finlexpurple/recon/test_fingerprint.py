"""Checks for passive technology fingerprint markers."""

from finlexpurple.recon.fingerprint import identify


def test_identifies_server_header_and_framework_markers() -> None:
    result = identify(
        {"server": "Example/1.0"},
        '<div id="__next"></div><script src="/_next/static/app.js"></script>',
    )

    assert result.server == "Example/1.0"
    assert result.technologies == ("Next.js",)


def test_identifies_common_cms_markers() -> None:
    result = identify({}, '<meta name="generator" content="Drupal 10"> /wp-content/theme.css')

    assert result.technologies == ("Drupal", "WordPress")
