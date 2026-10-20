"""Phase 14: original exposed-socket / container-escape static checks."""

from __future__ import annotations

from finlexpurple.container import escape_checks
from finlexpurple.detectors.schema import Severity


def test_dockerfile_running_as_root_is_flagged() -> None:
    findings = escape_checks.check_dockerfile("FROM debian:10\nRUN apt-get update\n")
    assert len(findings) == 1
    assert findings[0].vulnerability_class == "container_runs_as_root"


def test_dockerfile_with_nonroot_user_is_clean() -> None:
    assert escape_checks.check_dockerfile("FROM debian\nUSER app\n") == []


def test_runtime_config_privileged_and_socket_and_caps() -> None:
    config = {
        "HostConfig": {
            "Privileged": True,
            "Binds": ["/var/run/docker.sock:/var/run/docker.sock", "/etc:/host-etc"],
            "CapAdd": ["SYS_ADMIN", "NET_RAW"],
            "PidMode": "host",
            "NetworkMode": "bridge",
        }
    }
    classes = {f.vulnerability_class for f in escape_checks.check_runtime_config(config)}
    assert "privileged_container" in classes
    assert "exposed_docker_socket" in classes
    assert "sensitive_host_mount" in classes  # /etc
    assert "dangerous_capability" in classes  # SYS_ADMIN (NET_RAW is not dangerous-listed)
    assert "host_namespace_sharing" in classes  # PidMode=host


def test_exposed_socket_is_critical() -> None:
    config = {"HostConfig": {"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}}
    sock = [f for f in escape_checks.check_runtime_config(config)
            if f.vulnerability_class == "exposed_docker_socket"]
    assert sock and sock[0].severity is Severity.CRITICAL


def test_compose_services_are_checked() -> None:
    data = {
        "services": {
            "web": {"privileged": True, "volumes": ["/var/run/docker.sock:/var/run/docker.sock"]},
            "safe": {"image": "nginx"},
        }
    }
    findings = escape_checks.check_compose(data)
    classes = {f.vulnerability_class for f in findings}
    assert "privileged_container" in classes
    assert "exposed_docker_socket" in classes
    assert all("#web" in f.url for f in findings)


def test_clean_runtime_config_yields_nothing() -> None:
    assert escape_checks.check_runtime_config({"HostConfig": {"Privileged": False}}) == []
