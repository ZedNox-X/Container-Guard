from app.container_audit import audit_container

class Fake:
    attrs = {
        "HostConfig": {
            "Privileged": True,
            "PidMode": "host",
            "NetworkMode": "host",
            "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
            "ReadonlyRootfs": False,
            "CpuQuota": 0,
            "NanoCpus": 0,
            "Memory": 0,
            "CapAdd": ["SYS_ADMIN"],
        },
        "Config": {"User": "root"},
        "NetworkSettings": {"Ports": {}},
    }

def test_dangerous_configuration_detection():
    rules = {x["rule"] for x in audit_container(Fake())}
    assert "CG-PRIVILEGED" in rules
    assert "CG-DOCKER-SOCKET" in rules
    assert "CG-ROOT" in rules
