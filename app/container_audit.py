import docker

def _finding(rule, severity, message):
    return {"rule": rule, "severity": severity, "message": message}

def audit_container(container) -> list[dict]:
    attrs = container.attrs
    host = attrs.get("HostConfig", {})
    cfg = attrs.get("Config", {})
    findings = []

    if host.get("Privileged"):
        findings.append(_finding("CG-PRIVILEGED", "CRITICAL", "Privileged mode is enabled"))
    if host.get("PidMode") == "host":
        findings.append(_finding("CG-HOST-PID", "HIGH", "Host PID namespace is enabled"))
    if host.get("NetworkMode") == "host":
        findings.append(_finding("CG-HOST-NET", "HIGH", "Host network namespace is enabled"))

    binds = host.get("Binds") or []
    for bind in binds:
        if "/var/run/docker.sock" in bind:
            findings.append(_finding("CG-DOCKER-SOCKET", "CRITICAL", "Docker socket is mounted"))
            break

    user = cfg.get("User", "")
    if not user or user in ("0", "root"):
        findings.append(_finding("CG-ROOT", "HIGH", "Container runs as root or does not specify a user"))

    if host.get("ReadonlyRootfs") is False:
        findings.append(_finding("CG-WRITABLE-ROOTFS", "MEDIUM", "Root filesystem is writable"))

    if host.get("CpuQuota", 0) == 0 and host.get("NanoCpus", 0) == 0:
        findings.append(_finding("CG-NO-CPU-LIMIT", "MEDIUM", "No CPU limit is configured"))
    if host.get("Memory", 0) == 0:
        findings.append(_finding("CG-NO-MEMORY-LIMIT", "MEDIUM", "No memory limit is configured"))

    caps = host.get("CapAdd") or []
    dangerous = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}
    for cap in caps:
        if cap in dangerous:
            findings.append(_finding("CG-DANGEROUS-CAP", "HIGH", f"Dangerous Linux capability added: {cap}"))

    ports = attrs.get("NetworkSettings", {}).get("Ports") or {}
    exposed = [p for p, bindings in ports.items() if bindings]
    if exposed:
        findings.append(_finding("CG-PUBLISHED-PORT", "LOW", f"Published ports detected: {', '.join(exposed)}"))

    return findings

def audit_running_containers():
    client = docker.from_env()
    results = []
    for c in client.containers.list():
        findings = audit_container(c)
        results.append({
            "container_id": c.short_id,
            "name": c.name,
            "image": c.image.tags[0] if c.image.tags else c.image.short_id,
            "findings": findings,
            "finding_count": len(findings),
        })
    return results
