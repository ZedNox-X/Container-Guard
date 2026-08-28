from app.scanner import scan_image

def test_scanner_handles_invalid_image(monkeypatch):
    class P:
        returncode = 1
        stdout = '{"Results":[]}'
        stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **k: P())
    result = scan_image("example:latest")
    assert result["status"] == "completed"
    assert result["finding_count"] == 0
