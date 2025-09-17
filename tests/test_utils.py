import os
import json
from port_scanner.utils import save_json, save_csv, TOP_TCP_PORTS

def test_save_and_read(tmp_path):
    data = [
        {"port": 22, "status": "open", "service": "ssh", "banner": "SSH-2.0-Test"},
        {"port": 80, "status": "closed", "service": None, "banner": None}
    ]
    json_file = tmp_path / "out.json"
    csv_file = tmp_path / "out.csv"
    save_json(data, str(json_file))
    save_csv(data, str(csv_file))

    assert json_file.exists()
    assert csv_file.exists()

    # spot check json content
    content = json.loads(json_file.read_text(encoding="utf-8"))
    assert isinstance(content, list)
    assert content[0]["port"] == 22

    # csv existence is enough for this simple test
    assert csv_file.stat().st_size > 0
