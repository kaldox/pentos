"""Regressionstest für die ProjectDiscovery-Parser (httpx/naabu/dnsx, JSONL).

Alle drei Tools geben natives JSON aus (ein Objekt pro Zeile, "-json"-Flag).
Schema verifiziert gegen die Go-Structs der jeweiligen Repos:
- httpx: runner/types.go (u.a. url, status_code, title, webserver, tech)
- naabu: pkg/result (ip, port, host, protocol) -- README-Beispiel:
  {"ip":"104.16.99.52","port":443}
- dnsx:  libs/dnsx (host, a, aaaa, cname, ...)

Anders als nikto/nuclei/testssl sind das reine Recon-/Enumeration-Tools (kein
Schwachstellen-Scan) -- Treffer landen wie bei subfinder als strukturierte
Notiz, nicht als Findings.
"""


def test_parse_jsonl_extracts_objects_per_line():
    from pentos.runners.parsers import _parse_jsonl
    text = '{"a": 1}\n{"b": 2}\n\n   \n{"c": 3}\n'
    items = _parse_jsonl(text)
    assert items == [{"a": 1}, {"b": 2}, {"c": 3}]


def test_parse_jsonl_skips_garbage_lines():
    from pentos.runners.parsers import _parse_jsonl
    text = 'not json\n{"ok": true}\n[1,2,3]\n"just a string"\n'
    items = _parse_jsonl(text)
    # [1,2,3] und "just a string" sind gültiges JSON, aber keine Objekte -> raus
    assert items == [{"ok": True}]


def test_parse_jsonl_handles_empty_input():
    from pentos.runners.parsers import _parse_jsonl
    assert _parse_jsonl("") == []
    assert _parse_jsonl("\n\n\n") == []


HTTPX_SAMPLE = (
    '{"timestamp":"2026-08-16T10:00:00Z","url":"https://10.10.10.8",'
    '"input":"10.10.10.8","host":"10.10.10.8","status_code":200,'
    '"title":"Welcome","webserver":"nginx","tech":["nginx","PHP:8.1"],'
    '"content_length":512}\n'
    '{"timestamp":"2026-08-16T10:00:01Z","url":"https://10.10.10.8/admin",'
    '"status_code":401,"title":"","webserver":"nginx","content_length":0}\n'
)


def test_parse_httpx_formats_url_status_title_server_tech():
    from pentos.runners.parsers import _parse_httpx
    lines = _parse_httpx(HTTPX_SAMPLE)
    assert len(lines) == 2
    assert "https://10.10.10.8" in lines[0]
    assert "[200]" in lines[0]
    assert "Welcome" in lines[0]
    assert "nginx" in lines[0]
    assert "PHP:8.1" in lines[0]
    assert "[401]" in lines[1]


def test_parse_httpx_ignores_lines_without_url():
    from pentos.runners.parsers import _parse_httpx
    assert _parse_httpx('{"status_code": 200}\n') == []
    assert _parse_httpx("garbage\n") == []


NAABU_SAMPLE = (
    '{"ip":"104.16.99.52","port":443}\n'
    '{"host":"scanme.example","ip":"104.16.99.52","port":80,"protocol":"tcp"}\n'
)


def test_parse_naabu_formats_ip_port_protocol():
    from pentos.runners.parsers import _parse_naabu
    lines = _parse_naabu(NAABU_SAMPLE)
    assert len(lines) == 2
    assert lines[0] == "104.16.99.52:443/tcp"
    assert lines[1] == "scanme.example (104.16.99.52):80/tcp"


def test_parse_naabu_ignores_lines_without_ip_or_port():
    from pentos.runners.parsers import _parse_naabu
    assert _parse_naabu('{"port": 443}\n') == []
    assert _parse_naabu('{"ip": "10.0.0.1"}\n') == []


DNSX_SAMPLE = (
    '{"host":"example.local","a":["10.10.10.9"],"timestamp":"2026-08-16T10:00:00Z"}\n'
    '{"host":"www.example.local","a":["10.10.10.9"],"cname":["example.local"]}\n'
    '{"host":"nxdomain.example.local"}\n'
)


def test_parse_dnsx_formats_host_and_records():
    from pentos.runners.parsers import _parse_dnsx
    lines = _parse_dnsx(DNSX_SAMPLE)
    assert len(lines) == 3
    assert lines[0] == "example.local → 10.10.10.9"
    assert "CNAME example.local" in lines[1]
    assert lines[2] == "nxdomain.example.local"  # keine Records, aber Host wird trotzdem gelistet


def test_parse_dnsx_ignores_lines_without_host():
    from pentos.runners.parsers import _parse_dnsx
    assert _parse_dnsx('{"a": ["1.2.3.4"]}\n') == []
