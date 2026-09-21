"""Regex/pattern SAST layer (templates + secrets in arbitrary files)."""
from scanners.sast.patterns import scan_file_text, should_scan


def test_safe_filter_in_template():
    vulns, _ = scan_file_text("t/page.html", "<div>{{ user_bio|safe }}</div>")
    assert any(v["rule_id"] == "XSS-002" for v in vulns)


def test_autoescape_off_in_template():
    vulns, _ = scan_file_text("t/p.html", "{% autoescape off %}{{ x }}{% endautoescape %}")
    assert any(v["rule_id"] == "XSS-003" for v in vulns)


def test_aws_key_in_env_file():
    vulns, _ = scan_file_text(".env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    assert any(v["rule_id"] == "SECRET-004" for v in vulns)


def test_github_token_in_yaml():
    vulns, _ = scan_file_text("ci.yml", "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWxyz\n")
    assert any(v["rule_id"] == "SECRET-005" for v in vulns)


def test_private_key_file():
    vulns, _ = scan_file_text("id_rsa.pem",
                              "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n"
                              "-----END RSA PRIVATE KEY-----\n")
    assert any(v["rule_id"] == "SECRET-003" for v in vulns)


def test_generic_credential_in_config():
    vulns, _ = scan_file_text("config.ini", "[db]\npassword = supersecretpw123\n")
    assert any(v["rule_id"] == "SECRET-002" for v in vulns)


def test_env_placeholder_not_flagged():
    vulns, _ = scan_file_text("config.env", "PASSWORD=${DB_PASSWORD}\n")
    assert not any(v["rule_id"] == "SECRET-002" for v in vulns)


def test_control_patterns():
    _, controls = scan_file_text("x.py", "import defusedxml\n")
    assert any(c["rule_key"] == "OK-DEFUSEDXML" for c in controls)


def test_should_scan_excludes_vendor_dirs():
    assert not should_scan("node_modules/lib/x.js")
    assert not should_scan(".venv/lib/site.py")
    assert not should_scan("app/migrations/0001_initial.py")
    assert should_scan("app/views.py")
    assert should_scan("templates/index.html")


def test_line_numbers_correct():
    text = "a=1\nb=2\nc={{ x|safe }}\n"
    vulns, _ = scan_file_text("t.html", text)
    assert vulns[0]["line"] == 3
