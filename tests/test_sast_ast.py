"""AST analyzer rule coverage - vulnerable snippets must be detected (spec 37)."""
import pytest

from scanners.sast.ast_analyzer import analyze_source


def hit_ids(source):
    return [h.rule_id for h in analyze_source("views.py", source).hits]


@pytest.mark.parametrize("code,rule", [
    ("def v(request):\n    return eval(request.GET['x'])\n", "DYN-001"),
    ("def v(request):\n    exec(request.POST['c'])\n", "DYN-001"),
    ("def v():\n    m = __import__('os')\n", "DYN-002"),
    ("import pickle\ndef v(request):\n    return pickle.loads(request.body)\n", "DESER-001"),
    ("import yaml\ndef v(request):\n    yaml.load(request.body)\n", "DESER-002"),
    ("import yaml\ndef v():\n    yaml.load(open('f'), Loader=yaml.FullLoader)\n", "DESER-002"),
    ("import marshal\ndef v():\n    marshal.loads(b'x')\n", "DESER-003"),
    ("import os\ndef v(request):\n    os.system('ls ' + request.GET['d'])\n", "CMD-001"),
    ("import subprocess\ndef v(request):\n    subprocess.run(request.GET['c'], shell=True)\n",
     "CMD-002"),
    ("import subprocess\ndef v(request):\n    subprocess.run(['ls', request.GET['d']])\n",
     "CMD-003"),
    ("def v(request):\n    from django.db import connection\n"
     "    with connection.cursor() as c:\n"
     "        c.execute('SELECT * FROM t WHERE id=%s' % request.GET['i'])\n", "SQLI-001"),
    ("def v(request):\n    from django.db import connection\n"
     "    with connection.cursor() as c:\n"
     "        c.execute(f'SELECT * FROM t WHERE id={request.GET[\"i\"]}')\n", "SQLI-001"),
    ("def v(request):\n    from app.models import M\n"
     "    M.objects.raw('SELECT * FROM m WHERE n=' + request.GET['n'])\n", "SQLI-002"),
    ("from django.db.models.expressions import RawSQL\n"
     "def v(request):\n    RawSQL('SELECT ' + request.GET['x'], [])\n", "SQLI-003"),
    ("from django.utils.safestring import mark_safe\n"
     "def v(request):\n    return mark_safe(request.GET['h'])\n", "XSS-001"),
    ("def v(request):\n    open('/data/' + request.GET['f'])\n", "PATH-001"),
    ("from django.http import FileResponse\n"
     "def v(request):\n    return FileResponse(open(request.GET['f'], 'rb'))\n", "PATH-002"),
    ("import tempfile\ndef v():\n    tempfile.mktemp()\n", "TMP-001"),
    ("import requests\ndef v(request):\n    requests.get(request.GET['url'])\n", "SSRF-001"),
    ("from django.shortcuts import redirect\n"
     "def v(request):\n    return redirect(request.GET['next'])\n", "REDIR-001"),
    ("import hashlib\ndef v():\n    hashlib.md5(b'x')\n", "CRYPTO-001"),
    ("import hashlib\ndef v():\n    hashlib.sha1(b'x')\n", "CRYPTO-001"),
    ("import random\ndef v():\n    api_key = random.getrandbits(128)\n", "CRYPTO-002"),
    ("import xml.etree.ElementTree as ET\ndef v(request):\n    ET.fromstring(request.body)\n",
     "XXE-001"),
    ("from django.template import Template\n"
     "def v(request):\n    Template(request.GET['t']).render()\n", "TPL-001"),
    ("from django.views.decorators.csrf import csrf_exempt\n"
     "@csrf_exempt\ndef v(request):\n    pass\n", "CSRF-001"),
    ("SECRET_KEY = 'literal-secret-key-value-long-enough'\n", "SECRET-001"),
    ("smtp_password = 'correct-horse-battery-staple'\n", "SECRET-002"),
    ("import re\nR = re.compile('(a+)+$')\n", "DOS-001"),
])
def test_vulnerable_snippet_detected(code, rule):
    assert rule in hit_ids(code), f"{rule} not detected in:\n{code}"


@pytest.mark.parametrize("code", [
    "import yaml\ndef v():\n    yaml.safe_load(open('f'))\n",
    "import hashlib\ndef v():\n    hashlib.md5(b'x', usedforsecurity=False)\n",
    "from django.utils.html import format_html\n"
    "def v(request):\n    format_html('<b>{}</b>', request.GET['n'])\n",
    "from django.utils.http import url_has_allowed_host_and_scheme\n"
    "from django.shortcuts import redirect\n"
    "def v(request):\n"
    "    t = request.GET.get('next')\n"
    "    if url_has_allowed_host_and_scheme(t):\n"
    "        return redirect(t)\n",
    "import subprocess\ndef v():\n    subprocess.run(['ls', '-l'])\n",
    "def v():\n    eval('1+1')\n" * 0 + "def v():\n    x = 1 + 1\n",
    "import defusedxml.ElementTree as ET\ndef v(request):\n    ET.fromstring(request.body)\n",
])
def test_safe_snippet_no_high_findings(code):
    hits = analyze_source("views.py", code).hits
    strong = [h for h in hits if (h.confidence or "") in ("Confirmed", "High")]
    assert not strong, f"unexpected strong findings: {[h.rule_id for h in strong]}"


def test_mark_safe_trusted_is_potential_not_confirmed():
    hits = analyze_source("views.py",
                          "from django.utils.safestring import mark_safe\n"
                          "TRUSTED = '<b>hi</b>'\ndef v():\n    return mark_safe(TRUSTED)\n").hits
    xs = [h for h in hits if h.rule_id == "XSS-001"]
    assert xs and xs[0].confidence != "Confirmed"


def test_mark_safe_request_data_is_confirmed():
    hits = analyze_source("views.py",
                          "from django.utils.safestring import mark_safe\n"
                          "def v(request):\n    return mark_safe(request.GET['name'])\n").hits
    xs = [h for h in hits if h.rule_id == "XSS-001"]
    assert xs and xs[0].confidence == "Confirmed"


def test_subprocess_shell_true_tainted_is_confirmed():
    hits = analyze_source("views.py",
                          "import subprocess\n"
                          "def v(request):\n    subprocess.run(request.GET['c'], shell=True)\n").hits
    assert any(h.rule_id == "CMD-002" and h.confidence == "Confirmed" for h in hits)


def test_empty_permission_classes_detected():
    code = ("from rest_framework.views import APIView\n"
            "class V(APIView):\n    permission_classes = []\n")
    assert "AUTHZ-002" in hit_ids(code)


def test_allowany_detected():
    code = ("from rest_framework.views import APIView\n"
            "from rest_framework.permissions import AllowAny\n"
            "class V(APIView):\n    permission_classes = [AllowAny]\n")
    assert "AUTHZ-001" in hit_ids(code)


def test_empty_authentication_classes_detected():
    code = ("from rest_framework.views import APIView\n"
            "class V(APIView):\n    authentication_classes = []\n")
    assert "AUTHZ-003" in hit_ids(code)


def test_detail_view_without_scoping_flagged():
    code = ("from rest_framework import viewsets\n"
            "from .models import Doc\n"
            "class DocViewSet(viewsets.ModelViewSet):\n"
            "    queryset = Doc.objects.all()\n")
    assert "AUTHZ-OBJECT-001" in hit_ids(code)


def test_scoped_detail_view_not_flagged():
    code = ("from rest_framework import viewsets\n"
            "from .models import Doc\n"
            "class DocViewSet(viewsets.ModelViewSet):\n"
            "    def get_queryset(self):\n"
            "        return Doc.objects.filter(owner=self.request.user)\n")
    assert "AUTHZ-OBJECT-001" not in hit_ids(code)


def test_serializer_sensitive_field_flagged():
    code = ("from rest_framework import serializers\n"
            "from .models import U\n"
            "class US(serializers.ModelSerializer):\n"
            "    class Meta:\n"
            "        model = U\n"
            "        fields = ['id', 'name', 'password']\n")
    assert "SENSITIVE-001" in hit_ids(code)


def test_serializer_write_only_not_flagged():
    code = ("from rest_framework import serializers\n"
            "from .models import U\n"
            "class US(serializers.ModelSerializer):\n"
            "    password = serializers.CharField(write_only=True)\n"
            "    class Meta:\n"
            "        model = U\n"
            "        fields = ['id', 'name', 'password']\n")
    assert "SENSITIVE-001" not in hit_ids(code)


def test_mass_assignment_detected():
    code = ("from .models import Doc\n"
            "def v(request):\n    Doc.objects.create(**request.data)\n")
    ids = hit_ids(code)
    assert "MASS-001" in ids and "SER-001" in ids


def test_logging_sensitive_value_flagged():
    code = ("import logging\n"
            "def v(password):\n    logging.info('pw is %s', password)\n")
    assert "LOG-001" in hit_ids(code)


def test_race_heuristic_flagged():
    code = ("from .models import Account\n"
            "def v(request):\n"
            "    account = Account.objects.get(pk=request.GET['id'])\n"
            "    account.balance += 10\n"
            "    account.save()\n")
    assert "RACE-001" in hit_ids(code)


def test_upload_without_validation_flagged():
    code = ("def v(request):\n"
            "    f = request.FILES['file']\n"
            "    open('/tmp/' + f.name, 'wb').write(f.read())\n"
            "    return f.name\n")
    assert "UPLOAD-001" in hit_ids(code)


def test_control_presence_recorded():
    code = ("from django.utils.http import url_has_allowed_host_and_scheme\n"
            "def v(request):\n"
            "    t = request.GET.get('next')\n"
            "    if url_has_allowed_host_and_scheme(t):\n"
            "        from django.shortcuts import redirect\n"
            "        return redirect(t)\n")
    res = analyze_source("views.py", code)
    assert any(c.rule_key == "OK-REDIR" for c in res.controls)
