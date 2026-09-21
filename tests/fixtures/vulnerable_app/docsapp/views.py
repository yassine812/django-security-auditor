"""Intentionally vulnerable views fixture.

Contains: SQL injection, eval, command injection, pickle deserialization,
SSRF, open redirect, path traversal, mark_safe XSS, weak crypto, insecure
temp files, unsafe YAML, SSTI, log leakage, mass assignment.
"""
import hashlib
import os
import pickle
import random
import subprocess
import tempfile

import requests
import yaml
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.template import Template
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import Document
from .serializers import DocumentSerializer

API_KEY = "sk_live_FAKE0000000000000000"   # synthetic test key (fixture for SECRET-006)


def calc(request):
    expr = request.GET.get("expr", "1+1")
    result = eval(expr)                      # dynamic code execution (RCE)
    exec("x = %r" % result)                  # dynamic code execution
    return HttpResponse(result)


def search(request):
    query = request.GET.get("q", "")
    # SQL injection via string formatting
    sql = "SELECT * FROM documents WHERE title LIKE '%%%s%%'" % query
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute(sql)
        rows = cursor.fetchall()
    return HttpResponse(str(rows))


def document_detail(request, doc_id):
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM documents WHERE id = {doc_id}")
        row = cursor.fetchone()
    return HttpResponse(str(row))


def run_report(request):
    name = request.GET.get("name")
    # command injection
    os.system("generate-report.sh " + name)
    # command injection via shell=True with tainted input
    subprocess.run("convert " + name, shell=True)
    return HttpResponse("ok")


def load_profile(request):
    data = request.body
    profile = pickle.loads(data)
    return HttpResponse(str(profile))


def import_config(request):
    config = yaml.load(request.body)
    return HttpResponse(str(config))


def fetch_preview(request):
    url = request.GET.get("url")
    resp = requests.get(url)
    return HttpResponse(resp.text[:100])


def go_next(request):
    target = request.GET.get("next")
    return redirect(target)


def download(request):
    filename = request.GET.get("file")
    path = "/var/uploads/" + filename
    return FileResponse(open(path, "rb"))


def welcome(request):
    name = request.GET.get("name", "world")
    html_content = "<b>Hello " + name + "</b>"
    return render(request, "page.html", {"content": html_content})


def dynamic_template(request):
    tpl_source = request.GET.get("tpl")
    tpl = Template(tpl_source)
    return HttpResponse(tpl.render())


def make_token(request):
    token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    digest = hashlib.md5(token.encode()).hexdigest()
    logger_info("generated token " + token)
    return HttpResponse(digest)


def logger_info(message):
    import logging
    logging.getLogger(__name__).info(f"user token: {message}")


def save_tmp(request):
    path = tempfile.mktemp()
    with open(path, "w") as fh:
        fh.write(request.body.decode())
    return HttpResponse(path)


@csrf_exempt
@api_view(["POST"])
def bulk_update(request):
    Document.objects.filter(pk=request.data.get("id")).update(**request.data)
    return Response({"status": "ok"})


class DocumentViewSet(viewsets.ModelViewSet):
    queryset = Document.objects.all()
    serializer_class = DocumentSerializer
    permission_classes = [AllowAny]


class PrivateViewSet(viewsets.ModelViewSet):
    queryset = Document.objects.all()
    serializer_class = DocumentSerializer
    authentication_classes = []
    permission_classes = []
