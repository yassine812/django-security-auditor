"""Secure coding patterns fixture - used to verify low false-positive rates."""
import hashlib
import secrets

import defusedxml.ElementTree as SafeET
import yaml
from django.http import FileResponse, HttpResponse
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from .models import Note
from .serializers import NoteSerializer


def search(request):
    query = request.GET.get("q", "")
    # parameterized via the ORM
    notes = Note.objects.filter(title__icontains=query, owner=request.user)
    return render(request, "ok.html", {"notes": notes})


def safe_yaml(request):
    config = yaml.safe_load(request.body)
    return HttpResponse(str(config))


def safe_xml(request):
    tree = SafeET.fromstring(request.body)
    return HttpResponse(tree.tag)


def safe_hash(request):
    # allowed: non-security checksum with explicit annotation
    digest = hashlib.sha256(request.GET.get("data", "").encode()).hexdigest()
    return HttpResponse(digest)


def make_token(request):
    token = secrets.token_urlsafe(32)
    return HttpResponse(token)


def safe_redirect(request):
    target = request.GET.get("next", "/")
    if url_has_allowed_host_and_scheme(target, allowed_hosts={"notes.example.com"}):
        return redirect(target)
    return redirect("/")


def download(request, note_id):
    note = Note.objects.get(pk=note_id, owner=request.user)   # scoped + validated
    path = "/var/notes-store/" + str(note.storage_key)         # derived from db record
    return FileResponse(open(path, "rb"))


def transfer(request):
    from django.db import transaction
    from django.db.models import F
    with transaction.atomic():
        Note.objects.select_for_update().filter(pk=request.POST.get("id")).update(
            version=F("version") + 1)
    return HttpResponse("ok")


class NoteViewSet(viewsets.ModelViewSet):
    serializer_class = NoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # scoped to the requesting user - prevents cross-user object access
        return Note.objects.filter(owner=self.request.user)

    def perform_destroy(self, instance):
        if instance.owner != self.request.user:
            raise PermissionError("not the owner")
        instance.delete()
