from rest_framework import routers
from django.urls import path

from . import views

router = routers.SimpleRouter()
router.register("notes", views.NoteViewSet)

urlpatterns = [
    path("search/", views.search),
    path("yaml/", views.safe_yaml),
    path("xml/", views.safe_xml),
    path("hash/", views.safe_hash),
    path("token/", views.make_token),
    path("go/", views.safe_redirect),
    path("download/<int:note_id>/", views.download),
    path("transfer/", views.transfer),
]

urlpatterns += router.urls
