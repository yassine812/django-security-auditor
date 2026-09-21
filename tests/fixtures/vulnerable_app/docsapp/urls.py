from rest_framework import routers
from django.urls import path

from . import views

router = routers.DefaultRouter()
router.register("documents", views.DocumentViewSet)
router.register("private", views.PrivateViewSet)

urlpatterns = [
    path("search/", views.search),
    path("doc/<int:doc_id>/", views.document_detail),
    path("report/", views.run_report),
    path("profile/", views.load_profile),
    path("config/", views.import_config),
    path("preview/", views.fetch_preview),
    path("go/", views.go_next),
    path("download/", views.download),
    path("welcome/", views.welcome),
    path("render/", views.dynamic_template),
    path("token/", views.make_token),
    path("bulk/", views.bulk_update),
]

urlpatterns += router.urls
