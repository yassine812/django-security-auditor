from django.db import models


class Document(models.Model):
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    body = models.TextField()
    secret_note = models.CharField(max_length=200, default="")
