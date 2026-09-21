from django.db import models


class Note(models.Model):
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    body = models.TextField()
    storage_key = models.CharField(max_length=64)
    version = models.IntegerField(default=1)
