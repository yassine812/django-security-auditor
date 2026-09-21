from rest_framework import serializers

from .models import Note


class NoteSerializer(serializers.ModelSerializer):
    api_key = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Note
        fields = ["id", "title", "body", "api_key"]
