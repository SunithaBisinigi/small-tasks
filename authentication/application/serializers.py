from rest_framework import serializers

class UserTokenSerializer(serializers.Serializer):
    access = serializers.CharField()
