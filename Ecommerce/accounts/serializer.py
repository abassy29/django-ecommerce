from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password




class userserializer(serializers.ModelSerializer):

    password = serializers.CharField(write_only=True, required=True)


    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'phone_number']

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user