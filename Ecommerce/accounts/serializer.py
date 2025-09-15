from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password




class userserializer(serializers.ModelSerializer):

    password = serializers.CharField(write_only=True, required=True)
    phone_number = serializers.CharField(required=False, allow_blank=True) 
    


    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'phone_number', 'is_verified']

    def validate_password(self, value):
        validate_password(value)
        return value
    
    def validate_phone_number(self, value):
        if value and User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("A user with this phone number already exists.")
        return value

    def create(self, validated_data):
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user
#new ------------------------------
class RegisterResponseSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()
    user = userserializer()

class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        help_text="The new password for the user."
    )

    def validate_new_password(self, value):
        validate_password(value)
        return value


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="The email address associated with the user account.")


class LoginSerializer(serializers.Serializer):
    login = serializers.CharField(required=True ,help_text="Email or phone number")
    password = serializers.CharField(required=True ,write_only=True, help_text="User's password")
    #remember_me = serializers.BooleanField(default=False, help_text="Remember me option")

    # def validate(self, data):
    #     login = data.get("login")
    #     password = data.get("password")

    #     # check user exists
    #     user = User.objects.filter(email=login).first() if "@" in login else User.objects.filter(phone_number=login).first()

    #     if not user or not user.check_password(password):
    #         raise serializers.ValidationError({"error": "Invalid credentials"})


    #     data["user"] = user
    #     return data




class LoginSuccessSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()
    user = serializers.DictField()


class ErrorSerializer(serializers.Serializer):
    error = serializers.CharField()



