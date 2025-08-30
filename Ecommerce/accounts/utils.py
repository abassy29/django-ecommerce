from django.core.mail import send_mail
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken


def send_verification_email(user):
    token = RefreshToken.for_user(user).access_token
    link = f"http://localhost:8000/api/accounts/verify-email/{token}"
    subject = "Verify your email"
    message = f"Hi {user.name}, please verify your email by clicking the link: {link}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])


def send_password_reset_email(user):
    token = RefreshToken.for_user(user).access_token
    link = f"http://localhost:8000/api/accounts/reset-password/{token}"
    subject = "Reset your password"
    message = f"Hi {user.name}, please reset your password by clicking the link: {link}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])