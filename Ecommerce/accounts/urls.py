from django.urls import path
from .views import RegisterView, userListView ,LoginView ,UserProfileView, VerifyEmailView ,ResetPasswordView,ForgotPasswordView , ResendVerificationEmailView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('users/', userListView.as_view(), name='user_list'),
    path('login/', LoginView.as_view(), name='login'),
    # path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('profile/<int:pk>/', UserProfileView.as_view(), name='user_profile_detail'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify_email'),
    path('reset-password/<str:token>/', ResetPasswordView.as_view(), name='reset_password'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('resend-verification-email/', ResendVerificationEmailView.as_view(), name='resend_verification_email'),
    # path('update-profile/', UpdateProfileView.as_view(), name='update_profile'),
    # path('delete-account/', DeleteAccountView.as_view(), name='delete_account'),


    #///////////////////////////
    
]
