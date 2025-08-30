#import Response
from rest_framework.response import Response
from rest_framework.views import APIView 
from rest_framework import status

from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken ,AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from django.shortcuts import get_object_or_404
from .serializer import userserializer
from .models import User
from rest_framework.permissions import IsAuthenticated , IsAdminUser




# Create your views here.
from .utils import send_verification_email , send_password_reset_email
class VerifyEmailView(APIView):
    def get(self, request, token):
        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
           
           access_token = AccessToken(token)
           user_id = access_token['user_id']

           user = User.objects.get(id=user_id)
           user.is_verified = True
           user.save()
           return Response({"message": "Email verified successfully"}, status=status.HTTP_200_OK)
        except user.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except TokenError:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:  
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            
class ResetPasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request ,token):
        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            user = User.objects.get(id=user_id)
            new_password = request.data.get('new_password')
            if new_password:
                user.save()
                return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "New password is required"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            send_password_reset_email(user) 
        return Response({"message": "If your email exists, a reset link has been sent."})
    
class ResendVerificationEmailView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        if not user.is_verified:
            send_verification_email(user)
            return Response({"message": "Verification email sent."}, status=status.HTTP_200_OK)
        return Response({"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)



class RegisterView(APIView):
    @transaction.atomic
    def post(self, request):
        serializer = userserializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            # send_verification_email(user)
            send_verification_email(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": serializer.data,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
class LoginView(APIView):
    def post(self,request):
        
        login = request.data.get('login')
        password = request.data.get('password')
        if '@' in login:
            user = get_object_or_404(User , email=login)
        else:
            user = get_object_or_404(User , phone_number=login)
        if user.check_password(password):
            refresh = RefreshToken.for_user(user)
            serializer = userserializer(user)
            if not user.is_verified:
                return Response({"error": "Email not verified"}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": serializer.data,
            }, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    
class LogoutView(APIView):
    pass




# check it out
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request , pk=None):
        if pk:
            #self permission_classes = [IsAdminUser] Ask chat-gbt
            if not request.user.is_superuser:
                return Response({"error": "You do not have permission to view this user."}, status=status.HTTP_403_FORBIDDEN)
            user = get_object_or_404(User, pk=pk)
        else:
            user = request.user
        serializer = userserializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
# class UpdateProfileView(APIView):
#     pass
# class ChangePasswordView(APIView):
#     pass
class userListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        users = User.objects.all()
        serializer = userserializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)