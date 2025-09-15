from rest_framework.response import Response
from rest_framework.views import APIView 
from rest_framework import status

from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken ,AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from django.shortcuts import get_object_or_404
from .serializer import userserializer , RegisterResponseSerializer, ResetPasswordSerializer , ForgotPasswordSerializer , LoginSerializer , LoginSuccessSerializer , ErrorSerializer
from .models import User
from rest_framework.permissions import IsAuthenticated , IsAdminUser
from drf_spectacular.utils import OpenApiExample, extend_schema , OpenApiResponse , OpenApiRequest



# Create your views here.
from .utils import send_verification_email , send_password_reset_email



def success_response(data, message="Success", status_code=status.HTTP_200_OK):
    return Response({
        "status": "success",
        "message": message,
        "data": data
    }, status=status_code)

def error_response(errors, message="Validation failed", status_code=status.HTTP_400_BAD_REQUEST):
    return Response({
        "status": "error",
        "message": message,
        "errors": errors
    }, status=status_code)


class VerifyEmailView(APIView):
    @extend_schema(
        summary="Verify user email",
    description=(
        "Verifies a user's email address using the verification token sent via email.\n\n"
        "The frontend should call this endpoint with the token included in the query string.\n\n"
        "Example URL:\n"
        "`GET /api/auth/email-verify/?token=<verification_token>`"
    ),
        responses={
            200: OpenApiResponse(description="Email verified successfully"),
            400: OpenApiResponse(description="Invalid or missing token"),
            404: OpenApiResponse(description="User not found"),
        },

        tags=["Accounts"],  # هتظهر في الـ Swagger تحت قسم Authentication
    )
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

    @extend_schema(
        summary="Reset user password",
        description="Resets a user's password using the reset token sent via email.",
        request=ResetPasswordSerializer,
        responses={
            200: OpenApiResponse(
                description="Password reset successfully",
                examples=[
                    OpenApiExample(
                        "Success Response",
                        value={"message": "Password reset successfully"},
                        response_only=True,
                    ),
                ],
            ),
            400: OpenApiResponse(
                description="Invalid or missing token, or validation errors",
                examples=[
                    OpenApiExample(
                        "Invalid Token",
                        value={"error": "Invalid token"},
                        response_only=True,
                        status_codes=["400"],
                    ),
                    OpenApiExample(
                        "Weak Password",
                        value={"new_password": ["This password is too common."]},
                        response_only=True,
                        status_codes=["400"],
                    ),
                ],
            ),
            404: OpenApiResponse(description="User not found"),
        },
        tags=["Accounts"],
        examples=[
            OpenApiExample(
                "Reset Password Example",
                value={"new_password": "NewStrongPassword123!"},
                request_only=True,
            ),
        ],
    )
    def post(self, request, token):
        # 1️ Validate the request body using serializer
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 2️ Decode token and fetch user
            access_token = AccessToken(token)
            user_id = access_token["user_id"]
            user = User.objects.get(id=user_id)

            # 3️ Set and save the new password
            new_password = serializer.validated_data["new_password"]
            user.set_password(new_password)
            user.save()

            return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except TokenError:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
   
class ForgotPasswordView(APIView):
    @extend_schema(
        summary="Forgot password",
        description="Sends a password reset email if the email exists in the system.",
        request=ForgotPasswordSerializer,
        responses={
            200: OpenApiResponse(
                description="Reset link sent if email exists",
                examples=[
                    OpenApiExample(
                        "Success Response",
                        value={"message": "If your email exists, a reset link has been sent."},
                        response_only=True,
                    ),
                ]
            ),
        },
        tags=["Accounts"],
        examples=[
            OpenApiExample(
                "Forgot Password Example",
                value={"email": "user@example.com"},
                request_only=True,
            ),
        ]
    )
    def post(self, request):
        email = request.data.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            send_password_reset_email(user) 
        return Response({"message": "If your email exists, a reset link has been sent."})
    
class ResendVerificationEmailView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Resend verification email",
        description="Resends the email verification link to the authenticated user if their email is not verified.",
        responses={
            200: OpenApiResponse(
                description="Verification email sent",
                examples=[
                    OpenApiExample(
                        "Success Response",
                        value={"message": "Verification email sent."},
                    )
                ],
            ),
            400: OpenApiResponse(
                description="Email already verified",
                examples=[
                    OpenApiExample(
                        "Already Verified",
                        value={"message": "Email already verified."},
                    )
                ],
            ),
            401: OpenApiResponse(description="Unauthorized (user not authenticated)"),
        },
        tags=["Accounts"],
    )
    def post(self, request):
        user = request.user
        if not user.is_verified:
            send_verification_email(user)
            return Response({"message": "Verification email sent."}, status=status.HTTP_200_OK)
        return Response({"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)
    



class RegisterView(APIView):
    """
    Register a new user and send a verification email.
    Returns JWT tokens and user data on success.
    """
    @extend_schema(
        summary="Register new user",
        description=(
            "Registers a new user and sends a verification email.\n\n"
            "**Required fields:** `name`, `email`, `password`\n"
            "**Optional field:** `phone_number` (can be blank)\n"
            "Returns JWT tokens and user data on success."
        ),
        request= userserializer ,
        responses={
            201: RegisterResponseSerializer,
            400: ErrorSerializer,
        },
        tags=["Accounts"],
        examples=[
            OpenApiExample(
                "Success Response",
                value={
                    "status": "success",
                    "message": "User registered successfully.",
                    "data": {
                        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
                        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
                        "user": {
                            "name": "John Doe",
                            "email": "sabdhds@gmail.com",
                            "phone_number": "+201234567890",
                            "is_verified": False
                        }
                    }
                },
                response_only=True,
            ),
            OpenApiExample(
                "Validation Error",
                value={
                    "status": "error",
                    "message": "Validation failed",
                    "errors": {
                        "email": ["This field must be unique."]
                    }
                },
                response_only=True,
                status_codes=["400"],
            ),
        ],
    )
    @transaction.atomic
    def post(self, request):
        serializer = userserializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            send_verification_email(user)
            return success_response(
                message="User registered successfully.",
                data={
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "user": serializer.data
                },
                status_code=status.HTTP_201_CREATED
            )
        return error_response(serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)

    
class LoginView(APIView):
    @extend_schema(
        summary="Login user",
        description=(
            "Authenticates a user using email or phone number and password.\n\n"
            "- **login**: Email or phone number.\n"
            "- **password**: User's password.\n\n"
            "If successful, returns access & refresh JWT tokens and user details."
        ),
        request=OpenApiRequest(
            request=LoginSerializer,
            examples=[
                OpenApiExample(
                    "Login Example",
                    value={"login": "user@example.com", "password": "StrongPassword123!"},
                    request_only=True,
                ),
            ],
        ),
        responses={
            200: OpenApiResponse(
                response=LoginSuccessSerializer,
                description="Login successful",
                examples=[
                    OpenApiExample(
                        "Success Response",
                        value={
                            "status": "success",
                            "message": "Login successful",
                            "data": {
                                "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
                                "access": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
                                "user": {
                                    "name": "John Doe",
                                    "email": "john@example.com",
                                    "phone_number": "+201234567890",
                                    "is_verified": True
                                }
                            }
                        },
                        response_only=True,
                    ),
                ],
            ),
            400: OpenApiResponse(
                response=ErrorSerializer,
                description="Both login and password are required.",
                examples=[
                    OpenApiExample(
                        "Missing Fields",
                        value={
                            "status": "error",
                            "message": "Both login and password are required.",
                            "errors": {"error": "Both login and password are required."}
                        },
                        response_only=True,
                        status_codes=["400"],
                    ),
                ],
            ),
            401: OpenApiResponse(
                response=ErrorSerializer,
                description="Invalid credentials or email not verified",
                examples=[
                    OpenApiExample(
                        "Invalid Credentials",
                        value={
                            "status": "error",
                            "message": "Invalid credentials",
                            "errors": {"error": "Invalid credentials"}
                        },
                        response_only=True,
                        status_codes=["401"],
                    ),
                ],
            ),
            403: OpenApiResponse(
                response=ErrorSerializer,
                description="Account is blocked.",
                examples=[
                    OpenApiExample(
                        "Blocked Account",
                        value={
                            "status": "error",
                            "message": "Account is blocked.",
                            "errors": {"error": "This account is blocked. Please contact support."}
                        },
                        response_only=True,
                        status_codes=["403"],
                    ),
                ],
            ),
        },
        tags=["Accounts"],
    )
    def post(self, request):            #momken validate b login serializer
        login = request.data.get("login")
        password = request.data.get("password")

        if not login or not password:
            return error_response(
                errors={"error" : "Both login and password are required."},
                message="Both login and password are required.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        # Find user by email or phone, but don't raise 404
        user = User.objects.filter(email=login).first() if "@" in login else User.objects.filter(phone_number=login).first()

        if user:
            if not user.is_active:
                return error_response(
                    errors={"error": "This account is blocked. Please contact support."},
                    message="Account is blocked.",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            if user.check_password(password):
                # if not user.is_verified:
                #     return Response({"error": "Email not verified"}, status=status.HTTP_401_UNAUTHORIZED)

                refresh = RefreshToken.for_user(user)
                serializer = userserializer(user)
                return success_response(
                    message="Login successful",
                    data={
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "user": serializer.data
                        
                    },
                    status_code=status.HTTP_200_OK
                )

        # Always return same message for wrong login or wrong password
        return error_response(
            errors={"error": "Invalid credentials"},
            message="Invalid credentials",
            status_code=status.HTTP_401_UNAUTHORIZED
        )

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

