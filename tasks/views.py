from django.shortcuts import render

# Create your views here.
import jwt
from datetime import datetime
from django.conf import settings
from django.db.models import QuerySet
from drf_yasg.utils import swagger_auto_schema
from rest_framework import exceptions
from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from common.responses import bad_request_response, not_found_response, success_response, get_plain_error_message_from_exception
from .authentication import JWTAuthentication
from .helper import random_with_N_digits
from .models import User
from .serializers import UserLoginSerializer, ObtainTokenSerializer, RefreshTokenSerializer, UserRegistrationSerializer, OTPVerifySerializer, ResetPasswordSerializer, SetPasswordValidatorTokenSerializer,\
SetPasswordSerializer

timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

# Create your views here.

class LoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class   = ObtainTokenSerializer

    @swagger_auto_schema(request_body=serializer_class)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)

            email    = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')

            user = User.objects.filter(email = email).first()

            if user is None:
                return bad_request_response(400,{
                    "path"    : "Login",
                    "message" : "Email or Wrong Password"
                })
            
            if user is None or not user.check_password(password):
                return bad_request_response(400, {
                    "path"    : "Login",
                    "message" : "Invalid Credentials"
                })
            
            if user.is_active :       #Generate the JWT token
                access_token    = JWTAuthentication.generate_access_token(user)
                refresh_token   = JWTAuthentication.generate_refresh_token(user)
                user_serializer = UserLoginSerializer(user)
                token = {
                    'access_token' : access_token,
                    'refresh_token': refresh_token
                }
                return success_response(200, 'successfully login', user_serializer.data, **token)
            else:
                return bad_request_response(400, {
                    "path"    : "Login",
                    "message" : "Something is Causing Problems."
                })
        except Exception as e:
            error = get_plain_error_message_from_exception(e)
            return bad_request_response(400, error)
        
class CustomRefreshTokenAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class   = RefreshTokenSerializer

    @swagger_auto_schema(request_body=RefreshTokenSerializer)
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')

            if not refresh_token:
                return bad_request_response(400, {
                    "path"    : "Refresh Token",
                    "message" : "Refresh token is required."
                })
            
            try:
                payload = jwt.decode(refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                dict_response = {
                    "message"   : "Unauthorized",
                    "timestamp" : timestamp,
                    "details"   : {
                        "path"    : "Refresh Token",
                        "message" : "expired refresh token, please login again"
                    }
                }
                raise exceptions.AuthenticationFailed(dict_response)
            
            user = User.objects.filter(id = payload.get('user_identifier')).first()
            if user is None:
                dict_response = {
                    "message"   : "Unauthorized",
                    "timestamp" : timestamp,
                    "details"   : {
                        "path"    : "User",
                        "message" : "User not found"
                    }
                }
                raise exceptions.AuthenticationFailed(dict_response)
            
            if not user.is_active:
                dict_response = {
                    "message"   : "Unauthorized",
                    "timestamp" : timestamp,
                    "details"   : {
                        "path"    : "User",
                        "message" : "User not found"
                    }
                }
                raise exceptions.AuthenticationFailed(dict_response)
            
            access_token    = JWTAuthentication.generate_access_token(user)
            refresh_token   = JWTAuthentication.generate_refresh_token(user)
            user_serializer = UserLoginSerializer(user)

            token = {
                'access_token'  : access_token,
                'refresh_token' : refresh_token,
            }
            return success_response(200, "Successfully refresh token generate", user_serializer.data, **token)
        
        except Exception as e:
            error = get_plain_error_message_from_exception(e)
            return bad_request_response(400, error)


class UserRegistrationViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]
    serializers_class  = UserRegistrationSerializer

    @swagger_auto_schema(request_body=UserRegistrationSerializer)
    def create(self, request):
        try:
            serializer = UserRegistrationSerializer(data = request.data)
            serializer.is_valid(raise_exception=True)
            password         = serializer.validated_data['password']
            confirm_password = serializer.validated_data['confirm_password']

            if password != confirm_password :
                return bad_request_response(400, {
                    "path"    : "Password",
                    "message" : "Password are unmatched."
                })
            
            user = User.objects.create_user(
                email    = serializer.validated_data['email'],
                username = serializer.validated_data['username'],
                password = password
            )

            user.save()

            user_data = serializer.data.copy()
            user_data.pop('password', None)
            user_data.pop('confirm_password', None)

            return success_response(201, "User created successfully", data=user_data)
        
        except Exception as e:
            error = get_plain_error_message_from_exception(e)
            return bad_request_response(400, error)
        
        

class OTPVerifyViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body = OTPVerifySerializer)
    def create(self, request, *args, **kwargs):
        try:
            serializer = OTPVerifySerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            email = serializer.validated_data.get("email")
            user  = User.objects.get(email = email)
            otp   = serializer.validated_data.get("otp")

            if user and user.otp == otp:
                user.otp = None
                user.save()
                access_token = JWTAuthentication.generate_access_token(user)
                token        = {"token" : access_token}
                return success_response(200, "OTP verification successful", **token)
            return bad_request_response(400, {
                "path"    : "OTP Code",
                "message" : "Invalid OTP Code."
            })
        except Exception as e:
            error = get_plain_error_message_from_exception(e)
            return bad_request_response(400, error)
        


class ResetPasswordViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    @swagger_auto_schema(request_body=ResetPasswordSerializer)
    def create(self, request):
        try:
            serializer = ResetPasswordSerializer(data = request.data)
            serializer.is_valid(raise_exception=True)

            email    = serializer.validated_data.get("email")
            user     = User.objects.get(email = email)
            otp      = random_with_N_digits(4)
            user.otp = otp
            user.save()
            return success_response(200, "OTP sent successfully", data=email)
        
        except Exception as e:
            error = get_plain_error_message_from_exception(e)
            return bad_request_response(400, error)
        


class SetPasswordViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        try:
            user_serializer = SetPasswordValidatorTokenSerializer(data=request.data)
            user_serializer.is_valid(raise_exception=True)
            
            access_token  = user_serializer.data.get("token")
            payload       = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
            user          = User.objects.get(id = payload.get("user_id"))
            serializer    = SetPasswordSerializer(data=request.data, context = user)
            serializer.is_valid(raise_exception=True)

            if serializer.validated_data.get("new_password") != serializer.validated_data.get("confirm_password"):
                return bad_request_response(400, {
                    "path" : "New Password",
                    "message" : "New passwords do not match."
                })
            user.set_password(serializer.validated_data.get("new_password"))
            user.save()
            return success_response(200, "Password changed successfully")
        
        except Exception as e:
            error = get_plain_error_message_from_exception(e)
            return bad_request_response(400, error)