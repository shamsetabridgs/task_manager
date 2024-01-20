from django.urls import path, include
from .views import LoginView, CustomRefreshTokenAPIView, UserRegistrationViewSet,ResetPasswordViewSet,\
      OTPVerifyViewSet, SetPasswordViewSet, TaskViewSet, TaskSearchViewSet
from rest_framework import routers



router = routers.DefaultRouter()
router.register('registration', UserRegistrationViewSet, basename='user_registration')
router.register('otp-verify', OTPVerifyViewSet, basename='otp-verify')
router.register('reset-password', ResetPasswordViewSet, basename='reset-password')
router.register('set-password', SetPasswordViewSet, basename='password')
router.register('tasks', TaskViewSet, basename='task')
router.register('task-search', TaskSearchViewSet, basename='task-search')

urlpatterns = [
    path('user/', include(router.urls)),
    path('user/login/', LoginView.as_view(), name='login'),
    path('user/refresh-token/', CustomRefreshTokenAPIView.as_view(), name='refresh_token')
]