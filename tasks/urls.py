from django.urls import path, include
from .views import LoginView, CustomRefreshTokenAPIView, UserRegistrationViewSet,ResetPasswordViewSet,\
      OTPVerifyViewSet, SetPasswordViewSet, TaskViewSet, TaskSearchViewSet,\
                register_view, login_view, task_detail, task_list, logout_view, task_create, task_update, task_delete
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
    path('user/refresh-token/', CustomRefreshTokenAPIView.as_view(), name='refresh_token'),


    path('', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('task-list/', task_list, name='task_list'),
    path('task-detail/<task_id>/', task_detail, name='task_detail'),
    path('logout/', logout_view, name='logout'),
    path('task-create/', task_create, name='task_create'),
    path('task-update/<task_id>/', task_update, name='task_update'),
    path('task-delete/<int:task_id>/', task_delete, name='task_delete'), 
]