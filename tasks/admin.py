from django.contrib import admin
from .models import User
from django.contrib.auth.admin import UserAdmin
from .forms import CustomUserCreationForm, CustomUserChangeForm

# Register your models here.

class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form     = CustomUserChangeForm
    model    = User

    add_fieldsets = (
        (None, {
            'classes': ('wise',),
            'fields' : ('email', 'username', 'is_active', 'is_staff', 'is_superuser', 'password1', 'password2')
        }),
    )
    fieldsets = (
        (None, {
            "fields": (
                ("username", "password", "first_name", "last_name", "email","otp", "is_active",\
                 "is_staff", "is_superuser", "groups", "user_permissions", "last_login", "date_joined")
            ),
        }),
    )
    list_display = [
        'email',
        'id',
        'first_name',
        'last_name',
        'username',
        'date_joined',
    ]

    search_fields = [
        'email',
        'id',
        'first_name',
        'last_name',
        'username',
        'date_joined',
    ]
admin.site.register(User, CustomUserAdmin)
