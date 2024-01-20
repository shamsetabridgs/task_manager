from django.contrib import admin
from .models import User, Task, Photo
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



@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'description', 'due_date', 'priority', 'is_complete', 'created_at', 'updated_at')
    search_fields = ('title',)
    list_filter = ('due_date', 'priority', 'is_complete')

@admin.register(Photo)
class PhotoAdmin(admin.ModelAdmin):
    list_display = ('task', 'image', 'created_at')
    list_filter = ('task', 'created_at')