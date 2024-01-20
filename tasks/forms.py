from typing import Any
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import User

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ("email",)

    def clean(self):
        is_superuser = self.cleaned_data.get("is_superuser")
        is_staff     = self.cleaned_data.get("is_staff")
        is_active    = self.cleaned_data.get("is_active")
        
    def save(self, commit = True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user
    


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = ('email',)
    
    def clean(self):
        is_superuser = self.cleaned_data.get("is_superuser")
        is_staff     = self.cleaned_data.get("is_staff")
        is_active    = self.cleaned_data.get("is_active")
        
