from typing import Any
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import User, Task

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
        

from django import forms
class Custom_User_CreationForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text='Required. Enter a valid email address.')

    class Meta:
        model = User
        fields = ('email',)


from tempus_dominus.widgets import DatePicker
class TaskCreationForm(forms.ModelForm):
    # Change the widget to ClearableFileInput
    photos = forms.ImageField(widget=forms.ClearableFileInput(attrs={'multiple': False}), required=False)

    class Meta:
        model = Task
        fields = ['title', 'description', 'due_date', 'priority', 'photos']
        widgets = {
            'due_date': DatePicker(
                options={
                    'format': 'YYYY-MM-DD HH:mm',  # Adjust the format as needed
                    'showTodayButton': True,
                    # Add any additional options you want to customize the date picker
                },
            ),
        }


class TaskForm(forms.ModelForm):
    # Change the widget to ClearableFileInput
    photos = forms.ImageField(widget=forms.ClearableFileInput(attrs={'multiple': False}), required=False)

    class Meta:
        model = Task
        fields = ['title', 'description', 'due_date', 'priority', 'photos']
        widgets = {
            'due_date': DatePicker(
                options={
                    'format': 'YYYY-MM-DD HH:mm',  # Adjust the format as needed
                    'showTodayButton': True,
                    # Add any additional options you want to customize the date picker
                },
            ),
        }