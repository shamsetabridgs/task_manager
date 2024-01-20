from rest_framework import serializers
from .models import User, Photo, Task

class UserLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model        = User
        fields       = '__all__'
        extra_kwargs = {'password' : {'write_only' : True}, }

class ObtainTokenSerializer(serializers.Serializer):
    username = serializers.CharField(style={
        'placeholder' : "Email",
    },help_text = 'Please enter your email')
    password = serializers.CharField()

class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class UserRegistrationSerializer(serializers.Serializer):
    email            = serializers.CharField(required = True)
    username         = serializers.CharField(required = False)
    password         = serializers.CharField(required = True, min_length = 8)
    confirm_password = serializers.CharField(required = True)

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in used.")
        return value
    
    class Meta:
        exclude = ('password',)





class OTPVerifySerializer(serializers.Serializer):
    otp   = serializers.IntegerField(required = True)
    email = serializers.CharField(required = True, style = {"placeholder" : "Email"},  help_text = "Please enter your email")


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.CharField(required = True, style = {"placeholder" : "Email"}, help_text = "Please enter your email")


class SetPasswordValidatorTokenSerializer(serializers.Serializer):
    token = serializers.CharField(required = True)


class SetPasswordSerializer(serializers.Serializer):
    new_password     = serializers.CharField(required = True, min_length = 8)
    confirm_password = serializers.CharField(required = True)




class PhotoSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Photo
        fields = '__all__'

class TaskSerializer(serializers.ModelSerializer):
    photos = PhotoSerializer(many=True, read_only=True)

    class Meta:
        model  = Task
        fields = '__all__'