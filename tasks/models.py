from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractUser
import uuid
from django.utils import timezone

# Create your models here.


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The email field must be set")
        email = self.normalize_email(email)
        user  = self.model(email=email, id=uuid.uuid4(), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        return self.create_user(email, password, **extra_fields)
    

class User(AbstractUser):
    id          = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email       = models.EmailField(unique= True)
    username    = models.CharField(max_length=48, null=True, blank=True)
    first_name  = models.CharField(max_length= 30, blank=True, null=True)
    last_name   = models.CharField(max_length=30, blank=True, null=True)
    otp         = models.PositiveIntegerField(null = True, blank = True)

    is_active   = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD  = 'email'
    REQUIRED_FIELDS = []

    def __str__(self) -> str:
        return str(self.email)
    
    class Meta:
        db_table = "auth_user"