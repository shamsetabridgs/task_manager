from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractUser
import uuid
from django.utils import timezone
from django.conf import settings

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




class BaseTimeModel(models.Model):
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now     = True)

    class Meta:
        abstract = True



class Task(BaseTimeModel):
    title       = models.CharField(max_length=255)
    description = models.TextField()
    due_date    = models.DateTimeField()
    priority    = models.CharField(max_length=20, choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')])
    is_complete = models.BooleanField(default=False)
    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    photos      = models.ManyToManyField('Photo', blank=True, related_name='tasks_photos')

    def __str__(self):
        return self.title
    
    class Meta:
        ordering = ['-due_date']

class Photo(BaseTimeModel):
    image = models.ImageField(upload_to='task_photos/')
    task  = models.ForeignKey(Task, related_name='task_photos', on_delete=models.CASCADE)

    def __str__(self):
        return f"Photo for Task: {self.task.title}"



