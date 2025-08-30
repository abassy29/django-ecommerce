from django.db import models
#import AbstractBaseUser from django.contrib.auth.models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from phonenumber_field.modelfields import PhoneNumberField
# Create your models here.

class CustomUserManager(BaseUserManager):

    def create_user(self, email, name, password=None, phone_number=None, **extra_fields):
        
        if not email:
            raise ValueError("The Email field must be set")
        if not name:
            raise ValueError("The Name field must be set")


        email = self.normalize_email(email)
        user = self.model(email=email, name=name,phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, name, password=None, **extra_fields):

        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, name, password, **extra_fields)



class User(AbstractBaseUser , PermissionsMixin):
    email= models.EmailField(unique=True ,null=False, blank=False)
    name= models.CharField(max_length=50 , null=False, blank=False)
    phone_number= PhoneNumberField(null=True, blank=True, unique=True)
    is_active= models.BooleanField(default=True)
    is_staff= models.BooleanField(default=False)
    is_superuser= models.BooleanField(default=False)
    is_verified= models.BooleanField(default=False)

    date_joined= models.DateTimeField(auto_now_add=True)

    
    objects= CustomUserManager()


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return f"{self.email} - {self.name}"
    