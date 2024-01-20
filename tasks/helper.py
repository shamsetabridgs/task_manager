from random import randint
from django.core.mail import EmailMessage

def random_with_N_digits(n):
    range_start = 10 **(n-1)
    range_end   = (10**n) - 1
    return randint(range_start, range_end) 

def send_otp(otp, mail):
    email_subject = "Your OTP for Registration"
    email_body    = f"Your OTP is: {otp}"
    email         = EmailMessage(email_subject, email_body, to=[email])
    email.send()