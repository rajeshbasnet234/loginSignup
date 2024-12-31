from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from base import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str  # Use force_str

from django.contrib.auth import authenticate, login, logout
from .tokens import generate_token

# Create your views here.
def home(request):
    return render(request, "authentication/index.html")

def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        
        # Check if username already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists! Please try another one.")
            return redirect('signup')
        
        # Check if email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered!")
            return redirect('signup')
        
        # Validate username length
        if len(username) > 20:
            messages.error(request, "Username must be under 20 characters!")
            return redirect('signup')
        
        # Validate passwords match
        if pass1 != pass2:
            messages.error(request, "Passwords didn't match!")
            return redirect('signup')
        
        # Validate username to be alphanumeric
        if not username.isalnum():
            messages.error(request, "Username must be alphanumeric!")
            return redirect('signup')
        
        # Create user and send email
        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False  # Account is not active until verified
        myuser.save()

        # Success message
        messages.success(request, "Your account has been created successfully! Please check your email to confirm your email address.")

        # Send Welcome Email
        subject = "Welcome to GFG- Django Login!"
        message = f"Hello {myuser.first_name}, Welcome to GFG! Please confirm your email address."
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Send Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm your Email @ GFG - Django Login!"
        message2 = render_to_string('email_confirmation.html', {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject, message2, settings.EMAIL_HOST_USER, [myuser.email]
        )
        email.fail_silently = True
        email.send()

        return redirect('signin')
    
    return render(request, "authentication/signup.html")


def activate(request, uidb64, token):
    try:
        # Decode the user ID from the URL
        uid = force_str(urlsafe_base64_decode(uidb64))  # Replace force_text with force_str
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None  # If user doesn't exist, set to None
    
    # Check if the user exists and the token is valid
    if myuser and generate_token.check_token(myuser, token):
        myuser.is_active = True  # Activate the user's account
        myuser.save()
        login(request, myuser)  # Log the user in immediately after activation
        messages.success(request, "Your account has been activated!")
        return redirect('signin')
    else:
        messages.error(request, "Activation link is invalid or has expired.")
        return render(request, 'activation_failed.html')


def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']
        
        # Authenticate the user
        user = authenticate(username=username, password=pass1)
        
        if user is not None:
            login(request, user)
            messages.success(request, f"Welcome back, {user.first_name}!")
            return redirect('home')  # Redirect to home after successful login
        else:
            messages.error(request, "Invalid username or password.")
            return redirect('signin')
    
    return render(request, "authentication/signin.html")


def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect('home')  # Redirect to home after logout
