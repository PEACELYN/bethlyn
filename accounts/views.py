from django.shortcuts import render,redirect
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

from .models import AppUser
from .forms import RegistrationForm
from carts.views import _cart_id
from carts.models import Cart, CartItem
from orders.models import Order

# send email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

import requests

# Create your views here.

#  ## Register FUNCTIONALITY

def register(request):
    if request.method =='POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            firstname = form.cleaned_data['firstname']
            lastname = form.cleaned_data['lastname']
            phonenumber = form.cleaned_data['phonenumber']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split('@')[0]
            user  = AppUser.objects.create_user(firstname=firstname, lastname=lastname,email=email,username=username,password=password)
            user.phonenumber = phonenumber
            user.save()

            # User sending email and activation key generation
            current_url = get_current_site(request)
            email_subject = "Please activate your account"
            email_message = render_to_string('accounts/accountverification.html',{
                "user":user,
                "domain":current_url,
                "uid":urlsafe_base64_encode(force_bytes(user.pk)),
                "token":default_token_generator.make_token(user)
            })    
            registering_user_email = email
            send_email = EmailMessage(email_subject, email_message, to=[registering_user_email])
            send_email.send()
            # End of user email sending

            # messages.success(request, f"Thank you for registering with us, We have sent a verification email to {registering_user_email}.")

            return redirect('/accounts/login/?command=verify&email='+registering_user_email)
    else:
        form = RegistrationForm()
    
    context = {
        'form':form
    }
    return render(request, 'accounts/register.html', context)



#  ## LOGIN FUNCTIONALITY

def login(request):
    if request.method == "POST":
        email =request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)

        if user is not None:
            try:
                cart = Cart.objects.get(cart_id=_cart_id(request))
                is_cart_item_exists = CartItem.objects.filter(cart=cart).exists()

                if is_cart_item_exists:
                    cart_item = CartItem.objects.filter(cart=cart)

                    product_variation = []
                    for item in cart_item:
                        variation = item.variations.all()
                        product_variation.append(list(variation))   

                    # get the cart item from the user to access his product variation
                    cart_item = CartItem.objects.filter(user=user)
                    ex_var_list = []
                    id=[]
                    for item in cart_item:
                        existing_variation = item.variations.all() 
                        ex_var_list.append(list(existing_variation))
                        id.append(item.id)

                    for pr in product_variation:
                        if pr in ex_var_list:
                            index = ex_var_list.index(pr)
                            item_id = id[index]
                            item = CartItem.objects.get(id=item_id)
                            item.quantity += 1
                            item.user = user 
                            item.save()
                        else:
                            cart_item = CartItem.objects.filter(cart=cart)
                            for item in cart_item:
                                item.user = user 
                                item.save()
            except:
                pass
            auth.login(request, user)
            messages.success(request,'You are logged in successfully')

            url = request.META.get("HTTP_REFERER")
            try:
                query = requests.utils.urlparse(url).query
                params = dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextPage = params['next']
                    return redirect(nextPage)
            except:
                return redirect('dashboard')

        else:
            messages.error(request, "Invalid Login Credentials")
            return redirect('login')
    return render(request, 'accounts/login.html')


#  ## LOGOUT FUNCTIONALITY

@login_required(login_url = 'login')
def logout(request):
    auth.logout(request)
    messages.success(request, "You are logged out.")
    return redirect('login')



#  ## ACTIVATE FUNCTIONALITY

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = AppUser._default_manager.get(pk=uid)

    except(TypeError,ValueError,OverflowError, AppUser.DoesNotExist):
        user=None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active=True
        user.save()
        messages.success(request,"Congratulations!, Your account is activated.")
        return redirect('login')
    else:
        messages.error(request, 'Invalid activation link')
        return redirect('register')



#  ## DASHBOARD FUNCTIONALITY

@login_required(login_url = 'login')
def dashboard(request):
    orders = Order.objects.order_by('-created_at').filter(user_id=request.user.id, is_ordered=True)
    orders_count = orders.count()
    context = {
        'orders_count':orders_count
    }
    return render(request,'accounts/dashboard.html', context)


# Password reset Functionality
def passwordreset(request):
    if request.method =='POST':
        email = request.POST['email']
        if AppUser.objects.filter(email=email).exists():
            user = AppUser.objects.get(email__exact=email)

            # User sending email and activation key generation
            current_url = get_current_site(request)
            email_subject = "Reset your password"
            email_message = render_to_string('accounts/reset_password_email.html',{
                "user":user,
                "domain":current_url,
                "uid":urlsafe_base64_encode(force_bytes(user.pk)),
                "token":default_token_generator.make_token(user)
            })    
            registering_user_email = email
            send_email = EmailMessage(email_subject, email_message, to=[registering_user_email])
            send_email.send()
            # End of user email sending

            messages.success(request, "An email has been sent to reset your password.")
            return redirect('login')
        else:
            messages.error(request, 'Account does not exists')
            return redirect('passwordreset')

    return render(request, 'accounts/passwordreset.html')



def resetpassword_validate(request,uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = AppUser._default_manager.get(pk=uid)

    except(TypeError,ValueError,OverflowError, AppUser.DoesNotExist):
        user=None

    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid 
        messages.success(request,"Please reset your password")
        return redirect('changepassword')

    else:
        messages.error(request,'This link has expired!')
        return redirect("login")



def changePassword(request):
    if request.method == "POST":
        password = request.POST['password']
        confirmpassword = request.POST['confirmpassword']

        if password == confirmpassword:
            uid = request.session.get('uid')
            user = AppUser.objects.get(pk=uid)
            user.set_password(password)
            user.save() 
            messages.success(request,"Password reset successful")
            return redirect("login")
        else:
            messages.error(request,'Password does not match!')
            return redirect('changepassword')
    else:
        return render(request, 'accounts/changepassword.html')


def my_orders_page(request):
    orders = Order.objects.filter(user=request.user, is_ordered=True).order_by('-created_at')
    context = {
        'orders':orders,
    }
    return render(request, 'accounts/my_orders.html', context)