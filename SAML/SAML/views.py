from onelogin.saml2.auth import OneLogin_Saml2_Auth
from SAML.saml_settings import SAML_SETTINGS
from django.http import HttpResponseRedirect
from django.shortcuts import redirect,render
from django.http import HttpResponse
from django.contrib.auth import logout
from django.views.decorators.csrf import csrf_exempt

def home(request):
    if request.user.is_authenticated:
        print('authenticated')
        return render(request,'welcome.html')
    else:
        print('is not authenticated')
        return render(request,'home.html')

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req,SAML_SETTINGS)
    return auth

def prepare_django_request(request):
    # Prepare the Django request data to be passed to the SAML authentication class
    return {
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'server_port': request.META['SERVER_PORT'],
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy(),
        'https': 'on' if request.is_secure() else 'off',
    }

@csrf_exempt   
def saml_login(request):
    req = prepare_django_request(request)
    auth = init_saml_auth(req)
    return HttpResponseRedirect(auth.login())

@csrf_exempt
def saml_acs(request):
    req = prepare_django_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    print(errors)
    
    if auth.is_authenticated():
        # Do your authentication logic here
        request.session['samlUserdata'] = auth.get_attributes()
        request.session['samlNameId'] = auth.get_nameid()
        return render(request,'welcome.html')
    else:
        print("Last Error Reason: ", auth.get_last_error_reason())
        return HttpResponse("Authentication Failed", status=401)
    
def saml_logout(request):
    req = prepare_django_request(request)
    auth = init_saml_auth(req)
    # return HttpResponseRedirect(auth.logout())
    logout(request)
    return redirect('/')

def saml_logout_complete(request):
    logout(request)
    return redirect('/')