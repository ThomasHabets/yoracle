from django.template import loader, RequestContext
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login
from django.utils.translation import ugettext_lazy as _

from yubikey.yubidjango.models import Yubikey, YUBIKEY_USE_PASSWORD
from yubikey.yubidjango.forms import LoginForm, LoginPasswordForm

def login_view(request, template='yubidjango/login.html'):
    error = None
    
    if YUBIKEY_USE_PASSWORD:
        FormClass = LoginPasswordForm
    else:
        FormClass = LoginForm
    
    if request.method == 'POST':
        form = FormClass(request.POST)
        if form.is_valid():
            user = authenticate(token=form.cleaned_data['token'], password=form.cleaned_data.get('password', None))
            
            if user is not None:
                login(request, user)
                return HttpResponseRedirect('/')
            else:
                if YUBIKEY_USE_PASSWORD:
                    error = _('The Yubikey token or password is incorrect.')
                else:
                    error = _('The Yubikey token is incorrect.')
    else:
        form = FormClass()

    templ = loader.get_template(template)
    cont = RequestContext(request, {'form': form, 'error': error})
    return HttpResponse(templ.render(cont))
