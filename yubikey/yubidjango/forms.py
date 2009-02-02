import re

from django import forms
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _

from yubikey.yubidjango.models import Yubikey, YUBIKEY_USE_PASSWORD
from yubikey.decrypt import RE_TOKEN, RE_AES_KEY, InvalidToken, InvalidAESKey

RE_SECRET_ID = re.compile(r'^[0-9a-fA-F]{12}$')
RE_PUBLIC_ID = re.compile(r'^[cbdefghijklnrtuv]{12}$')

class YubikeyForm(forms.ModelForm):
    public_id = forms.RegexField(label=_('Public ID'), regex=RE_PUBLIC_ID, min_length=12, max_length=12, error_messages={'invalid': _('The public ID can only contain the characters "cbdefghijklnrtuv".')})
    aes_key = forms.RegexField(label=_('AES key'), regex=RE_AES_KEY, min_length=32, max_length=32, error_messages={'invalid': _('The AES key must be in hexadecimal encoding.')})
    secret_id = forms.RegexField(label=_('Secret ID'), regex=RE_SECRET_ID, min_length=12, max_length=12, error_messages={'invalid': _('The secret ID must be in hexadecimal encoding.')})
    passcode = forms.CharField(label=_('Password'), min_length=6, required=YUBIKEY_USE_PASSWORD, help_text=_('Leave empty to keep the currect password. A password should have at least 6 characters.'), widget=forms.PasswordInput())
    passcode_confirm = forms.CharField(label=_('Confirm password'), min_length=6, required=YUBIKEY_USE_PASSWORD, widget=forms.PasswordInput())

    class Meta:
        model = Yubikey
        fields = ('user', 'public_id', 'aes_key', 'secret_id', 'remarks', 'is_active',)

    def clean(self):
        if self.cleaned_data.get('passcode') and self.cleaned_data['passcode'] != self.cleaned_data.get('passcode_confirm'):
            raise forms.ValidationError(_('The passwords do not match. Note that passwords are case-sensitive.'))
        return self.cleaned_data

    def save(self, commit=True):
        yubikey = super(YubikeyForm, self).save(commit=commit) 
        if self.cleaned_data['passcode']:
            yubikey.set_password(self.cleaned_data['passcode'])
            yubikey.save()
        return yubikey

class LoginForm(forms.Form):
    token = forms.RegexField(label=_('Yubikey'), regex=RE_TOKEN, min_length=44, max_length=44, error_messages={'invalid': _('The provided token is invalid, please provide a new token.')})

class LoginPasswordForm(LoginForm):
    password = forms.CharField(label=_('Password'), min_length=6, widget=forms.PasswordInput())
