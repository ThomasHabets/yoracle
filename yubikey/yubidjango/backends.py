from django.contrib.auth.backends import ModelBackend

from yubikey.yubidjango.models import Yubikey, YUBIKEY_USE_PASSWORD
from yubikey.decrypt import InvalidToken, InvalidAESKey

class YubikeyBackend(ModelBackend):
    
    def authenticate(self, token=None, password=None):
        public_id = token[:-32]

        # check if token exists
        try:
            yubikey = Yubikey.objects.get(public_id=public_id)
        except Yubikey.DoesNotExist:
            return None

        # check if user and yubikey are active
        if not yubikey.is_active or not yubikey.user.is_active:
            return None

        # check if token is correct
        try:
            if not yubikey.check_token(token):
                return None
        except InvalidToken:
            return None
        except InvalidAESKey:
            return None

        # check if password is correct (when needed)
        if YUBIKEY_USE_PASSWORD:
            if password and yubikey.check_password(password):
                return yubikey.user
            else:
                return None
        else:
            return yubikey.user

