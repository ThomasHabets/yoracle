"""
Django models for storing Yubikeys and an optional associated password.

It doesn't use the password field of the Django User model because you could
have multiple keys for one user, each with a different password. This also allows
a fall back to the default Django authentication backend, for example with a
longer password.

The methods for setting the password are copied from the Django User model.
"""

from datetime import datetime
import random

from django.db import models, transaction
from django.contrib.auth.models import User, get_hexdigest, check_password, UNUSABLE_PASSWORD
from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from yubikey import decrypt

YUBIKEY_USE_PASSWORD = getattr(settings, 'YUBIKEY_USE_PASSWORD', False)

class Yubikey(models.Model):
    user = models.ForeignKey(User, verbose_name=_('user'))
    public_id = models.CharField(_('public ID'), max_length=12, help_text=_('ModHex value of 12 characters (ModHex only consists of the characters: "cbdefghijklnrtuv".'), unique=True)
    aes_key = models.CharField(_('AES key'), max_length=32, help_text=_('Hexadecimal value of 32 characters.'))
    secret_id = models.CharField(_('secret ID'), max_length=12, help_text=_('Hexadecimal value of 12 characters'))
    password = models.CharField(_('password'), max_length=128, default=UNUSABLE_PASSWORD, help_text=_('Please set to the value of "%s" if no password is set.' % UNUSABLE_PASSWORD))
    is_active = models.BooleanField(_('is active'), default=True, help_text=_('When disabling a key, please give a reason in the remarks field.'))
    remarks = models.TextField(_('remarks'), blank=True)
    counter = models.PositiveIntegerField(_('counter'), default=0, editable=False, help_text='Last value used by the internal counter (0-65535).')
    counter_session = models.PositiveIntegerField(_('session counter'), default=0, editable=False, help_text='Last value used by the internal session counter (0-256).')
    created_at = models.DateTimeField(_('created at'), default=datetime.now, editable=False)
    modified_at = models.DateTimeField(_('last modified/login at'), default=datetime.now, editable=False)

    class Meta:
        verbose_name = _('yubikey')
        verbose_name_plural = _('yubikeys')

    def __unicode__(self):
        return 'Yubikey "%s" for user %s' % (self.public_id, self.user)

    def save(self):
        self.modified_at = datetime.now()
        super(Yubikey, self).save()

    @transaction.commit_manually
    def check_token(self, token):
        """
        Returns a boolean of whether the provided token is correct. It decrypts
        the token, checks the CRC, checks if the counter(s) are higher then the 
        saved one.
        
        It does NOT check the password, use the "check_password" method.
        When succesful it saves the new counter value to protect against using
        the same token again.

        The transaction is commited manually so exceptions after this check
        will not rollback the new counter values.
        """
        yubikey = decrypt.YubikeyToken(token, self.aes_key)
        if yubikey.crc_ok and ((yubikey.counter > self.counter) or (yubikey.counter == self.counter and yubikey.counter_session > self.counter_session)) and yubikey.secret_id == self.secret_id and yubikey.public_id == self.public_id:
            self.counter = yubikey.counter
            self.counter_session = yubikey.counter_session
            self.save()
            transaction.commit()
            return True
        else:
            return False

    def set_password(self, raw_password):
        algo = 'sha1'
        salt = get_hexdigest(algo, str(random.random()), str(random.random()))[:5]
        hsh = get_hexdigest(algo, salt, raw_password)
        self.password = '%s$%s$%s' % (algo, salt, hsh)

    def check_password(self, raw_password):
        """
        Returns a boolean of whether the raw_password was correct. Handles
        encryption formats behind the scenes.
        """
        if self.has_usable_password():
            return check_password(raw_password, self.password)
        else:
            return False

    def set_unusable_password(self):
        # Sets a value that will never be a valid hash
        self.password = UNUSABLE_PASSWORD

    def has_usable_password(self):
        return self.password != UNUSABLE_PASSWORD

