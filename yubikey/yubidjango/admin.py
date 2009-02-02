
from django.contrib import admin
from yubikey.yubidjango.models import Yubikey
from yubikey.yubidjango.forms import YubikeyForm

class YubikeyAdmin(admin.ModelAdmin):
    model = Yubikey
    form = YubikeyForm
    fields = ('user', 'public_id', 'aes_key', 'secret_id', 'passcode', 'passcode_confirm', 'remarks', 'is_active',)
    list_display = ('public_id', 'user', 'is_active', 'created_at', 'modified_at')
    list_filter = ('is_active',)

admin.site.register(Yubikey, YubikeyAdmin)
