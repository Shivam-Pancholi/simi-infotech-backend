from django.db import models
from django.contrib.auth.models import User


class Userdata(models.Model):
    user = models.ForeignKey(User, on_delete=models.PROTECT, null=True, blank=True)
    file_name = models.TextField(max_length=2048)
    data = models.JSONField(default=dict)
    whatsapp_account_id = models.CharField(max_length=2048, null=True, blank=True)
    whatsapp_phone_no_id = models.CharField(max_length=2048, null=True, blank=True)
    whatsapp_token = models.CharField(max_length=4096, null=True, blank=True)
    templates = models.JSONField(default=dict)
    template_img = models.FileField(upload_to='documents', blank=True, null=True)
    msg_limit = models.IntegerField(default=0)
    scheme_file_name = models.TextField(null=True, blank=True)
    stock_file_name = models.TextField(null=True, blank=True)
