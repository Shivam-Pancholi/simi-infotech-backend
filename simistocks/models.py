from django.db import models
from django.contrib.auth.models import User


class Userdata(models.Model):
    user = models.ForeignKey(User, on_delete=models.PROTECT, null=True, blank=True)
    file_name = models.CharField(max_length=2048)
    data = models.JSONField(default=dict)
