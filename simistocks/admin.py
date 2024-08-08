from django.contrib import admin
from .models import Userdata, Manage_App_Access
from djangoql.admin import DjangoQLSearchMixin
from djangoql.schema import DjangoQLSchema


class UserdataQLSchema(DjangoQLSchema):
    # You can customize this schema to include or exclude certain fields
    include = ['user', 'file_name', 'whatsapp_account_id', 'mobile_number', 'otp_authentication']


class ManageAppAccessQLSchema(DjangoQLSchema):
    include = ['user', 'is_approved', 'fcm_id', 'device_name', 'otp_receiver_number']


@admin.register(Userdata)
class UserdataAdmin(DjangoQLSearchMixin, admin.ModelAdmin):
    list_display = ['user', 'file_name', 'whatsapp_account_id', 'mobile_number', 'otp_authentication']
    search_fields = ['user__username', 'file_name', 'mobile_number', 'whatsapp_account_id']
    djangoql_schema = UserdataQLSchema


@admin.register(Manage_App_Access)
class ManageAppAccessAdmin(DjangoQLSearchMixin, admin.ModelAdmin):
    list_display = ['user', 'is_approved', 'fcm_id', 'device_name', 'otp_receiver_number']
    search_fields = ['user__user__username', 'is_approved', 'fcm_id', 'device_name', 'otp_receiver_number']
    djangoql_schema = ManageAppAccessQLSchema


