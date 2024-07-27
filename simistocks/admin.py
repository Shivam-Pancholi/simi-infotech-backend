from django.contrib import admin
from .models import Userdata, Manage_App_Access, Whatsapp_Data
from djangoql.admin import DjangoQLSearchMixin
from djangoql.schema import DjangoQLSchema

class UserdataSchema(DjangoQLSchema):
    # Customize your schema here if needed
    pass

class ManageAppAccessSchema(DjangoQLSchema):
    # Customize your schema here if needed
    pass

class WhatsappDataSchema(DjangoQLSchema):
    # Customize your schema here if needed
    pass

@admin.register(Userdata)
class UserdataAdmin(DjangoQLSearchMixin, admin.ModelAdmin):
    list_display = ['user', 'file_name', 'whatsapp_account_id', 'mobile_number', 'otp_authentication']
    search_fields = ['user__username', 'file_name', 'mobile_number', 'whatsapp_account_id']
    djangoql_schema = UserdataSchema

@admin.register(Manage_App_Access)
class ManageAppAccessAdmin(DjangoQLSearchMixin, admin.ModelAdmin):
    list_display = ['user', 'is_approved', 'fcm_id', 'device_name', 'otp_receiver_number']
    search_fields = ['user__user__username', 'fcm_id', 'device_name', 'otp_receiver_number']
    djangoql_schema = ManageAppAccessSchema


@admin.register(Whatsapp_Data)
class WhatsappDataAdmin(DjangoQLSearchMixin, admin.ModelAdmin):
    list_display = ['user', 'module']
    search_fields = ['user__user__username', 'module']
    djangoql_schema = WhatsappDataSchema
