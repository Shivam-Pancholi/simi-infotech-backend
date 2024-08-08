from django.contrib import admin
from django.urls import path
from simistocks.views import simidata, list_users, update_user, simi_whatsapp, templates, send_wp_msg, delete_data, \
    exchange_wp_msg, default_data, get_default_data, webhook, simistocksdata, list_app_users, update_app_user, \
    block_number_details, ping, validate_otp, get_tally_otp, sales, stocks, wa_default_data, wa_send_message, \
    wa_templates, wa_exchange_message, delete_all_my_data

urlpatterns = [
    path('simidata', simidata),
    path('list_users', list_users),
    path('update_user', update_user),
    path('simi_whatsapp', simi_whatsapp),
    path('templates', templates),
    path('send_wp_msg', send_wp_msg),
    path('delete_data', delete_data),
    path('exchange_wp_msg', exchange_wp_msg),
    path('default_data', default_data),
    path('get_default_data', get_default_data),
    path('webhook/<path:last_value>/', webhook),
    path('simistocksdata', simistocksdata),
    path("list_app_users", list_app_users),
    path("update_app_user", update_app_user),
    path("block_number_details", block_number_details),
    path("ping", ping),
    path("validate_otp", validate_otp),
    path("get_tally_otp", get_tally_otp),
    # NEW API
    path('sales', sales),
    path('stocks', stocks),
    path('wa_default_data', wa_default_data),
    path('wa_send_message', wa_send_message),
    path('wa_templates', wa_templates),
    path('wa_exchange_message', wa_exchange_message),
    path('delete_all_my_data', delete_all_my_data),
]
