from django.contrib import admin
from django.urls import path
from simistocks.views import simidata, list_users, update_user, simi_whatsapp, templates, send_wp_msg

urlpatterns = [
    path('simidata', simidata),
    path('list_users', list_users),
    path('update_user', update_user),
    path('simi_whatsapp', simi_whatsapp),
    path('templates', templates),
    path('send_wp_msg', send_wp_msg)
]
