import os
from urllib.parse import urlparse

import requests
from django.http import HttpResponse
from django.shortcuts import render
import ast
import random

from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from simistocks.models import Userdata, Manage_App_Access
from rest_framework import parsers, renderers, generics, status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.compat import coreapi, coreschema
from rest_framework.response import Response
from rest_framework.schemas import ManualSchema
from rest_framework.schemas import coreapi as coreapi_schema
from rest_framework.views import APIView
import copy
import json
from django.core.cache import cache
# from rest_framework import serializers
from django.contrib.auth.models import User
# from rest_framework.validators import UniqueValidator
# from django.contrib.auth.password_validation import validate_password
from datetime import datetime
from rest_framework.parsers import MultiPartParser, FormParser

# class RegisterSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(
#         required=True,
#         validators=[UniqueValidator(queryset=User.objects.all())]
#     )
#
#     password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
#
#     class Meta:
#         model = User
#         fields = ('username', 'password', 'email')
#
#     def create(self, validated_data):
#         user = User.objects.create(
#             username=validated_data['username'],
#             email=validated_data['email'],
#         )
#         user.set_password(validated_data['password'])
#         user.save()
#
#         return user


# class RegisterView(generics.CreateAPIView):
#     queryset = User.objects.all()
#     permission_classes = (AllowAny,)
#     serializer_class = RegisterSerializer


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def simidata(request):
    user = Userdata.objects.filter(user_id=request.user.id).first()
    file_name = (user.file_name).split(",")
    data = user.data
    db_dict = {}
    if not file_name:
        return Response({"message": "No file is linked to this account"},
                        status=status.HTTP_404_NOT_FOUND)
    for file in file_name:
        resp = requests.get("http://simistocks.com/login/%s.json" % file)
        print(resp)
        resp = resp.json().get("ENVELOPE")
        if resp == data.get("last_updated_data"):
            data = data.get("data")
            return Response(sum(list(data.values()), []))
        last_data = copy.deepcopy(resp)
        for k, v in resp.items():
            v["id"] = k.split("_")[1]
            v["row"] = k
            if db_dict.get(v.get('K1')):
                db_dict.get(v.get('K1')).append(v)
            else:
                db_dict[v.get('K1')] = []
                db_dict.get(v.get('K1')).append(v)
            if data:
                if data.get("data").get(v.get('K1')):
                    del data["data"][v.get('K1')]
    if not data:
        data = dict(sorted(db_dict.items(), key=lambda x: datetime.strptime(x[0], '%d-%m-%Y'), reverse=False))
        user.data = {"data": data, "last_updated_data": resp}
    else:
        data.get("data").update(db_dict)
        data = dict(sorted(data.get("data").items(), key=lambda x: datetime.strptime(x[0], '%d-%m-%Y'), reverse=False))
        user.data = {"data": data, "last_updated_data": last_data}
    user.save()
    return Response(sum(list(data.values()), []))


class ObtainAuthToken(APIView):
    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = AuthTokenSerializer

    if coreapi_schema.is_enabled():
        schema = ManualSchema(
            fields=[
                coreapi.Field(
                    name="username",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Username",
                        description="Valid username for authentication",
                    ),
                ),
                coreapi.Field(
                    name="password",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Password",
                        description="Valid password for authentication",
                    ),
                ),
            ],
            encoding="application/json",
        )

    def get_serializer_context(self):
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    def get_serializer(self, *args, **kwargs):
        kwargs['context'] = self.get_serializer_context()
        return self.serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        device_name = ''
        token, created = Token.objects.get_or_create(user=user)
        User_obj = Userdata.objects.filter(user=user).last()
        if request.data.get('clientType') == 'mobile-app':
            print(User_obj)
            user_access = Manage_App_Access.objects.filter(user=User_obj)
            print(user_access)
            if user_access.filter(fcm_id=request.data.get("fcmToken")).exists():
                print(1)
                is_approved = user_access.filter(fcm_id=request.data.get("fcmToken")).last().is_approved
                device_name = user_access.filter(fcm_id=request.data.get("fcmToken")).last().device_name
                user_app_id = user_access.filter(fcm_id=request.data.get("fcmToken")).last().id
                print("1st data", is_approved, device_name, user_app_id)
            else:
                print(2)
                if len(user_access) + 1 <= User_obj.allowed_app_user:
                    user_app = Manage_App_Access.objects.create(user=User_obj, fcm_id=request.data.get("fcmToken"),
                                                     device_details=request.data.get("deviceDetails"))
                    user_app_id = user_app.id
                    is_approved = False
                    print("2", user_app_id, user_app)
                else:
                    print(3)
                    return Response({"message": "Please Contact admin as the limit for allowed user for using app has "
                                                "been reached"},
                                    status=status.HTTP_400_BAD_REQUEST)
            if is_approved:
                print(4)
                return Response({'token': token.key, 'admin': user.is_superuser, 'name': user.first_name,
                                 'is_approved': is_approved, 'device_name': device_name, 'user_app_id': user_app_id,
                                 'access_allowed': user_access.last().access_allowed})
            else:
                print(5)
                return Response({'token': token.key, 'admin': user.is_superuser, 'name': user.first_name,
                                 'is_approved': is_approved, 'device_name': device_name, 'user_app_id': user_app_id},
                                status=status.HTTP_403_FORBIDDEN)
        print(6)
        if User_obj.otp_authentication and User_obj.mobile_number:
            number = random.randint(1111, 9999)
            User_obj.otp = number
            numbers = User_obj.mobile_number
            auth_token = "EAAIgdUrTOEwBALJ7ZBX8cwtCe4Xfo1x8qfBgLwryErWHokEeL2QDmGBxZAJTu0agIw0ZC90vffz18yoyvkSZA9S9ZBSgvYStHPmvz" \
                    "PiVdvqMj16ZAqVn7u9ZBlo2ZAKIYulPWMOZAAF1kvuftENQWtVXzljmFxTpc9PYup6rJTqZBrdAPrYPG95xLU2eQ8XIxBOaW5dN6Z" \
                    "BxRT3ugZDZD"
            url = "https://graph.facebook.com/v15.0/107427908838031/messages"
            payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + str(numbers)),
                                  "type": "template", "template": {"name": "only_text", "language": {"code": "en_US"},
                                                                   "components": [{"type": "body",
                                                                                   "parameters": [{"type": "text",
                                                                                                   "text": "Otp for "
                                                                                                           "verification is "
                                                                                                           "*%s*" % number}]}]
                                                                   }})
            headers = {
                'Authorization': 'Bearer %s' % auth_token,
                'Content-Type': 'application/json'
            }
            response = requests.request("POST", url, headers=headers, data=payload).json()
            User_obj.save()
        if User_obj.otp_authentication:
            return Response({'admin': user.is_superuser, 'name': user.first_name,
                             'access_allowed': User_obj.access_allowed,
                             'otp_authentication': User_obj.otp_authentication, "user_id": user.id})
        return Response({'token': token.key, 'admin': user.is_superuser, 'name': user.first_name,
                         'access_allowed': User_obj.access_allowed, 'otp_authentication': User_obj.otp_authentication})


obtain_auth_token = ObtainAuthToken.as_view()


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register(request):
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        user = User.objects.create(email=request.data.get("email"), username=request.data.get("email"),
                                   first_name=request.data.get("name"))
        user.set_password(request.data.get("password"))
        user.save()
        Userdata.objects.create(user=user, file_name=request.data.get("file_name"),
                                whatsapp_phone_no_id=request.data.get("whatsapp_phone_no_id"),
                                whatsapp_token=request.data.get("whatsapp_token"),
                                whatsapp_account_id=request.data.get("whatsapp_account_id"),
                                msg_limit=request.data.get("msg_limit"),
                                scheme_file_name=request.data.get("scheme_file_name"),
                                stock_file_name=request.data.get("stock_file_name"),
                                allowed_app_user=request.data.get("allowed_app_user"),
                                mobile_number=request.data.get("mobile_number"),
                                otp_authentication=request.data.get("otp_authentication"),
                                access_allowed=request.data.get("access_allowed"),
                                third_party_api=request.data.get("third_party_api")
                                )
        msg = "User Created Successfully"
    else:
        msg = "You don't have rights to perform this action"
    return Response(msg)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_users(request):
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        return Response(list(Userdata.objects.filter(user__is_staff=False).values("user__id", "user__is_active", "file_name", "user__email",
                                                                                  "user__date_joined", "whatsapp_phone_no_id", "whatsapp_token",
                                                                                  "whatsapp_account_id", "msg_limit",
                                                                                  "user__first_name", "stock_file_name",
                                                                                  "scheme_file_name", "allowed_app_user",
                                                                                  "mobile_number", "otp_authentication",
                                                                                  "access_allowed", "third_party_api",
                                                                                  "otp")))
    else:
        return Response("You don't have rights to perform this action")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_user(request):
    data = request.data
    if data.get("blocked_numbers", []):
        user = Userdata.objects.filter(user__id=request.user.id).last()
        user.blocked_number = data.get("blocked_numbers")
        user.save()
        return Response("Blocked number has been updated")
    if data.get("delete", False):
        Userdata.objects.filter(user__id=data.get('id')).delete()
        User.objects.filter(id=data.get('id')).delete()
        return Response("User has been deleted")
    if data.get("password", ''):
        user = User.objects.filter(id=data.get('id')).last()
        user.set_password(data.get("password"))
        user.save()
        return Response("Password has been changed successfully")
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        user = Userdata.objects.filter(user__id=data.get('id')).last()
        user.user.is_active = data.get("is_active")
        user.file_name = data.get("file_name")
        user.user.email = data.get("email")
        user.user.first_name = data.get("name")
        user.whatsapp_token = data.get("whatsapp_token", "")
        user.whatsapp_account_id = data.get("whatsapp_account_id", "")
        user.whatsapp_phone_no_id = data.get("whatsapp_phone_no_id", "")
        user.msg_limit = data.get("msg_limit")
        user.scheme_file_name = data.get("scheme_file_name")
        user.stock_file_name = data.get("stock_file_name")
        user.allowed_app_user = data.get("allowed_app_user")
        user.mobile_number = data.get("mobile_number")
        user.otp_authentication = data.get("otp_authentication", False)
        user.access_allowed = data.get("access_allowed", {})
        user.third_party_api = data.get("third_party_api", "")
        user.user.save()
        user.save()
        return Response("Success")
    else:
        return Response("You don't have rights to perform this action")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def simi_whatsapp(request):
    data_dict, template = {}, {}
    data_url = ""
    limit_remaining = 0
    user = Userdata.objects.filter(user__id=request.user.id).last()
    phone_id = user.whatsapp_phone_no_id
    token = user.whatsapp_token
    url = "https://graph.facebook.com/v15.0/%s/messages" % phone_id
    limit = user.msg_limit
    if limit < len(ast.literal_eval(request.data.get("phone_numbers"))):
        return Response("Sorry only %s msg is remaining %s" % (limit, len(request.data.get("phone_numbers"))))
    data = json.loads(request.data.get("data"))
    if not (request.data.get("image") or request.data.get("video") or request.data.get("document")):
        if data.get("default_file"):
            data_url = data.get("default_file")
    elif request.data.get("image") or request.data.get("video") or request.data.get("document"):
        # user = Userdata.objects.filter(user__id=request.user.id).last()
        user.template_img.delete()
        user.template_img = request.data.get('image', request.data.get("video", request.data.get("document")))
        user.save()
        # data_url = "https://king-prawn-app-4zv54.ondigitalocean.app" + user.template_img.url
        data_url = "https://admin.simiinfotech.com/" + user.template_img.url
        print(data_url)
    if data.get("components") and data.get("name") not in ["only_text", "text_with_image", "text_button_image"]:
        if data.get("components")[0].get('type') == 'HEADER':
            types = data.get("components")[0].get("format")
            if types == 'TEXT':
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")},
                            "components": [{"type": "header", "parameters": [{"type": "text", "text": data.get('text')}]}]}
            elif types == 'IMAGE':
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")},
                            "components": [{"type": "header", "parameters": [{"type": "image", "image": {
                                "link": data_url}}]}]}
            elif types == 'VIDEO':
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")},
                            "components": [{"type": "header", "parameters": [{"type": "video", "video": {
                                "link": data_url}}]}]}
            elif types == 'DOCUMENT':
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")},
                            "components": [{"type": "header", "parameters": [{"type": "document", "document": {
                                "link": data_url, "filename": data.get('filename')}}]}
                                           ]}
            else:
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")}}
    if request.data.get("free_field_msg"):
        text = request.data.get("free_field_msg")
    else:
        if data.get("default_text"):
            text = data.get("default_text")
        else:
            text = ""
    for numbers in ast.literal_eval(request.data.get("phone_numbers")):
        if numbers in user.blocked_number:
            continue
        if data.get("name") in ["only_text", "text_with_image", "text_button_image"]:
            if data.get("name") == "only_text":
                payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + str(numbers)),
                                      "type": "template", "template": {"name": "only_text", "language": {"code": "en_US"},
                                                                       "components": [{"type": "body",
                                                                                       "parameters": [{"type": "text",
                                                                                                       "text": text}]}]
                                                         }})
            else:
                payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + str(numbers)),
                                      "type": "template",
                                      "template": {"name": data.get("name"), "language": {"code": "en_US"},
                                                   "components": [{"type": "header", "parameters": [{"type": "image",
                                                                                                     "image": {"link": data_url}}]},
                                                                  {"type": "body", "parameters": [{"type": "text",
                                                                                                   "text": text}]}]
                                                   }})
        else:
            payload = json.dumps({
              "messaging_product": "whatsapp",
              "to": int('91' + str(numbers)),
              "type": "template",
              "template": template
            })
        headers = {
          'Authorization': 'Bearer %s' % token,
          'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=payload).json()
        if response.get("messages"):
            if response.get("messages")[0]:
                if response.get("messages")[0].get("id", ""):
                    if not cache.get("msg_%s_%s" % (phone_id, numbers)):
                        cache.set("msg_%s_%s" % (phone_id, numbers), "success", 60 * 60 * 24)
                        data_dict[str(numbers)] = "success"
                        limit_remaining = limit - 1
                        user.msg_limit = limit_remaining
                        user.save()
                    else:
                        data_dict[str(numbers)] = "success"
        else:
            data_dict[str(numbers)] = "error"
    return Response(data_dict)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def templates(request):
    user = Userdata.objects.filter(user__id=request.user.id).last()
    if user.third_party_api:
        return Response({"data": [{
      "name": "text_with_image",
      "components": [
        {
          "type": "HEADER",
          "format": "IMAGE",
          "example": {
            "header_handle": []
          }
        },
        {
          "type": "BODY",
          "text": "Hello, \\n{{1}}. \\n\\n*Simi Infotech*.",
          "example": {
            "body_text": [
              [
                "Welcome to simi"
              ]
            ]
          }
        }
      ],
      "language": "en_US",
      "status": "APPROVED",
      "category": "MARKETING",
      "id": "1234159660829621",
      "default_text": "",
      "default_file": ""
    }, {
      "name": "files",
      "components": [
        {
          "type": "HEADER",
          "format": "DOCUMENT",
          "example": {
            "header_handle": []
          }
        },
        {
          "type": "BODY",
          "text": "Hello, \\n{{1}}. \\n\\n*Simi Infotech Alerts*.",
          "example": {
            "body_text": [
              [
                "Welcome to simi Infotech"
              ]
            ]
          }
        }
      ],
      "language": "en_US",
      "status": "APPROVED",
      "category": "MARKETING",
      "id": "739438117579441",
      "default_text": "",
      "default_file": ""
    }, {
      "name": "only_text",
      "components": [
        {
          "type": "BODY",
          "text": "Hello, \\n{{1}}. \\n\\n*Simi Infotech Alerts*.",
          "example": {
            "body_text": [
              [
                "hello"
              ]
            ]
          }
        }
      ],
      "language": "en_US",
      "status": "APPROVED",
      "category": "MARKETING",
      "id": "826005875438677",
      "default_text": "",
      "default_file": ""}], "msg_limit": "Unlimited"})
    whatsapp_account_id = user.whatsapp_account_id
    token = user.whatsapp_token
    default_txt = user.templates.get("msg", "")
    default_img = user.templates.get("img", "")
    msg_limit = user.msg_limit
    url = "https://graph.facebook.com/v15.0/%s/message_templates?access_token=%s" % (whatsapp_account_id, token)
    res = requests.get(url).json()
    for data in res.get("data"):
        data["default_text"] = default_txt
        data["default_file"] = default_img
    return Response({"data": res.get("data"), "msg_limit": msg_limit})


@api_view(['GET'])
def send_wp_msg(request):
    # username = request.query_params.get('username')
    # password = request.query_params.get('password')
    # print(username, password)
    # url = "https://king-prawn-app-4zv54.ondigitalocean.app/login/"
    # payload = json.dumps({
    #     "username": username,
    #     "password": password
    # })
    # headers = {
    #     'Content-Type': 'application/json'
    # }
    # response = requests.request("POST", url, headers=headers, data=payload).json()
    # print(response)
    # if request.query_params.get('token') == "107427908838031" and request.query_params.get('username') == "simiinfotech":
    #     user = Userdata.objects.filter(user__username="kapil",
    #                                    whatsapp_phone_no_id="111935795037601").last()
    # else:
    user = Userdata.objects.filter(user__username=request.query_params.get('username'),
                                   whatsapp_phone_no_id=request.query_params.get('token')).last()
    if not user:
        return Response('Invalid Credentials')
    number_list = request.query_params.get('receiverMobileNo').split(',')
    for number in number_list:
        if number in user.blocked_number:
            continue
        if request.query_params.get('fileurl'):
            a = urlparse(request.query_params.get('fileurl'))
            payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + number), "type": "template","template":
                {"name":"files", "language": {"code": "en_US"}, "components": [{"type": "header",
                                                                               "parameters": [{"type": "document",
                                                                                               "document":
                                                                                                   {"link": request.query_params.get('fileurl'),
                                                                                                    "filename": os.path.basename(a.path)}}]},
                                                                              {"type": "body", "parameters": [{"type": "text","text": request.query_params.get(
                                                                                                       "message", "Please find your attachment above")}]}]}})
        else:
            payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + number),
                                  "type": "template", "template": {"name": "only_text", "language": {"code": "en_US"},
                                                                   "components": [{"type": "body",
                                                                                   "parameters": [{"type": "text",
                                                                                                   "text": request.query_params.get(
                                                                                                       "message")}]}]
                                                                   }})
        phone_id = user.whatsapp_phone_no_id
        token = user.whatsapp_token
        limit = user.msg_limit
        url = "https://graph.facebook.com/v15.0/%s/messages" % phone_id
        headers = {
            'Authorization': 'Bearer %s' % token,
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=payload).json()
        if response.get("messages")[0].get("id"):
            if not cache.get("msg_%s_%s" % (phone_id, number)):
                cache.set("msg_%s_%s" % (phone_id, number), "success", 60 * 60 * 24)
                limit_remaining = limit - 1
                user.msg_limit = limit_remaining
                user.save()
        else:
            return Response('ERROR')
    return Response('SUCCESS')


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_data(request):
    user = Userdata.objects.filter(user__id=request.user.id).last()
    user.data = {}
    user.save()
    return Response(user.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def exchange_wp_msg(request):
    data_dict, template = {}, {}
    data_url = ""
    user = Userdata.objects.filter(user__id=request.user.id).last()
    phone_id = user.whatsapp_phone_no_id
    token = user.whatsapp_token
    url = "https://graph.facebook.com/v15.0/%s/messages" % phone_id
    limit = user.msg_limit
    msg = request.data.get("free_field_msg")
    if limit < len(request.data):
        return Response("Sorry only %s msg is remaining %s" % (limit, len(request.data.get("data"))))
    data = json.loads(request.data.get("template_data"))
    if not (request.data.get("image") or request.data.get("video") or request.data.get("document")):
        if data.get("default_file"):
            data_url = data.get("default_file")
    elif request.data.get("image") or request.data.get("video") or request.data.get("document"):
        # user = Userdata.objects.filter(user__id=request.user.id).last()
        user.template_img.delete()
        user.template_img = request.data.get('image', request.data.get("video", request.data.get("document")))
        user.save()
        data_url = "https://admin.simiinfotech.com" + user.template_img.url
        # data_url = "https://king-prawn-app-4zv54.ondigitalocean.app" + user.template_img.url
        print(data_url)
    if data.get("components") and data.get("name") not in ["only_text", "text_with_image", "text_button_image"]:
        if data.get("components")[0].get('type') == 'HEADER':
            types = data.get("components")[0].get("format")
            if types == 'TEXT':
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")},
                            "components": [
                                {"type": "header", "parameters": [{"type": "text", "text": data.get('text')}]}]}
            elif types == 'IMAGE':
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")},
                            "components": [{"type": "header", "parameters": [{"type": "image", "image": {
                                "link": data_url}}]}]}
            elif types == 'VIDEO':
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")},
                            "components": [{"type": "header", "parameters": [{"type": "video", "video": {
                                "link": data_url}}]}]}
            elif types == 'DOCUMENT':
                a = urlparse(data_url)
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")},
                            "components": [{"type": "header", "parameters": [{"type": "document", "document": {
                                "link": data_url, "filename": os.path.basename(a.path)}}]}
                                           ]}
            else:
                template = {"name": "%s" % data.get("name"), "language": {"code": "%s" % data.get("language")}}
    for users in ast.literal_eval(request.data.get("data")):
        numbers = users.get("K5")
        if numbers in user.blocked_number:
            continue
        if msg.find("{{name}}") >= 0:
            msg = msg.replace("{{name}}", users.get("K4"))
        if msg.find("{{product}}") >= 0:
            msg = msg.replace("{{product}}", users.get("K6"))
        if msg.find("{{value}}") >= 0:
            msg = msg.replace("{{value}}", users.get("exchage_value"))
        if data.get("name") in ["only_text", "text_with_image", "text_button_image"]:
            if data.get("name") == "only_text":
                payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + str(numbers)),
                                      "type": "template",
                                      "template": {"name": "only_text", "language": {"code": "en_US"},
                                                   "components": [{"type": "body",
                                                                   "parameters": [{"type": "text",
                                                                                   "text": msg}]}]
                                                   }})
            else:
                payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + str(numbers)),
                                      "type": "template",
                                      "template": {"name": data.get("name"), "language": {"code": "en_US"},
                                                   "components": [{"type": "header", "parameters": [{"type": "image",
                                                                                                     "image": {
                                                                                                         "link": data_url}}]},
                                                                  {"type": "body", "parameters": [{"type": "text",
                                                                                                   "text": msg}]}]
                                                   }})
        else:
            payload = json.dumps({
                "messaging_product": "whatsapp",
                "to": int('91' + str(numbers)),
                "type": "template",
                "template": template
            })
        headers = {
            'Authorization': 'Bearer %s' % token,
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=payload).json()
        if response.get("messages"):
            if response.get("messages")[0]:
                if response.get("messages")[0].get("id", ""):
                    if not cache.get("msg_%s_%s" % (phone_id, numbers)):
                        cache.set("msg_%s_%s" % (phone_id, numbers), "success", 60 * 60 * 24)
                        data_dict[str(numbers)] = "success"
                        limit_remaining = limit - 1
                        user.msg_limit = limit_remaining
                        user.save()
                    else:
                        data_dict[str(numbers)] = "success"
        else:
            data_dict[str(numbers)] = "error"
    return Response(data_dict)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def default_data(request):
    user = Userdata.objects.filter(user__id=request.user.id).last()
    data_url = None
    if request.data.get("image") or request.data.get("video") or request.data.get("document"):
        # user = Userdata.objects.filter(user__id=request.user.id).last()
        user.template_img.delete()
        user.template_img = request.data.get('image', request.data.get("video", request.data.get("document")))
        user.save()
        # data_url = "https://king-prawn-app-4zv54.ondigitalocean.app" + user.template_img.url
        data_url = "https://admin.simiinfotech.com/" + user.template_img.url
    user.templates = {"msg": request.data.get("msg"), "img": data_url}
    user.save()
    return Response('Data saved successfully')


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_default_data(request):
    return Response(Userdata.objects.filter(user__id=request.user.id).last().templates)


@csrf_exempt
def webhook(request):
    if request.method == 'POST':
        # Get the incoming message data
        data = dict(request.POST)
        print(data)
        sender_id = data.get('From', '')
        message_text = data.get('Body', '')
        print("sender_id", sender_id)
        print("mess", message_text)
        return HttpResponse(str("received"))
    else:
        print(request.GET)
        return HttpResponse(dict(request.GET).get("hub.challenge", {}))


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def simistocksdata(request):
    user = Userdata.objects.filter(user_id=request.user.id).first()
    stock_file_name = user.stock_file_name.split(",")
    scheme_file_name = user.scheme_file_name.split(",")
    db_list = []
    schemes = {}
    if not scheme_file_name:
        return Response({"message": "No file is linked to this account"},
                        status=status.HTTP_404_NOT_FOUND)
    if scheme_file_name:
        for schemes_file in scheme_file_name:
            resp = requests.get("http://simistocks.com/login/%s.json" % schemes_file)
            resp = resp.json().get("ENVELOPE")
            for k, v in resp.items():
                if not (datetime.strptime(v.get("J3"), '%d-%m-%Y').date() <= datetime.now().date() <= datetime.strptime(v.get("J4"), '%d-%m-%Y').date()):
                    continue
                if not schemes.get(v.get("J1")):
                    schemes[v.get("J1")] = []
                    schemes[v.get("J1")].append(v)
                else:
                    schemes[v.get("J1")].append(v)
    for file in stock_file_name:
        resp = requests.get("http://simistocks.com/login/%s.json" % file)
        resp = resp.json().get("ENVELOPE")
        for k, v in resp.items():
            v["id"] = k.split("_")[1]
            v["row"] = k
            v["schemes"] = schemes.get(v.get("c1", ""), [])
            db_list.append(v)
    return Response(db_list)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_app_users(request):
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        return Response(list(Manage_App_Access.objects.all().values("id", "user__user__email", "is_approved", "fcm_id",
                                                                    "access_allowed", "device_name", "device_details")))
    else:
        app_access = Manage_App_Access.objects.filter(user__user_id=request.user.id)
        if app_access:
            return Response(list(app_access.values("id", "user__user__email", "is_approved", "fcm_id", "access_allowed",
                                                                    "device_name", "device_details")))
        return Response("No data Found")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_app_user(request):
    data = request.data
    admin = User.objects.filter(id=request.user.id).last()
    if admin.is_superuser:
        if data.get("delete", False):
            Manage_App_Access.objects.filter(id=data.get('id')).delete()
            return Response("App User has been deleted")
        else:
            app_access = Manage_App_Access.objects.filter(id=data.get("id")).last()
            app_access.is_approved = data.get("is_approved", False)
            app_access.device_name = data.get("device_name")
            app_access.device_details = data.get("device_details")
            app_access.fcm_id = data.get("fcm_id")
            app_access.access_allowed = data.get("access_allowed", {})
        app_access.save()
        return Response("Success")
    else:
        app_access = Manage_App_Access.objects.filter(id=data.get("id")).last()
        if data.get("device_name") and not data.get("is_approved", ""):
            app_access.device_name = data.get("device_name")
            app_access.save()
            return Response("Success")
        elif app_access:
            app_access.is_approved = data.get("is_approved")
            app_access.device_name = data.get("device_name")
            app_access.device_details = data.get("device_details")
            app_access.fcm_id = data.get("fcm_id")
            app_access.access_allowed = data.get("access_allowed")
            app_access.save()
            return Response("Success")
        else:
            return Response("Something Went wrong")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def block_number_details(request):
    user = Userdata.objects.filter(user__id=request.user.id).last()
    return Response({"blocked_numbers": user.blocked_number})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ping(request):
    User_obj = Userdata.objects.filter(user__id=request.user.id).last()
    user_access = Manage_App_Access.objects.filter(user=User_obj)
    if user_access.filter(fcm_id=request.data.get("fcmToken")).exists():
        is_approved = user_access.filter(fcm_id=request.data.get("fcmToken")).last().is_approved
    else:
        is_approved = False
    return Response({"is_approved": is_approved})


@api_view(['POST'])
def validate_otp(request):
    user = User.objects.filter(id=request.data.get("user_id"), username=request.data.get("username")).last()
    if not user:
        Response("Something went wrong", status.HTTP_400_BAD_REQUEST)
    print(user)
    User_obj = Userdata.objects.filter(user=user).last()
    print(User_obj)
    token, created = Token.objects.get_or_create(user=user)
    if int(request.data.get("otp")) == User_obj.otp:
        return Response({'token': token.key, 'admin': user.is_superuser, 'name': user.first_name,
                         'access_allowed': User_obj.access_allowed, 'otp_authentication': User_obj.otp_authentication})
    else:
        return Response("Invalid Otp", status.HTTP_203_NON_AUTHORITATIVE_INFORMATION)
