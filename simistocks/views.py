import requests
from django.shortcuts import render
import ast
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from simistocks.models import Userdata
from rest_framework import parsers, renderers, generics
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
    file_name = user.file_name
    data = user.data
    resp = requests.get("http://simistocks.com/login/%s.json" % file_name)
    resp = resp.json().get("ENVELOPE")
    if resp == data.get("last_updated_data"):
        data = data.get("data")
        return Response(sum(list(data.values()), []))
    db_dict = {}
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
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'admin': user.is_superuser, 'name': user.first_name})


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
                                msg_limit=request.data.get("msg_limit", 1000))
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
                                                                                  "user__first_name")))
    else:
        return Response("You don't have rights to perform this action")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_user(request):
    data = request.data
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
        user.msg_limit = data.get("msg_limit", 1000)
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
    if request.data.get("image") or request.data.get("video") or request.data.get("document"):
        user = Userdata.objects.filter(user__id=request.user.id).last()
        user.template_img = request.data.get('image', request.data.get("video", request.data.get("document")))
        user.save()
        data_url = "https://king-prawn-app-4zv54.ondigitalocean.app/" + user.template_img.url
    data = json.loads(request.data.get("data"))
    if data.get("components") and data.get("name") not in ["only_text", "text_with_image"]:
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
    for numbers in ast.literal_eval(request.data.get("phone_numbers")):
        if data.get("name") in ["only_text", "text_with_image"]:
            if data.get("name") == "only_text":
                payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + str(numbers)),
                                      "type": "template", "template": {"name": "only_text", "language": {"code": "en_US"},
                                                                       "components": [{"type": "body",
                                                                                       "parameters": [{"type": "text",
                                                                                                       "text": request.data.get("free_field_msg")}]}]
                                                         }})
            else:
                payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + str(numbers)),
                                      "type": "template",
                                      "template": {"name": "text_with_image", "language": {"code": "en_US"},
                                                   "components": [{"type": "header", "parameters": [{"type": "image",
                                                                                                     "image": {"link": data_url}}]},
                                                                  {"type": "body", "parameters": [{"type": "text",
                                                                                                   "text": request.data.get(
                                                                                                       "free_field_msg")}]}]
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
        if response.get("messages")[0].get("id"):
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
    whatsapp_account_id = user.whatsapp_account_id
    token = user.whatsapp_token
    url = "https://graph.facebook.com/v15.0/%s/message_templates?access_token=%s" % (whatsapp_account_id, token)
    res = requests.get(url).json()
    return Response({"data": res.get("data")})


@api_view(['GET'])
def send_wp_msg(request):
    data = {"username": request.query_params.get('username'), "password": request.query_params.get('password')}
    res = requests.post("https://simiinfotech.herokuapp.com/login/", json=data)
    if res.json().get("token"):
        payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + str(request.query_params.get('to_send'))),
                              "type": "template", "template": {"name": "only_text", "language": {"code": "en_US"},
                                                               "components": [{"type": "body",
                                                                               "parameters": [{"type": "text",
                                                                                               "text": request.query_params.get(
                                                                                                   "message")}]}]
                                                               }})
        user = Userdata.objects.filter(user__username=request.query_params.get('username')).last()
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
            if not cache.get("msg_%s_%s" % (phone_id, request.query_params.get('to_send'))):
                cache.set("msg_%s_%s" % (phone_id, request.query_params.get('to_send')), "success", 60 * 60 * 24)
                limit_remaining = limit - 1
                user.msg_limit = limit_remaining
                user.save()
        else:
            return Response('ERROR')
        return Response('SUCCESS')
    return Response('ERROR')


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_data(request):
    user = Userdata.objects.filter(user__id=request.user.id).last()
    user.data = {}
    user.save()
    return Response(user.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def exchane_wp_msg(request):
    data_dict = {}
    user = Userdata.objects.filter(user__id=request.user.id).last()
    phone_id = user.whatsapp_phone_no_id
    token = user.whatsapp_token
    url = "https://graph.facebook.com/v15.0/%s/messages" % phone_id
    limit = user.msg_limit
    if limit < len(request.data):
        return Response("Sorry only %s msg is remaining %s" % (limit, len(request.data.get("phone_numbers"))))
    for user in request.data:
        numbers = user.get("K5")
        payload = json.dumps({"messaging_product": "whatsapp", "to": int('91' + str(numbers)),
                              "type": "template", "template": {"name": "", "language": {"code": "en_US"},
                                                               "components": [{"type": "body",
                                                                               "parameters": [{"type": "text",
                                                                                               "text": request.data.get(
                                                                                                   "exchange_value")}]}]
                                                               }})
        headers = {
            'Authorization': 'Bearer %s' % token,
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=payload).json()
        if response.get("messages")[0].get("id"):
            if not cache.get("msg_%s_%s" % (phone_id, numbers)):
                cache.set("msg_%s_%s" % (phone_id, numbers), "success", 60 * 60 * 24)
                data_dict[str(numbers)] = "success"
                limit_remaining = limit - 1
                user.msg_limit = limit_remaining
                user.save()
        else:
            data_dict[str(numbers)] = "error"
    return Response(data_dict)
