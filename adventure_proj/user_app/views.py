from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authentication import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from user_app.models import User
from datetime import datetime,timedelta
from .utilities import HttpOnlyAuthentication
# Create your views here.

def create_http_only_cookie_on_response(_response,token):
    life_time = datetime.now() + timedelta(days=1)
    format_life_time = life_time.strftime("%a,%d %b $Y %H:%M:%S EST")


    #TODO : set secure= True when deploying after https set up.
    #give token info as well cookie settings. samesite allows only GET, any other request needs to be allowed in cors settings.
    _response.set_cookie(key="token",value=token.key,httponly=True,secure=False,samesite='Lax',expires=format_life_time)
    return _response

class SignUp(APIView):
    def post(self,request):
        #create user objects, token object
        #get username and password and ensure they are BOTH entered.
        username = request.data.get("username")
        password = request.data.get("password")
        if username and password:
            user = User.objects.create_user(**request.data)
            token = Token.objects.create(user=user)
            _response =  Response({'user':user.username},status=status.HTTP_200_OK)
            return create_http_only_cookie_on_response(_response,token)
        else:
            return Response("Please enter correct credentials",status=status.HTTP_400_BAD_REQUEST)
        

class Login(APIView):
    def post(self,request):
        #retrieve login credentials, authenticate. If authenticated then get or create token.
        username = request.data.get('username')
        password = request.data.get('password')
        #looks in database for user entry matching these credentials. Returns none object if not validated.
        user = authenticate(username=username,password=password)
        if user:
            token,created = Token.objects.get_or_create(user=user)
            #we need to create cookie and token stored in it. First make life time for token
            #strf time to format date time to string. %a for abbreviated weekday %d for day %b for aBBreviated month name %Y year % H hour %S second then manual time zone
            

            if created:
                _response = Response({"user":username},status=status.HTTP_200_OK)
                return create_http_only_cookie_on_response(_response,token)
        else:
            return Response("Please enter correct credentials",status=status.HTTP_400_BAD_REQUEST)
        


class HttpOnlyReq(APIView):
    #overrides drf default authenticate method to grab tokens from http cookies instead of request header
    authentication_classes = [HttpOnlyAuthentication]
    permission_classes = [IsAuthenticated]

class TokenReq(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
class LogOut(HttpOnlyReq):
    #this view should only be available once we are logged in
    

    #simply destroy the token
    def post(self,request):
        request.user.auth_token.delete()
        _response = Response(status=status.HTTP_204_NO_CONTENT)
        _response.delete_cookie("token")
        return _response

