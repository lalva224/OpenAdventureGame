from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

#we want to override some things from token authentication to use http only cookies
class HttpOnlyAuthentication(TokenAuthentication):
    def get_auth_token_from_cookie(self,request):
        return request.COOKIES.get('token')
    
    def authenticate(self,request):
        #all we're doing different is getting the auth token from cookie instead of from request header
        auth_token = self.get_auth_token_from_cookie(request)

        if not auth_token:
            return None
        
        #use their same exact authenticate credentials method
        return self.authenticate_credentials(auth_token)
