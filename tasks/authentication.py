from datetime import timedelta,datetime
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed, ParseError

User = get_user_model()

timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
success_message = False

class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        # Extract the JWT from the Authorization header
        #jwt_token = request.Meta.get('HTTP_AUTHORIZATION')
        jwt_token_header = request.headers.get('Authorization')
        if jwt_token_header is None:
            return None
        
        jwt_token = JWTAuthentication.get_the_token_from_header(jwt_token_header)  # clean the token

        # Decode the JWT and verify its signature
        try:
            payload = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=['HS256'])


        except jwt.exceptions.InvalidSignatureError:
            dict_response = {
                "message"  : "Unauthorized",
                "timestamp": timestamp,
                "details"  : [
                    {
                        "path"   : "Authorization",
                        "message": "Invalid signature"
                    }
                ]
            }
            raise AuthenticationFailed(dict_response)
        except jwt.ExpiredSignatureError:
            dict_response = {
                "message"   : "Unauthorized",
                "timestamp" : timestamp,
                "details"   : [
                    {
                        "path"    : "Authorization",
                        "message" : "Token has expired."
                    }
                ]
            }
            raise AuthenticationFailed(dict_response)
        except jwt.InvalidTokenError:
            dict_response = {
                "message"   : "Unauthorized",
                "timestamp" : timestamp,
                "details"   : [
                    {
                        "path"    : "Authorization",
                        "message" : "Invalid Token."
                    }
                ]
            }
            raise AuthenticationFailed(dict_response)
        except:
            dict_response = {
                "message"   : "Unauthorized",
                "timestamp" : timestamp,
                "details"   : [
                    {
                        "path" : "Authorization",
                        "message" : "Malformed request."
                    }
                ]
            }
            raise ParseError(dict_response)
        
        # Get the user from database...........
        username_or_email = payload.get('user_id')
        if username_or_email is None:
            dict_response = {
                "message"   : "Unauthorized",
                "timestamp" : timestamp,
            }
            raise AuthenticationFailed(dict_response)
        
        user = User.objects.filter(id = username_or_email).first()
        if user is None:
            dict_response = {
                "message"   : "Unauthorized",
                "timestamp" : timestamp,
            }
            raise AuthenticationFailed(dict_response)
        
        # Return the user and token payload.........
        return user, payload
    
    def authenticate_header(self, request):
        return 'Bearer'
    
    @classmethod
    def generate_access_token(cls, user):
        # Create the JWT payload
        payload = {
            "user_id" : str(user.id),
            "exp"     : datetime.utcnow() + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            # Set the expiration lifetime for 5 hour from now....
            "iat"     : datetime.now().timestamp(),
        }

        # Encode the JWT with your secret key...............

        jwt_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        return jwt_token
    
    @classmethod
    def generate_refresh_token(cls, user):
        refresh_token_payload = {
            "user_id" : str(user.id),
            "exp"     : datetime.utcnow() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
            "iat"     : datetime.utcnow()
        }
        #refresh_token = jwt.encode(refresh_token_payload, settings.REFRESH_KEY, algorithm='HS256')
        refresh_token = jwt.encode(refresh_token_payload, settings.SIMPLE_JWT['SIGNING_KEY'], algorithm='HS256')
        return refresh_token
    
    @classmethod
    def get_the_token_from_header(cls, token):
        token = token.replace('Bearer', '').replace(' ', '')  # clean the token
        return token