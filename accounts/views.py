from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth.models import User
from .serializers import UserSerializer
from django.conf import settings
import jwt

@api_view(['POST'])
def login_view(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'message': 'Email and password required'}, status=400)

    try:
        user = User.objects.get(email=email)
        if not user.check_password(password):
            return Response({'message': 'Invalid credentials'}, status=401)
    except User.DoesNotExist:
        return Response({'message': 'Invalid credentials'}, status=401)

    refresh = RefreshToken.for_user(user)
    access = refresh.access_token

    response = Response({
        'user': UserSerializer(user).data,
        'access_token': str(access)  # For debugging, remove in production
    })

    # Set cookies with proper domain/path
    response.set_cookie(
        key='refresh_token',
        value=str(refresh),
        httponly=True,
        secure=settings.DEBUG is False,  # True in production
        samesite='Lax' if settings.DEBUG else 'Strict',
        max_age=7 * 24 * 3600,  # 7 days
        path='/refresh/',  # Only sent to refresh endpoint
    )
    
    response.set_cookie(
        key='access_token',
        value=str(access),
        httponly=True,
        secure=settings.DEBUG is False,
        samesite='Lax',
        max_age=15 * 60,  # 15 minutes
        path='/',  # Available to all paths
    )
    
    return response

@api_view(['POST'])
def refresh_token(request):
    refresh_token = request.COOKIES.get('refresh_token')
    
    if not refresh_token:
        return Response({'message': 'Refresh token missing'}, status=401)

    try:
        refresh = RefreshToken(refresh_token)
        user = User.objects.get(id=refresh['user_id'])
        new_access = refresh.access_token
        
        response = Response({
            'user': UserSerializer(user).data
        })
        
        response.set_cookie(
            key='access_token',
            value=str(new_access),
            httponly=True,
            secure=settings.DEBUG is False,
            samesite='Lax',
            domain='localhost',
            max_age=15 * 60,
        )
        return response
        
    except jwt.ExpiredSignatureError:
        return Response({'message': 'Refresh token expired'}, status=401)
    except (jwt.InvalidTokenError, User.DoesNotExist):
        return Response({'message': 'Invalid refresh token'}, status=401)

@api_view(['GET'])
def verify_session(request):
    access_token = request.COOKIES.get('access_token')
    
    if not access_token:
        return Response({'message': 'No access token'}, status=401)

    try:
        access = AccessToken(access_token)
        user = User.objects.get(id=access['user_id'])
        return Response({'user': UserSerializer(user).data})
    except jwt.ExpiredSignatureError:
        return Response({'message': 'Access token expired'}, status=401)
    except (jwt.InvalidTokenError, User.DoesNotExist):
        return Response({'message': 'Invalid access token'}, status=401)