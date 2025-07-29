@api_view(['GET'])
def verify_session(request):
    access_token = request.COOKIES.get('access_token')
    
    if not access_token:
        return Response({'message': 'No access token'}, status=401)
    
    try:
        access = AccessToken(access_token)
        user = User.objects.get(id=access['user_id'])
        serializer = UserSerializer(user)
        return Response({'user': serializer.data})
    
    except Exception as e:
        return Response({'message': 'Invalid access token'}, status=401)
