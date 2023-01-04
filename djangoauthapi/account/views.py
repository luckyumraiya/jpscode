from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import (SendPasswordResetEmailSerializer, UserChangePasswordSerializer,
                                 UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer,
                                 UserRegistrationSerializer)
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated


from account.serializers import (TaskMasterSerializer, MenuMasterserializer, UserTaskAccessSerializer,
                                 FieldMasterSerializer, TaskFieldMasterSerializer, MenuGrpSerializer)
# from rest_framework.permissions import IsAuthenticated, AllowAny
# from django.core.mail import send_mail
from .models import MenuGroup, MenuMaster, TaskMaster, User, UserTaskAccess, FieldMaster, TaskFieldMaster
from django.http import Http404
from datetime import date
import socket
from django.shortcuts import render, HttpResponse


# Generate Token Manually


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    # renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({'token': token, 'msg': 'Registration Successful'}, status=status.HTTP_201_CREATED)

    # def get(self, request, pk=None, format=None):
    #     id = pk
    #     if id is not None:
    #         prod = User.objects.get(id=id)
    #         serializer = UserRegistrationSerializer(prod)
    #         return Response(serializer.data)
    #     prod = User.objects.all()
    #     serializer = UserRegistrationSerializer(prod, many=True)
    #     return Response(serializer.data)


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.data.get('username')
        password = serializer.data.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'token': token, 'msg': 'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors': {'non_field_errors': ['Username or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializerl.errors, status=status.HTTP_400_BAD_REQUEST)

    # def get(self, request, pk=None, format=None):
    #     id = pk
    #     if id is not None:
    #         prod = User.objects.get(id=id)
    #         serializer = UserLoginSerializer(prod)
    #         return Response(serializer.data)
    #     prod = User.objects.all()
    #     serializer = UserLoginSerializer(prod, many=True)
    #     return Response(serializer.data)


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Changed Successfully'}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(
            data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Reset Successfully'}, status=status.HTTP_200_OK)


# Company views opertions here.................

class CreateMenuGrpView(APIView):

    def post(self, request, format=None):
        serializer = MenuGrpSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            # token= get_tokens_for_user(user)
            return Response({'msg': 'Saved', 'status': 'success', 'menugroup': serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # renderer_classes =[UserRenderer]
    # def get(self, request, pk=None, format=None):
    #     id = pk
    #     if id is not None:
    #         prod = MenuGroup.objects.get(id=id)
    #         serializer = MenuGrpSerializer(prod)
    #         return Response(serializer.data)
    #     prod = MenuGroup.objects.all()
    #     serializer = MenuGrpSerializer(prod, many=True)
    #     return Response(serializer.data)

    def get(self, request, format=None):
        prod = MenuGroup.objects.all()
        serializer = MenuGrpSerializer(prod, many=True)
        return Response({'status': 'success', 'manugroup': serializer.data}, status=status.HTTP_200_OK)


class UpdateMenuGrpView(APIView):
    def get_object(self, pk):
        try:
            return MenuGroup.objects.get(pk=pk)
        except MenuGroup.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        menugrp = self.get_object(pk)
        serializer = MenuGrpSerializer(menugrp)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        menugrp = self.get_object(pk)
        serializer = MenuGrpSerializer(menugrp, data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({'msg': 'changed'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        menugrp = self.get_object(pk)
        menugrp.delete()
        return Response({'msg': 'Deleted'}, status=status.HTTP_204_NO_CONTENT)


class CreateMenuMasterView(APIView):
    # renderer_classes=[UserRenderer]

    def get(self, request, pk=None, format=None):
        id = pk
        if id is not None:
            prod = MenuMaster.objects.get(id=id)
            serializer = MenuMasterserializer(prod)
            return Response(serializer.data)
        prod = MenuMaster.objects.all()
        serializer = MenuMasterserializer(prod, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = MenuMasterserializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({'msg': 'Created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateMenuMasterView(APIView):
    def get_object(self, pk):
        try:
            return MenuMaster.objects.get(pk=pk)
        except MenuMaster.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        menumaster = self.get_object(pk)
        serializer = MenuMasterserializer(menumaster)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        menumaster = self.get_object(pk)
        serializer = MenuMasterserializer(menumaster, data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({'msg': 'Changed'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        menumaster = self.get_object(pk)
        menumaster.delete()
        return Response({'msg': 'Deleted'}, status=status.HTTP_204_NO_CONTENT)


lastip = socket.gethostbyname(socket.gethostname())
print(type(lastip))


class CreateTaskMasterView(APIView):
    # renderer_classes=[UserRenderer]
    def get(self, request, pk=None, format=None):
        id = pk
        if id is not None:
            prod = TaskMaster.objects.get(id=id)
            serializer = TaskMasterSerializer(prod)
            return Response(serializer.data)
        prod = TaskMaster.objects.all()
        serializer = TaskMasterSerializer(prod, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = TaskMasterSerializer(data=request.data)
        print(serializer)

        if serializer.is_valid(raise_exception=True):
            lastip = socket.gethostbyname(socket.gethostname())
            serializer.lastupdateip = lastip
            user = serializer.save()

            return Response({'msg': 'Created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateTaskMasterView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return TaskMaster.objects.get(pk=pk)
        except TaskMaster.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        taskmaster = self.get_object(pk)
        serializer = TaskMasterSerializer(taskmaster)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        taskmaster = self.get_object(pk)
        serializer = TaskMasterSerializer(taskmaster, data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({'msg': 'Changed'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        taskmaster = self.get_object(pk)
        taskmaster.delete()
        return Response({'msg': 'Deleted'}, status=status.HTTP_204_NO_CONTENT)


class CreateUserTaskAccessView(APIView):
    # renderer_classes=[UserRenderer]

    def get(self, request, pk=None, format=None):
        id = pk
        if id is not None:
            prod = UserTaskAccess.objects.get(id=id)
            serializer = UserTaskAccessSerializer(prod)
            return Response(serializer.data)
        prod = UserTaskAccess.objects.all()
        serializer = UserTaskAccessSerializer(prod, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = UserTaskAccessSerializer(data=request.data)
        # print(serializer.description)
        # lastip = socket.gethostbyname(socket.gethostbyname())
        if serializer.is_valid(raise_exception=True):
            # print(serializer.description)
            user = serializer.save()
            print(user.taskacc)
            return Response({'msg': 'Created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateUserTaskAccessView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return UserTaskAccess.objects.get(pk=pk)
        except UserTaskAccess.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        usertaskaccess = self.get_object(pk)
        serializer = UserTaskAccessSerializer(usertaskaccess)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        usertaskaccess = self.get_object(pk)
        serializer = UserTaskAccessSerializer(
            usertaskaccess, data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({'msg': 'changed'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        usertaskaccess = self.get_object(pk)
        usertaskaccess.delete()
        return Response({'msg': 'Deleted'}, status=status.HTTP_204_NO_CONTENT)


class CreateFieldMasterView(APIView):
    # renderer_classes=[UserRenderer]
    def get(self, request, pk=None, format=None):
        id = pk
        if id is not None:
            prod = FieldMaster.objects.get(id=id)
            serializer = FieldMasterSerializer(prod)
            return Response(serializer.data)
        prod = FieldMaster.objects.all()
        serializer = FieldMasterSerializer(prod, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = FieldMasterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({'msg': 'Created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateFieldMasterView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return FieldMaster.objects.get(pk=pk)
        except FieldMaster.DoesNotExist:
            return Http404

    def get(self, request, pk, format=None):
        fieldmaster = self.get_object(pk)
        serializer = FieldMasterSerializer(fieldmaster)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        fieldmaster = self.get_object(pk)
        serializer = FieldMasterSerializer(fieldmaster, data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({'msg': 'Changed'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        fieldmaster = self.get_object(pk)
        fieldmaster.delete()
        return Response({'msg': 'Deleted'}, status=status.HTTP_204_NO_CONTENT)


class CreateTaskFieldMasterView(APIView):
    # renderer_classes=[UserRenderer]
    def get(self, request, pk=None, format=None):
        id = pk
        if id is not None:
            prod = TaskFieldMaster.objects.get(id=id)
            serializer = TaskFieldMasterSerializer(prod)
            return Response(serializer.data)
        prod = TaskFieldMaster.objects.all()
        serializer = TaskFieldMasterSerializer(prod, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = TaskFieldMasterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({'msg': 'Created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateTaskFieldMasterView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return TaskFieldMaster.objects(pk)
        except TaskFieldMaster.DoesNotExist:
            return Http404

    def get(self, request, pk, format=None):
        taskfieldmaster = self.get_object(pk)
        serializer = TaskFieldMasterSerializer(
            taskfieldmaster, data=request.data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        taskfieldmaster = self.get_object(pk)
        serializer = TaskFieldMasterSerializer(
            taskfieldmaster, data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response({'msg': 'Chenged'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        taskfieldmaster = self.get_object(pk)
        taskfieldmaster.delete()
        return Response({'msg': 'Delete'}, status=status.HTTP_204_NO_CONTENT)
