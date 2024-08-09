#!/usr/bin/env python3
"""
Baisc_Auth module for API
"""
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """
        BasicAuth Class
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """"
            extract base64 authorization header
        """
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """"
            decode base64 authorization header
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(
                base64_authorization_header)  # base64 to bytes
            decoded_string = decoded_bytes.decode('utf-8')  # bytes to str
            return decoded_string
        except Exception as e:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """"
            extract user credentials
        """
        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        user, password = decoded_base64_authorization_header.split(':', 1)
        return user, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """
            user object from credentials
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({"email": user_email})

        if not users:
            return None
        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """
            current user
        """
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None

        encoded_credentials = self.extract_base64_authorization_header(
            auth_header)
        if encoded_credentials is None:
            return None

        decoded_credentials = self.decode_base64_authorization_header(
            encoded_credentials)
        if decoded_credentials is None:
            return None

        user_email, user_pwd = self.extract_user_credentials(
            decoded_credentials)
        if user_email is None or user_pwd is None:
            return None

        return self.user_object_from_credentials(user_email, user_pwd)
