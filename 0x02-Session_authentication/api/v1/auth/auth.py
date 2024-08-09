#!/usr/bin/env python3
"""
Auth module for API
"""
from typing import TypeVar
from flask import request
from typing import List
from typing import TypeVar


class Auth:
    """
        Auth Class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require Auth"""
        if path is None:
            return True

        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                prefix = excluded_path.rstrip('*')
                if path.startswith(prefix):
                    return False
            elif path == excluded_path:
                return False
            if path.startswith(excluded_path.rstrip('/')):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Authorization Header"""
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """Current User"""
        return None
