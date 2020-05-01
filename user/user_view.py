from flask import Blueprint, jsonify
from flask_request_validator import (
    JSON,
    Param,
    Pattern,
    MaxLength,
    MinLength,
    validate_params
)
from .user_service import UserService


class UserView:
    user_app = Blueprint('user_app', __name__, url_prefix='/user')

    @user_app.route("", methods=["POST"], endpoint='sign_up')
    @validate_params(
        Param('full_name', JSON, str, required=True),
        Param('email', JSON, str, required=True,
              rules=[Pattern(r'^[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*@[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*.[a-zA-Z]{2,3}$')]),
        Param('password', JSON, str,
              rules=[MaxLength(80)]),
        Param('password', JSON, str,
              rules=[MinLength(4)]),
        Param('auth_type_id', JSON, int)
    )
    def sign_up(*args):
        if args[4] not in range(1, 3):
            return jsonify({'message': 'INVALID_AUTH_TYPE'}), 400

        user_info = {
            'full_name': args[0],
            'email': args[1],
            'password': args[3],
            'auth_type_id': args[4]
        }
        user_service = UserService()
        result = user_service.sigh_up(user_info)
        return result

    @user_app.route("/sign-in", methods=["POST"], endpoint='sign_in')
    @validate_params(
        Param('email', JSON, str, required=True,
              rules=[Pattern(r'^[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*@[0-9a-zA-Z]([-_.]?[0-9a-zA-Z])*.[a-zA-Z]{2,3}$')]),
        Param('password', JSON, str,
              rules=[MaxLength(80)]),
        Param('password', JSON, str,
              rules=[MinLength(4)])
    )
    def sign_in(*args):
        user_info = {
            'email': args[0],
            'password': args[2]
        }
        user_service = UserService()
        result = user_service.sign_in(user_info)
        return result

    @user_app.route("/log-out", methods=["POST"], endpoint='log_out')
    @validate_params(
        Param('key', JSON, str),
        Param('token', JSON, str)
    )
    def log_out(*args):
        token_info = {
            'key': args[0],
            'token': args[1]
        }
        user_service = UserService()
        result = user_service.log_out(token_info)
        return result