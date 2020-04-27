import jwt
from flask import request, jsonify, g

from config import SECRET


def login_required(func):
    def wrapper(*args, **kwargs):
        access_token = request.headers.get('Authorization', None)

        if access_token:
            try:
                payload = jwt.decode(access_token, SECRET['secret_key'], algorithm=SECRET['algorithm'])
                account_no = payload['account_no']

                db_connection = DatabaseConnection()
                if db_connection:
                    try:
                        with db_connection as db_cursor:
                            get_account_info_stmt = ("""
                                SELECT auth_type_id, is_deleted FROM accounts WHERE account_no=%(account_no)s
                            """)
                            db_cursor.execute(get_account_info_stmt, {'account_no': account_no})
                            account = db_cursor.fetchone()
                            if account:
                                if account['is_deleted'] == 0:
                                    g.account_info = {
                                        'account_no': account_no,
                                        'auth_type_id': account['auth_type_id']
                                    }
                                    return func(*args, **kwargs)
                                return jsonify({'message': 'DELETED_ACCOUNT'}), 400
                            return jsonify({'message': 'ACCOUNT_DOES_NOT_EXIST'}), 404

                    except Error as e:
                        print(f'DATABASE_CURSOR_ERROR_WITH {e}')
                        return jsonify({'message': 'DB_CURSOR_ERROR'}), 400

            except jwt.InvalidTokenError:
                return jsonify({'message': 'INVALID_TOKEN'}), 401

            return jsonify({'message': 'NO_DATABASE_CONNECTION'}), 400
        return jsonify({'message': 'INVALID_TOKEN'}), 401
    return wrapper
