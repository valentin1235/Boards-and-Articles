import bcrypt, jwt, uuid

from .user_dao import User, RandomKey
from connection import get_db_connection, get_redis_connection
from config import SECRET

from datetime import datetime, timedelta
from flask import jsonify
from sqlalchemy import exists
from sqlalchemy.orm import sessionmaker


class UserService:
    def sigh_up(self, user_info):
        engine = get_db_connection()
        redis_connection = get_redis_connection()
        user = User()
        random_key = RandomKey()
        try:
            Session = sessionmaker(bind=engine)
            session = Session()

            if session.query(exists().where(User.email == user_info['email'])).one()[0]:
                return jsonify({'message': 'USER_EXISTS'}), 400

            hashed_password = bcrypt.hashpw(user_info.get('password', None).encode('utf-8'), bcrypt.gensalt()).decode()
            user.full_name = user_info['full_name']
            user.email = user_info['email']
            user.password = hashed_password
            user.auth_type_id = user_info['auth_type_id']
            session.add(user)

            # store redis key in db
            random_name = str(uuid.uuid4())
            random_key.key = random_name
            session.add(random_key)

            token = jwt.encode({'id': user.id,
                                'exp': datetime.utcnow() + timedelta(days=6)},
                                SECRET['secret_key'], algorithm=SECRET['algorithm'])

            # store key and token in redis
            redis_connection.set(random_name, token)

            # commit session after all tasks done
            session.commit()

            return jsonify({random_name: token}), 200

        except Exception as e:
            print(e)
            return jsonify({'message': e}), 500

        finally:
                try:
                    session.close()
                except Exception as e:
                    print(e)
                    return jsonify({'message': 'SESSION_CLOSE_ERROR'}), 500

    def sign_in(self, user_info):
        engine = get_db_connection()
        redis_connection = get_redis_connection()
        random_key = RandomKey()
        try:
            Session = sessionmaker(bind=engine)
            session = Session()
            user_info_db = session.query(User.password, User.id).filter(User.email == user_info['email']).all()

            if len(user_info_db) == 0:
                return jsonify({'message': 'USER_NOT_EXISTS'}), 400

            elif bcrypt.checkpw(user_info['password'].encode('utf-8'), user_info_db[0][0].encode('utf-8')):
                token = jwt.encode({'id': user_info_db[0][1],
                    'exp': datetime.utcnow() + timedelta(days=6)},
                    SECRET['secret_key'], algorithm=SECRET['algorithm'])

                # store redis key in db
                random_name = str(uuid.uuid4())
                random_key.key = random_name
                session.add(random_key)

                # store key and token in redis
                redis_connection.set(random_name, token)

                # commit session after all tasks done
                session.commit()

                return jsonify({random_name: token}), 200
            return jsonify({'message': 'INVALID_REQUEST'}), 401

        except Exception as e:
            print(e)
            return jsonify({'message': e}), 500

        finally:
            try:
                session.close()
            except Exception as e:
                print(e)
                return jsonify({'message': 'SESSION_CLOSE_ERROR'}), 500

    def log_out(self, token_info):
        engine = get_db_connection()
        redis_connection = get_redis_connection()
        try:
            Session = sessionmaker(bind=engine)
            session = Session()

            if not session.query(exists().where(RandomKey.key == token_info['key'])).one()[0]:
                return jsonify({'message': 'INVALID_KEY'}), 400

        except Exception as e:
            print(e)
            return jsonify({'message': e}), 500

        finally:
            try:
                session.close()
            except Exception as e:
                print(e)
                return jsonify({'message': 'SESSION_CLOSE_ERROR'}), 500

        key = token_info.get('key', None)
        access_token = token_info.get('token', None)
        if (not key) or (not access_token):
            return jsonify({'message': 'INAVLID_REQUEST'}), 400

        # generate expired token
        payload = jwt.decode(access_token, SECRET['secret_key'], algorithm=SECRET['algorithm'])
        payload['exp'] = datetime.utcnow()
        logged_out_token = jwt.encode(payload, SECRET['secret_key'], algorithm=SECRET['algorithm'])

        # replacing value on allocated key to expired token
        redis_connection.set(key, logged_out_token)
        return jsonify({'message': 'SUCCESS'}), 200