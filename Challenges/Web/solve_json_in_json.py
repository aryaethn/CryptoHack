import json
import jwt


def create_session(username):
    body = '{' \
            + '"admin": "' + "False" \
            + '", "username": "' + str(username) \
            + '"}'
    print(json.loads(body))


create_session("hello")
create_session('{"admin": "True"}')
