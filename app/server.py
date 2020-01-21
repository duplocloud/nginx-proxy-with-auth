from flask import Flask, jsonify, make_response, redirect, request, session
import json
import requests
from flask_cors import CORS
from flask_session import Session
import os

app = Flask(__name__)
SESSION_COOKIE_NAME = 'duplo_auth_proxy_session'
SESSION_TYPE = 'filesystem'
SESSION_FILE_DIR = '/project/flask_cookie'
secret = os.environ.get('FLASK_APP_SECRET')
SECRET_KEY = secret.encode()

app.config.from_object(__name__)

CORS(app)
Session(app)

auth_provider = os.environ.get('OAUTH_PROVIDER')

rules_detail = os.environ.get('ACCESS_RULES')
rules_detail = rules_detail.replace("'", '"')
rules = []
if rules_detail:
    rules = json.loads(rules_detail)

allowed_email_ids = os.environ.get('ALLOWED_EMAIL_IDS')
allowed_email_id_list = []

if allowed_email_ids:
    allowed_email_id_list = allowed_email_ids.split(";")

class InvalidUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


@app.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@app.route('/duplo_auth')
def welcome():
    return jsonify({
            'messsage': "Flask app is running",   # from cognito pool
        })

@app.route("/duplo_auth/login", endpoint='login')
def login():
    is_allowed = False
    proxy_home_uri = os.environ.get('PROXY_HOME_URI')

    if request.args.get('duplo_sso_token'):
        session['duplo_sso_token'] = request.args.get('duplo_sso_token')

    if 'duplo_sso_token' in session and session['duplo_sso_token']:
        # print("login -- using token from session")
        is_allowed = authorize_user(session['duplo_sso_token'])
    else:
        # print("going to other block")
        raise InvalidUsage('No Permission to view this page', status_code=403)

    if is_allowed:
        response = make_response(redirect('/' + proxy_home_uri))
        return response
    else:
        raise InvalidUsage('No Permission to view this page', status_code=403)

@app.route('/duplo_auth/auth')
def api_private():
    # print("auth function invoked")
    is_allowed = False
    if 'duplo_sso_token' in session and session['duplo_sso_token']:
        is_allowed = authorize_user(session['duplo_sso_token'])
    else:
        raise InvalidUsage('No Permission to view this page', status_code=403)

    if is_allowed:
        return jsonify({
            'valid_user': True,   # from cognito pool
        })
    else:
        raise InvalidUsage('No Permission to view this page', status_code=403)


def authorize_user(duplo_sso_token):
    duplo_auth_url = os.environ.get('DUPLO_AUTH_URL')
    duplo_auth_token = os.environ.get('DUPLO_AUTH_TOKEN')
    is_allowed = False

    duplo_auth_headers = {
        'Authorization': 'Bearer ' + duplo_sso_token
    }
    duplo_userinfo_response = requests.get(duplo_auth_url + "/admin/GetUserRoleInfo", headers=duplo_auth_headers)
    userinfo = {}
    if duplo_userinfo_response.status_code == 200:
        print("Userinfo api success response", duplo_userinfo_response.json())
        userinfo = duplo_userinfo_response.json()
    else:
        return False

    if duplo_auth_token:
        duplo_auth_headers = {
            'Authorization': 'Bearer ' + duplo_auth_token
        }
        duplo_isadmin_response = requests.get(duplo_auth_url + "/admin/IsUserAdminAnonymous/" + userinfo['Username'], headers=duplo_auth_headers)
        duplo_tenant_response = requests.get(duplo_auth_url + "/admin/GetTenantsForUserAnonymous/" + userinfo['Username'], headers=duplo_auth_headers)

        is_duplo_admin = False
        allowed_tenants = []

        if duplo_isadmin_response.status_code == 200:
            print("Admin api success response", duplo_isadmin_response.json())
            is_duplo_admin = duplo_isadmin_response.json()

        if duplo_tenant_response.status_code == 200:
            print("tenant api success response", duplo_tenant_response.json())
            allowed_tenants = duplo_tenant_response.json()

        print(type(is_duplo_admin), type(allowed_tenants))
        for rule in rules:
            if rule["role"] == "admin" and is_duplo_admin:
                is_allowed = True
            elif rule["role"] == "user" and rule["tenant"] in allowed_tenants:
                is_allowed = True

            if is_allowed:
                break
    elif userinfo['Username'] in allowed_email_id_list:
        is_allowed = True
    return is_allowed
