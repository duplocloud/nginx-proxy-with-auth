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

    oauth_client_id = os.environ.get('OAUTH_CLIENT_ID')
    oauth_client_secret = os.environ.get('OAUTH_CLIENT_SECRET')
    app_redirect_host = os.environ.get('APP_REDIRECT_HOST')
    proxy_home_uri = os.environ.get('PROXY_HOME_URI')

    if auth_provider == 'google':
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        payload = 'grant_type=authorization_code&client_id=' + oauth_client_id + '&redirect_uri=' + app_redirect_host + '/duplo_auth/login&code=' + request.args.get('code') + '&client_secret=' + oauth_client_secret
        post_response = requests.post("https://www.googleapis.com/oauth2/v4/token", headers=headers, data = payload)

        if post_response.status_code == 200:
            token_details = post_response.json()
            print("Access token got from google")

            user_info_response = requests.get("https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" + token_details['id_token'])
            print("user info response status code", user_info_response.status_code)

            if user_info_response.status_code == 200:
                user_details = user_info_response.json()
                if user_details['email_verified'] == 'true' and user_details['email']:
                    session['email'] = user_details['email']
    else:
        microsoft_ad_dir_id = os.environ.get('MICROSOFT_AD_DIRECTORY_ID')
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        payload = 'grant_type=authorization_code&client_id=' + oauth_client_id + '&redirect_uri=' + app_redirect_host + '/duplo_auth/login&code=' + request.args.get('code') + '&resource=https%3a%2f%2fgraph.windows.net%2f&client_secret=' + oauth_client_secret
        post_response = requests.post("https://login.microsoftonline.com/" + microsoft_ad_dir_id + "/oauth2/token", headers=headers, data = payload)

        if post_response.status_code == 200:
            token_details = post_response.json()
            print("Access token got")
            user_info_headers = {
                'Authorization': 'Bearer ' + token_details['access_token']
            }
            user_info_response = requests.get("https://graph.windows.net/" + microsoft_ad_dir_id + "/me?api-version=1.6", headers=user_info_headers)
            print("user info response status code", user_info_response.status_code)
            print(json.dumps(user_info_response.json()))

            if user_info_response.status_code == 200:
                user_details = user_info_response.json()
                session['email'] = user_details['userPrincipalName']
                print("user details got setting email to sessoin ", session['email'])

    response = make_response(redirect('/' + proxy_home_uri))
    return response

@app.route('/duplo_auth/auth')
def api_private():
    # user must have valid cognito access or ID token in header
    # (accessToken is recommended - not as much personal information contained inside as with idToken)
    duplo_auth_url = os.environ.get('DUPLO_AUTH_URL')
    duplo_auth_token = os.environ.get('DUPLO_AUTH_TOKEN')

    is_allowed = False
    if 'email' in session and session['email']:
        if duplo_auth_token:
            duplo_auth_headers = {
                'Authorization': 'Bearer ' + duplo_auth_token
            }
            duplo_isadmin_response = requests.get(duplo_auth_url + "/admin/IsUserAdminAnonymous/" + session['email'], headers=duplo_auth_headers)
            duplo_tenant_response = requests.get(duplo_auth_url + "/admin/GetTenantsForUserAnonymous/" + session['email'], headers=duplo_auth_headers)

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
        elif session['email'] in allowed_email_id_list:
            is_allowed = True

    else:
        raise InvalidUsage('This view is gone', status_code=401)

    if is_allowed:
        return jsonify({
            'valid_user': True,   # from cognito pool
        })
    else:
        raise InvalidUsage('No Permission to view this page', status_code=403)
