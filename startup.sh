#!/bin/bash -e

oauth_url=""
if [ $OAUTH_PROVIDER = 'google' ]
then
oauth_url="https://accounts.google.com/o/oauth2/v2/auth?scope=openid%20email\&access_type=offline\&include_granted_scopes=true\&state=$OAUTH_STATE\&redirect_uri=$APP_REDIRECT_HOST%2Fduplo_auth%2Flogin\&response_type=code\&client_id=$OAUTH_CLIENT_ID"
else
oauth_url="https://login.microsoftonline.com/$MICROSOFT_AD_DIRECTORY_ID/oauth2/authorize?client_id=$OAUTH_CLIENT_ID\&response_type=code\&redirect_uri=$APP_REDIRECT_HOST/duplo_auth/login\&response_mode=query\&resource=https%3a%2f%2fgraph.windows.net%2f\&state=$OAUTH_STATE"
fi

sed -ie "s|<PROXY_SERVER_URI>|$PROXY_SERVER_URI|g" /etc/nginx/conf.d/flask-site-nginx.conf

sed -ie "s|<OAUTH_AUTHORIZE_URL>|$oauth_url|g" /etc/nginx/conf.d/flask-site-nginx.conf

/usr/sbin/nginx