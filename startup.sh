#!/bin/bash -e

sed -ie "s|<PROXY_SERVER_URI>|$PROXY_SERVER_URI|g" /etc/nginx/conf.d/flask-site-nginx.conf
htpasswd -c -b /etc/nginx/.htpasswd $USERNAME $PASSWORD
/usr/sbin/nginx