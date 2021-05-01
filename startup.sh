#!/bin/bash

mkdir -m 777 -p /project/flask_cookie
# sed -ie "s|<PROXY_SERVER_URI>|$PROXY_SERVER_URI|g" /etc/nginx/conf.d/flask-site-nginx.conf
sed -ie "s|<PROXY_SERVER_URI>|$PROXY_SERVER_URI|g" /etc/nginx/nginx.conf

/usr/sbin/nginx