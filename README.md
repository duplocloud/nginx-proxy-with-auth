# nginx-proxy-with-auth

{
    "APP_REDIRECT_HOST": "https://site.domain.com", // this is the container DNS name you newly create for proxy
    "OAUTH_CLIENT_ID": "", // Google/Microsoft oauth client id
    "OAUTH_CLIENT_SECRET": "", // Google/Microsoft oauth client secret
    "FLASK_APP_SECRET": "", // Random string which will be used by flask to generate cookie. The bigger the string the more difficult to guess the cookie value
    "DUPLO_AUTH_URL": "", // Duplo auth service url
    "DUPLO_AUTH_TOKEN": "", // Duplo auth service bearer token
    "PROXY_SERVER_URI": "https://10.167.54.75", // URI of the source site which needs to be proxied
    "OAUTH_PROVIDER": "google", // google/microsoft -- this will be auth provider
    "PROXY_HOME_URI": "app/wazuh", // Any special path which need to be opened at the start
    "ACCESS_RULES": "",
    "ALLOWED_EMAIL_IDS": "", // List of email id who are granted permission. Separated by ';''
    "OAUTH_STATE": "" // unique string which will be validated with oauth authorization_code
}
