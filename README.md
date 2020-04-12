# Version which works with Duplo Session as SSO
This branch is for SSO integration with Duplo, meaning if the user is in Duplo and has admin access then he will have access to the service. It works as follows
1. User hits https://<proxyservice_url>/duplo_auth/login?duplo_sso_token=<Bearertoenfromduplosession>
2. using this token the service check if the user is an admin.

Only the following env is required
    {
        "APP_REDIRECT_HOST": "https://site.domain.com", // this is the container DNS name you newly create for proxy
        "FLASK_APP_SECRET": "", // Random string which will be used by flask to generate cookie. The bigger the string the more difficult to guess the cookie value
        "DUPLO_AUTH_URL": "", // Duplo auth service url
        "PROXY_SERVER_URI": "https://10.167.54.75", // URI of the source site which needs to be proxied
        "PROXY_HOME_URI": "app/wazuh", // Any special path which need to be opened at the start
    }
