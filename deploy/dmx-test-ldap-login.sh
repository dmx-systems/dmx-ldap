declare -a USERS=($1 thiswontwork)

USERNAME='admin'
PASSWORD="${DMX_ADMIN_PASSWORD}"
HOST="https://${WEB_URL}:443/"
## Test access to Administration workspace to ensure login as admin was successful.
URL='core/topic/uri/dmx.workspaces.administration'
# URL='access-control/user/workspace'
BASE64="$( echo -n "${USERNAME}:${PASSWORD}" | base64 )"
AUTH="Authorization: Basic ${BASE64}"
#SESSIONID="$( curl -sS -H "${AUTH}" "${HOST}/${URL}" -i 2>&1 | grep ^Set-Cookie: | cut -d';' -f1 | cut -d'=' -f2 )"
SESSION="$( curl -sS -H "${AUTH}" "${HOST}/${URL}" -i 2>&1 )"
HTTPCODE="$( echo "${SESSION}" | grep HTTP | cut -d' ' -f2 )"
echo "HTTPCODE: ${HTTPCODE}"
if [ "${HTTPCODE}" != "200" ]; then
    echo "login ${USERNAME} failed!"
    exit 1
else
    SESSIONID="$( echo "${SESSION}" | grep ^Set-Cookie: | cut -d';' -f1 | cut -d'=' -f2 )"
    echo "login ${USERNAME} successful (SESSIONID: ${SESSIONID})."
fi

## test ldap login
LDAPPASSWORD='testpass'
for user in "${USERS[@]}"; do
    LOGINNAME="$( echo "${user}" | tr '[:upper:]' '[:lower:]' | sed 's/\ /\_/g' )"
    BASE64=$( echo -n "${LOGINNAME}:${LDAPPASSWORD}" | base64 )
    AUTH="Authorization: LDAP ${BASE64}"
    ## Test user creation was successful by checking login and membership in Display Names workspace
    URL='access-control/user/workspace'
    LOGIN_RESPONSE="$( curl -I -sS -H "${AUTH}" "${HOST}/${URL}" )"
    HTTP_CODE="$( echo "${LOGIN_RESPONSE}" | head -n1 | cut -d' ' -f2 )"
    if [ ${HTTP_CODE} -eq 200 ]; then
        SESSION_ID="$( echo "${LOGIN_RESPONSE}" | grep ^Set-Cookie: | cut -d';' -f1 | cut -d'=' -f2 )"
        echo "LDAP login ${user} successful (id=${SESSION_ID})."
    elif [ "${user}" != "thiswontwork" ]; then
        echo "LDAP login ${user} failed! (${HTTP_CODE})"
        exit 1
    else
        echo "LDAP login ${user} failed! (${HTTP_CODE})"
        exit 0
    fi
done
