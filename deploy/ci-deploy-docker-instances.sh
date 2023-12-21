#!/bin/bash
##
## This script deploys dmx related docker containers on a 
## gitlab-runner with access to the shell and docker. 
##
## (jpn - 20231212)
##

source deploy/ci-deploy-vars.sh

function mkpw() {
    local LEN="$( shuf -i12-16 -n1 )"
    local PW="$( tr -dc A-Za-z0-9 </dev/urandom | head -c 2 )"
    local PW="${PW}$( pwgen -c -n ${LEN} -1 -y -B -r \?\^\$\.\\~\`\'\*\%\:\<\>\=\/\#\{\}\|\!\@\[\]\"\&\(\) )"
    echo -n "${PW}"
}

if [ -z "${DMX_ADMIN_PASSWORD}" ]; then
    export DMX_ADMIN_PASSWORD="$( mkpw )"
    echo "DMX_ADMIN_PASSWORD=${DMX_ADMIN_PASSWORD}"
fi

if [ -z "${LDAP_ADMIN_PASSWORD}" ]; then
    export LDAP_ADMIN_PASSWORD="$( mkpw )$( mkpw )"
    echo "LDAP_ADMIN_PASSWORD=${LDAP_ADMIN_PASSWORD}"
fi
if [ -z "${DMX_DIRS}" ]; then
    declare -a DMX_DIRS=(conf logs db filedir bundle-deploy bundle-available)
fi

###  before_script ###
echo "TIER=${TIER}"
docker version
docker compose version
docker login -u $CI_REGISTRY_USER -p $CI_JOB_TOKEN $CI_REGISTRY
test -d "${CONFIG_DIR}" || mkdir -p "${CONFIG_DIR}"
test -f "${ENV_FILE}" || touch "${ENV_FILE}"

## dmx instance specific directories
test -d "deploy/instance/${DOCKER_COMPOSE_PROFILE}" || mkdir -p deploy/instance/${DOCKER_COMPOSE_PROFILE}
for dmx_dir in "${DMX_DIRS[@]}"; do
    if [ ! -d deploy/instance/${DOCKER_COMPOSE_PROFILE}/${dmx_dir} ]; then
        mkdir -p deploy/instance/${DOCKER_COMPOSE_PROFILE}/${dmx_dir}
    fi
done

## fetch latest dmxstate.sh script
if [ ! -f deploy/scripts/dmxstate.sh ]; then
    curl --silent https://git.dmx.systems/dmx-contrib/dmx-state/-/raw/master/dmxstate.sh --create-dirs -o deploy/scripts/dmxstate.sh
    chmod +x deploy/scripts/dmxstate.sh
fi

## dmx plugins
test -d deploy/dmx/${DOCKER_COMPOSE_PROFILE}/plugins || mkdir deploy/dmx/${DOCKER_COMPOSE_PROFILE}/plugins
if [ -f deploy/ci-deploy-plugins.list ];  then 
    ## remove (ignore) existing plugins
    find deploy/dmx/${DOCKER_COMPOSE_PROFILE}/plugins/ -type f -name "*.jar" -delete
    PLUGINS="$(<deploy/ci-deploy-plugins.list)"
    declare -a PLUGINS=(${PLUGINS})
else 
    declare -a PLUGINS=()
fi
echo "PLUGINS: ${PLUGINS[@]}"
for plugin in ${PLUGINS[@]}; do
    echo "getting latest version of ${plugin} plugin"
    plugin_version="$( wget -q -O - "${WEBCGI}/ci/${plugin}/${plugin}-latest.jar" )"
    echo "installing ${plugin_version}"
    wget -q "${plugin_version}" -P deploy/dmx/${DOCKER_COMPOSE_PROFILE}/plugins/
done

## copy target
for target in "$( find target/*.jar -type f -name "${CI_PROJECT_NAME}*.jar" )"; do
    echo "copying ${target} file to deploy/dmx/${DOCKER_COMPOSE_PROFILE}/plugins/"
    cp -v ${target} deploy/dmx/${DOCKER_COMPOSE_PROFILE}/plugins/
done

##  script:
USER_ID="$( id -u )"
GROUP_ID="$( id -g )"
DMX_PORT="$( get_port.sh ${WEB_URL}-dmx )"
if [ -z "${DMX_PORT}" ]; then
    echo "ERROR! Could not retrieve the DMX containers proxyport from ${WEB_URL}."
    exit 1
fi
sleep 1
LOGS_PORT="$( get_port.sh ${WEB_URL}-log )"
if [ "$( echo "${PLUGINS[@]}" | grep dmx-sendmail )" ] || [ "$( echo "${target}" | grep dmx-sendmail )" ]; then
    MAIL_PORT="$( get_port.sh ${WEB_URL}-mail )"
    echo "MAIL_PORT=${MAIL_PORT}" >>"${ENV_FILE}"
else
    MAIL_PORT=
    echo "INFO: mailhog not installed."
fi

## save docker environment vars to file
echo "user_id=${USER_ID}" >>"${ENV_FILE}"
echo "group_id=${GROUP_ID}" >>"${ENV_FILE}"
echo "DMX_PORT=${DMX_PORT}" >>"${ENV_FILE}"
echo "LOGS_PORT=${LOGS_PORT}" >>"${ENV_FILE}"
echo "COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME}" >>"${ENV_FILE}"
echo "DEPLOY_PREFIX=${DEPLOY_PREFIX}" >>"${ENV_FILE}"
cat "${ENV_FILE}"
echo "DMX_ADMIN_PASSWORD=${DMX_ADMIN_PASSOWRD}" >>"${ENV_FILE}"
echo "LDAP_ADMIN_PASSWORD=${LDAP_ADMIN_PASSOWRD}" >>"${ENV_FILE}"
echo "dmx.websockets.url = wss://${WEB_URL}/websocket" > deploy/dmx/${DOCKER_COMPOSE_PROFILE}/conf.d/config.properties.d/10_websocket_url
echo "dmx.host.url = https://${WEB_URL}" > deploy/dmx/${DOCKER_COMPOSE_PROFILE}/conf.d/config.properties.d/10_host_url

## get runnung containers
CONTAINERS='dmx dmxlog ldap mailhog'
for cont in ${CONTAINERS}; do
    declare -a DOCKER_IMAGES
    if [ "$( docker container ls | grep ${CI_PROJECT_NAME}-${TIER}-${cont}-container )" ]; then
        DOCKER_IMAGE="$( docker inspect ${CI_PROJECT_NAME}-${TIER}-${cont}-container | jq .[].Config.Image | sed 's/\"//g' )"
        echo "DOCKER_IMAGE=${DOCKER_IMAGE}"
        DOCKER_IMAGES+="${DOCKER_IMAGE}"
    fi
done

## remove containers
docker compose --env-file "${ENV_FILE}" --file deploy/docker-compose.${DOCKER_COMPOSE_PROFILE}.yaml down -v --remove-orphans || true
for DOCKER_IMAGE in ${DOCKER_IMAGES[@]}; do
    for cont in ${CONTAINERS}; do
        if [ "$( docker image ls | grep "${DOCKER_IMAGE}" )" ]; then
            echo "checking ${cont} ${DOCKER_IMAGE} ..."
            if [ "$( docker ps --filter "status=running" --filter "name=dmx" --format "{{.Names}}" | grep ${CI_PROJECT_NAME}-${TIER}-${cont}-container )" ]; then
                docker container stop ${CI_PROJECT_NAME}-${TIER}-${cont}-container || true
                if [ "$( docker container ls -a | grep ${CI_PROJECT_NAME}-${TIER}-${cont}-container )" ]; then 
                    echo "deleting docker container ${CI_PROJECT_NAME}-${TIER}-${cont}-container"
                    docker container rm ${CI_PROJECT_NAME}-${TIER}-${cont}-container || true
                    sleep 1
                fi
                echo "deleting old docker image ${DOCKER_IMAGE}"
                docker image rm ${DOCKER_IMAGE} || true
                sleep 1
            fi
        fi
    done
done

## make sure network is removed
if [ "$( docker network ls | grep "${CI_PROJECT_NAME}-${TIER}_default" )" ]; then
    echo "deleting old docker network ${CI_PROJECT_NAME}-${TIER}_default"
    docker network rm ${CI_PROJECT_NAME}-${TIER}_default || true
    sleep 1
fi

## pull latest images (to keep versions up to date)
docker compose --env-file "${ENV_FILE}" --file deploy/docker-compose.${DOCKER_COMPOSE_PROFILE}.yaml pull
docker compose --env-file "${ENV_FILE}" --file deploy/docker-compose.${DOCKER_COMPOSE_PROFILE}.yaml up --force-recreate -d

## deploy containers
test -d ./deploy/instance/${DOCKER_COMPOSE_PROFILE}/logs/ || echo "ERROR! Directory ./deploy/instance/${DOCKER_COMPOSE_PROFILE}/logs/ not found. Container up?"
deploy/scripts/dmxstate.sh ./deploy/instance/${DOCKER_COMPOSE_PROFILE}/logs/dmx0.log 30 || cat ./deploy/instance/${DOCKER_COMPOSE_PROFILE}/logs/dmx0.log

## TEST
EXTERNAL_TEST_URL="https://${WEB_URL}/core/topic/0"
echo -n "INFO: Testing ${EXTERNAL_TEST_URL} "
count=0
HTTP_CODE="$( curl -s -o /dev/null -w "%{http_code}" ${EXTERNAL_TEST_URL} )"
while [ "${HTTP_CODE}" == "502" -a ${count} -lt 10 ]; do 
    sleep 1; HTTP_CODE="$( curl -s -o /dev/null -w "%{http_code}" ${EXTERNAL_TEST_URL} )"
    echo -n "."; count=$(( ${count} + 1 ))
done
echo " => HTTP_CODE ${HTTP_CODE}"
if [ ${HTTP_CODE} -ne 200 ]; then
    echo "ERROR! HTTP test for ${EXTERNAL_TEST_URL} failed with error code ${HTTP_CODE}."
    exit 1
fi
## run other tests
if [ -d deploy/tests ]; then
    TESTS="$( find deploy/tests/ -type f -name "*.sh" | grep -v *.bak | sort -n )"
else
    TESTS=""
fi
for test in ${TESTS}; do
   echo "Running ${test}."
   source ${test}
done
echo "You can now browse to https://${WEB_URL}/ for testing."

## EOF


