#!/bin/bash -x
set -e

# Load secrets from various management sources 
# Use them to configure the influxdb database

DOCKER_INFLUXDB_INIT_MODE=${DOCKER_INFLUXDB_INIT_MODE}
DOCKER_INFLUXDB_INIT_USERNAME=${DOCKER_INFLUXDB_INIT_USERNAME}
DOCKER_INFLUXDB_INIT_PASSWORD=${DOCKER_INFLUXDB_INIT_PASSWORD}
DOCKER_INFLUXDB_INIT_ORG=${DOCKER_INFLUXDB_INIT_ORG}
DOCKER_INFLUXDB_INIT_BUCKET=${DOCKER_INFLUXDB_INIT_BUCKET}
DOCKER_INFLUXDB_INIT_RETENTION=${DOCKER_INFLUXDB_INIT_RETENTION}
DOCKER_INFLUXDB_INIT_ADMIN_TOKEN=${DOCKER_INFLUXDB_INIT_ADMIN_TOKEN}
CONFIG_NAME=${CONFIG_NAME}
# Setup InfluxDB using the `setup` command
influx setup --name ${CONFIG_NAME} --bucket ${DOCKER_INFLUXDB_INIT_BUCKET} -t ${DOCKER_INFLUXDB_INIT_ADMIN_TOKEN} -o ${DOCKER_INFLUXDB_INIT_ORG}  --username="${DOCKER_INFLUXDB_INIT_USERNAME}" --password="${DOCKER_INFLUXDB_INIT_PASSWORD}" --host=http://influxdb:8086 -f

## Custom Setup
CUSTOM_BUCKET=coreData
CUSTOM_ORG=coreOrg
CUSTOM_USER=edgeCoreUser
CUSTOM_PASSWORD=edgeCoreUsersPassword

# Create a Custom Organization
influx org create -n ${CUSTOM_ORG} --host=http://influxdb:8086 -t ${DOCKER_INFLUXDB_INIT_ADMIN_TOKEN}

# Create a Custom Bucket, in the Org with retention policy of 24 hours
influx bucket create -n ${CUSTOM_BUCKET} -o ${CUSTOM_ORG} -r 24h --host=http://influxdb:8086 -t ${DOCKER_INFLUXDB_INIT_ADMIN_TOKEN}

# Create a Custom User 
influx user create -n ${CUSTOM_USER} -p ${CUSTOM_PASSWORD} -o ${CUSTOM_ORG} --host=http://influxdb:8086 -t ${DOCKER_INFLUXDB_INIT_ADMIN_TOKEN}