ARG NODE_VERSION=16
FROM node:${NODE_VERSION}

# Home directory for Node-RED application source code.
RUN mkdir -p /usr/src/node-red

# User data directory, contains flows, config and nodes.
RUN mkdir /data
RUN mkdir /data/csv
RUN chmod -R 777 /data/csv

WORKDIR /usr/src/node-red

# package.json contains Node-RED NPM module and node dependencies
COPY package.json /usr/src/node-red/
COPY flows.json /data/flows.json
COPY flows_cred.json /data/flows_cred.json
COPY settings.js /data/settings.js

RUN npm install

# User configuration directory volume
EXPOSE 1880

# Environment variable holding file path for flows configuration
ENV FLOWS=flows.json
ENV NODE_PATH=/usr/src/node-red/node_modules:/data/node_modules

CMD ["npm", "start", "--", "--userDir", "/data"]
