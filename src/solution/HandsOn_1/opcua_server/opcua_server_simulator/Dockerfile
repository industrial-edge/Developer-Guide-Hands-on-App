FROM node:18.9.0-alpine3.15

RUN mkdir /app

WORKDIR /app

RUN apk --no-cache add \
    openssl=1.1.1q-r0

# package.json contains Node-RED NPM module and node dependencies
COPY package.json .
COPY config.json .
COPY app.js .
COPY server.js .

RUN npm install

# User configuration directory volume
EXPOSE 4841

CMD ["npm", "start"]
