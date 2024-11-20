FROM node:latest AS base

USER node

WORKDIR /home/node/app

COPY package.json ./

RUN npm i

COPY . .

FROM base AS production

ENV NODE_PATH=./build

RUN npm run build

EXPOSE 4000

CMD ["node", "./build/index.js"]