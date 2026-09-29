# KryxAI — NBF gateway (trimmed nbf-samplerest clone)
FROM node:18-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY . .

# Fabric peer CA certs / connection profile are bind-mounted at runtime
# (compose maps ./gateway/connection-org1.json -> /config/connection-org1.json
# and ./gateway/wallet -> /config/wallet). CCP_FILE/WALLET_DIR point there.
ENV CCP_FILE=/config/connection-org1.json \
    WALLET_DIR=/config/wallet

EXPOSE 4000
CMD ["node", "server.js"]