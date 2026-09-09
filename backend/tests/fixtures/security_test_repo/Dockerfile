# SECURITY TEST FIXTURE — Dockerfile
# Intentionally insecure for Phase 6 testing
FROM node:18

# FAKE test secret — synthetic only, not real
ENV API_KEY=TEST_SECRET_DO_NOT_USE_abcdefgh12345

WORKDIR /app
COPY . .
RUN npm install

# Missing USER instruction — runs as root
CMD ["node", "index.js"]
