FROM node:22.19.0-bookworm-slim AS node
FROM python:3.13.9-slim-bookworm
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json requirements.txt ./
RUN npm ci --ignore-scripts && python -m pip install --no-cache-dir -r requirements.txt
RUN git init -q /opt/progent \
    && git -C /opt/progent remote add origin https://github.com/sunblaze-ucb/progent.git \
    && git -C /opt/progent fetch --depth=1 origin b02783b896d4bf01a2adf24738015e258db8d35b \
    && git -C /opt/progent checkout --detach FETCH_HEAD
COPY . .
ENV PYTHONHASHSEED=20261106 PYTHONDONTWRITEBYTECODE=1 PROGENT_SOURCE=/opt/progent
ENTRYPOINT ["python", "-m", "pipeline"]
