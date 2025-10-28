FROM node:24.1.0-alpine3.22 AS build
WORKDIR /srv/onlyoffice-docspace-mcp
COPY app app
COPY lib lib
COPY scripts/build-app.ts scripts/build-app.ts
COPY package.json package.json
COPY pnpm-lock.yaml pnpm-lock.yaml
COPY tsconfig.json tsconfig.json
RUN \
	npm install --global pnpm@10.11.0 && \
	pnpm install --frozen-lockfile && \
	pnpm build-app

FROM node:24.1.0-alpine3.22
LABEL org.opencontainers.image.authors="Ascensio System SIA <integration@onlyoffice.com>"
LABEL org.opencontainers.image.url="https://github.com/onlyoffice/docspace-mcp/"
LABEL org.opencontainers.image.documentation="https://github.com/onlyoffice/docspace-mcp/blob/v3.0.0/README.md"
LABEL org.opencontainers.image.source="https://github.com/onlyoffice/docspace-mcp/"
LABEL org.opencontainers.image.version="3.0.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="ONLYOFFICE DocSpace MCP Server"
LABEL org.opencontainers.image.description="ONLYOFFICE DocSpace Model Context Protocol Server"
ENV NODE_ENV=production
WORKDIR /srv/onlyoffice-docspace-mcp
COPY --from=build /srv/onlyoffice-docspace-mcp/bin bin
COPY LICENSE LICENSE
ENTRYPOINT ["node", "./bin/onlyoffice-docspace-mcp.js"]
