FROM node:20-alpine
WORKDIR /app
COPY server/server.js server/server.js
COPY TI4.html TI4.html
ENV PAGE_FILE=/app/TI4.html PORT=8080
EXPOSE 8080
USER node
CMD ["node", "server/server.js"]
