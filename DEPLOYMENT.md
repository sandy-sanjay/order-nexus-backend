# Deployment checklist for order-nexus-backend

This file documents the required environment variables and deployment steps for production.

Required environment variables (example names):

- SPRING_DATASOURCE_URL: e.g. `jdbc:mysql://<host>:<port>/order_nexus?useSSL=true&requireSSL=true&enabledTLSProtocols=TLSv1.2`
- SPRING_DATASOURCE_USERNAME
- SPRING_DATASOURCE_PASSWORD
- JWT_SECRET

Optional / recommended:
- APP_CORS_ALLOWED_ORIGINS: comma-separated list of allowed origins, example:
  `http://localhost:3000,https://your-frontend.example.com`

Build & Run with Docker (example):

# Build image
docker build -t order-nexus-backend:latest .

# Run container (example with envs)
docker run -d --name order-nexus -p 8080:8080 \
  -e SPRING_DATASOURCE_URL='jdbc:mysql://gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/order_nexus?useSSL=true&requireSSL=true&enabledTLSProtocols=TLSv1.2' \
  -e SPRING_DATASOURCE_USERNAME='your_user' \
  -e SPRING_DATASOURCE_PASSWORD='your_pass' \
  -e JWT_SECRET='replace-with-your-secret' \
  order-nexus-backend:latest

Healthcheck & orchestration:
- The Docker image includes a HEALTHCHECK which queries `/actuator/health`.
- Ensure your cloud platform respects container healthchecks or configure a platform-specific health probe.

Notes:
- **Do NOT store secrets in source control**. Use your cloud provider's secret manager or environment settings to inject values.
- If secrets were committed accidentally, rotate them and consider using BFG/git-filter-repo to remove them from history (I can help if needed).