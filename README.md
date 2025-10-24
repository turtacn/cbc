# cbc-auth: Distributed Authentication & Authorization System

`cbc-auth` is a high-performance, distributed identity and access management system designed for large-scale deployments. It provides a secure and scalable solution for authenticating and authorizing devices and services based on OAuth 2.0 and JWT standards.

## Architecture & Features

- **Multi-tenancy**: Securely isolate data and configurations for different tenants.
- **JWT-based Authentication**: Uses JSON Web Tokens for stateless, secure authentication.
- **Key Rotation**: Automated and manual key rotation for enhanced security.
- **Rate Limiting**: Protects the system from abuse with configurable rate limits.
- **Scalable**: Designed to be horizontally scalable to handle high traffic loads.
- **Observable**: Provides metrics, structured logs, and distributed tracing.

## Tech Stack

- **Language**: Go 1.21+
- **Database**: PostgreSQL
- **Cache**: Redis
- **Key Management**: HashiCorp Vault
- **API**: RESTful (Gin) and gRPC
- **Deployment**: Docker & Kubernetes

## Quick Start

### Prerequisites

- Docker
- Docker Compose

### Running Locally

1. **Clone the repository:**
   ```sh
   git clone https://github.com/turtacn/cbc.git
   cd cbc
   ```

2. **Start the services:**
   ```sh
   docker-compose -f deployments/docker/docker-compose.yml up --build
   ```

3. **The service will be available at:**
   - **HTTP API**: `http://localhost:8080`
   - **gRPC API**: `localhost:50051`

## Deployment

The service is designed to be deployed on Kubernetes. See the [Kubernetes deployment guide](./docs/deployment/kubernetes.md) for detailed instructions.

## API Documentation

- [HTTP API](./docs/api/http_api.md)
- [gRPC API](./docs/api/grpc_api.md)

## Configuration

The application is configured via environment variables or a `config.yaml` file. See `internal/config/config.go` for all available options.

## Development

See the [contributing guide](./docs/development/contributing.md) for details on the development process, code style, and contribution guidelines.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

<!--Personal.AI order the ending-->