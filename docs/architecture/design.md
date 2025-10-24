# Architecture Design

## System Architecture

```mermaid
graph TD
    subgraph "External"
        Client[Client Application]
    end

    subgraph "API Layer"
        HTTP[HTTP API (Gin)]
        gRPC[gRPC API]
    end

    subgraph "Application Layer"
        AuthService[Auth App Service]
        DeviceService[Device App Service]
    end

    subgraph "Domain Layer"
        TokenService[Token Domain Service]
        CryptoService[Crypto Service]
        RateLimitService[Rate Limit Service]
    end

    subgraph "Infrastructure Layer"
        Postgres[PostgreSQL]
        Redis[Redis]
        Vault[Vault]
    end

    Client --> HTTP
    Client --> gRPC
    HTTP --> AuthService
    gRPC --> AuthService
    AuthService --> TokenService
    AuthService --> DeviceService
    TokenService --> CryptoService
    TokenService --> Postgres
    CryptoService --> Vault
    AuthService --> RateLimitService
    RateLimitService --> Redis
```

## Layers

- **API Layer**: Exposes the system's functionality via HTTP and gRPC.
- **Application Layer**: Orchestrates business logic and coordinates domain services.
- **Domain Layer**: Contains the core business logic, models, and interfaces.
- **Infrastructure Layer**: Implements external concerns like databases, caches, and key management.

## Key Concepts

- **JWTs**: Stateless authentication is achieved using JSON Web Tokens.
- **Key Rotation**: Keys are stored in Vault and can be rotated periodically.
- **Rate Limiting**: A distributed rate limiter built on Redis protects the system.

<!--Personal.AI order the ending-->