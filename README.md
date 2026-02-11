# API Gateway Architect

A comprehensive AI agent specializing in API gateway design, management, and optimization for modern microservices architectures. Provides expert guidance on routing, authentication, rate limiting, and service mesh integration.

## Overview

API Gateway Architect helps engineering teams design, implement, and optimize API gateway solutions that serve as the single entry point for client requests. It covers everything from initial architecture decisions through production deployment and monitoring.

## Key Features

- **Gateway Architecture Design**: Multi-layer gateway patterns, service mesh integration, edge vs regional gateways
- **Routing & Load Balancing**: Path-based routing, header-based routing, canary deployments, blue-green strategies
- **Authentication & Authorization**: OAuth2/OIDC integration, JWT validation, API key management, mTLS
- **Rate Limiting & Throttling**: Token bucket, leaky bucket, sliding window algorithms, distributed rate limiting
- **Request/Response Transformation**: Protocol translation (REST/gRPC/GraphQL), payload transformation, aggregation
- **Caching Strategies**: Edge caching, CDN integration, cache invalidation patterns
- **Security & Compliance**: WAF integration, DDoS protection, request validation, audit logging
- **Observability**: Distributed tracing, metrics collection, log aggregation, health checks
- **Performance Optimization**: Connection pooling, HTTP/2 & HTTP/3, compression, timeout management

## Tech Stack & Platforms

**Gateway Solutions:**
- Kong Gateway (open-source & enterprise)
- AWS API Gateway (REST, HTTP, WebSocket)
- Azure API Management
- Google Cloud API Gateway
- NGINX Plus
- Traefik
- Envoy Proxy
- Tyk
- KrakenD
- Apache APISIX

**Service Mesh Integration:**
- Istio
- Linkerd
- Consul Connect
- AWS App Mesh

**Supporting Technologies:**
- Redis (rate limiting, caching)
- PostgreSQL (configuration storage)
- Prometheus & Grafana (monitoring)
- Jaeger/Zipkin (distributed tracing)
- ELK Stack (log management)

## Use Cases

### 1. Microservices Gateway
Design a unified API gateway for microservices architecture with service discovery, circuit breaking, and intelligent routing.

### 2. Multi-Region Deployment
Implement geo-distributed gateways with global load balancing and regional failover capabilities.

### 3. Legacy System Modernization
Create API facades for legacy systems while gradually migrating to modern architectures.

### 4. Partner API Management
Build secure, rate-limited APIs for external partners with usage tracking and billing integration.

### 5. GraphQL Federation
Design GraphQL gateway with schema stitching and federated service integration.

## Quick Start

### Example: Kong Gateway with Rate Limiting

```yaml
# kong.yml
_format_version: "3.0"

services:
  - name: user-service
    url: http://user-api:8080
    routes:
      - name: users-route
        paths:
          - /api/users
    plugins:
      - name: rate-limiting
        config:
          minute: 100
          policy: local
      - name: key-auth
      - name: prometheus

  - name: order-service
    url: http://order-api:8080
    routes:
      - name: orders-route
        paths:
          - /api/orders
    plugins:
      - name: rate-limiting
        config:
          minute: 50
          policy: redis
          redis_host: redis
          redis_port: 6379
      - name: jwt
        config:
          key_claim_name: iss
```

### Example: AWS API Gateway with Lambda Integration

```python
# api_gateway_config.py
import boto3

client = boto3.client('apigatewayv2')

# Create HTTP API
response = client.create_api(
    Name='ProductAPI',
    ProtocolType='HTTP',
    CorsConfiguration={
        'AllowOrigins': ['https://example.com'],
        'AllowMethods': ['GET', 'POST', 'PUT', 'DELETE'],
        'AllowHeaders': ['Content-Type', 'Authorization']
    }
)

api_id = response['ApiId']

# Create route with Lambda integration
client.create_integration(
    ApiId=api_id,
    IntegrationType='AWS_PROXY',
    IntegrationUri=f'arn:aws:lambda:us-east-1:123456789:function:ProductHandler',
    PayloadFormatVersion='2.0'
)

# Add JWT authorizer
client.create_authorizer(
    ApiId=api_id,
    AuthorizerType='JWT',
    IdentitySource=['$request.header.Authorization'],
    JwtConfiguration={
        'Audience': ['api.example.com'],
        'Issuer': 'https://auth.example.com'
    },
    Name='JWTAuthorizer'
)
```

### Example: NGINX Reverse Proxy with Rate Limiting

```nginx
# nginx.conf
http {
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req_zone $http_authorization zone=user_limit:10m rate=100r/s;
    
    upstream user_service {
        least_conn;
        server user-api-1:8080 max_fails=3 fail_timeout=30s;
        server user-api-2:8080 max_fails=3 fail_timeout=30s;
    }
    
    upstream order_service {
        server order-api:8080;
    }
    
    server {
        listen 443 ssl http2;
        server_name api.example.com;
        
        ssl_certificate /etc/nginx/certs/api.crt;
        ssl_certificate_key /etc/nginx/certs/api.key;
        
        # User service with rate limiting
        location /api/users {
            limit_req zone=user_limit burst=20 nodelay;
            
            proxy_pass http://user_service;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            
            # JWT validation via auth_request
            auth_request /auth;
            
            # Caching
            proxy_cache api_cache;
            proxy_cache_valid 200 5m;
            add_header X-Cache-Status $upstream_cache_status;
        }
        
        location /api/orders {
            limit_req zone=api_limit burst=5;
            proxy_pass http://order_service;
        }
        
        # Auth subrequest
        location = /auth {
            internal;
            proxy_pass http://auth-service:8080/validate;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
        }
    }
}
```

## Capabilities

### Gateway Selection & Design
- Evaluate gateway solutions based on requirements (scalability, features, cost)
- Design multi-tier gateway architectures (edge, regional, service-level)
- Plan migration strategies from monolithic to gateway-based architectures

### Routing & Traffic Management
- Implement advanced routing (path, header, query parameter, weight-based)
- Design canary deployment and A/B testing strategies
- Configure circuit breakers and fallback mechanisms

### Security Implementation
- Design OAuth2/OIDC authentication flows
- Implement JWT validation and token refresh strategies
- Configure mTLS for service-to-service communication
- Set up API key rotation and management

### Performance Optimization
- Design caching strategies (edge, gateway, service level)
- Optimize connection pooling and keep-alive settings
- Implement request/response compression
- Configure timeouts and retry policies

### Observability & Monitoring
- Set up distributed tracing with correlation IDs
- Implement metrics collection (request rates, latencies, errors)
- Configure health checks and readiness probes
- Design log aggregation and analysis pipelines

## Integration Points

- **Service Discovery**: Consul, etcd, Eureka, Kubernetes DNS
- **Authentication Providers**: Auth0, Okta, Keycloak, AWS Cognito
- **Monitoring Tools**: Prometheus, Grafana, Datadog, New Relic
- **Tracing Systems**: Jaeger, Zipkin, AWS X-Ray, Google Cloud Trace
- **Message Queues**: Kafka, RabbitMQ, AWS SQS (for async processing)
- **Databases**: Redis (caching), PostgreSQL (config), DynamoDB (rate limiting)

## Best Practices

1. **Defense in Depth**: Implement security at multiple layers (gateway, service, data)
2. **Fail Fast**: Use appropriate timeouts and circuit breakers to prevent cascade failures
3. **Idempotency**: Design APIs to be idempotent where possible
4. **Versioning**: Implement API versioning strategy (path, header, or content negotiation)
5. **Documentation**: Maintain OpenAPI/Swagger specs synchronized with gateway configuration
6. **Testing**: Test gateway configurations in staging environments before production
7. **Monitoring**: Track golden signals (latency, traffic, errors, saturation)
8. **Capacity Planning**: Monitor and plan for traffic growth and peak loads

## Common Patterns

### Backend for Frontend (BFF)
Create specialized gateways for different client types (web, mobile, IoT) with tailored responses and aggregation.

### API Composition
Aggregate responses from multiple backend services into a single client response.

### Request/Response Transformation
Transform between different protocols (REST to gRPC) or payload formats (XML to JSON).

### Strangler Fig Pattern
Gradually migrate from legacy systems by routing traffic through the gateway based on feature flags.

## Getting Started

1. **Define Requirements**: Identify traffic patterns, security needs, and integration points
2. **Select Gateway Solution**: Choose based on scale, features, and operational constraints
3. **Design Architecture**: Plan routing, authentication, and observability strategies
4. **Implement Configuration**: Set up gateway with routing rules and plugins
5. **Test Thoroughly**: Load test and security test before production deployment
6. **Monitor & Iterate**: Continuously monitor and optimize based on real traffic patterns

## Resources

- [Kong Gateway Documentation](https://docs.konghq.com/)
- [AWS API Gateway Best Practices](https://docs.aws.amazon.com/apigateway/latest/developerguide/best-practices.html)
- [NGINX Plus as API Gateway](https://www.nginx.com/blog/deploying-nginx-plus-as-an-api-gateway-part-1/)
- [Envoy Proxy Documentation](https://www.envoyproxy.io/docs)
- [API Gateway Pattern - Microsoft](https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway)

## Support

For questions, issues, or feature requests, consult the agent directly with specific gateway architecture challenges or implementation questions.

---

**Built for modern API-first architectures • Optimized for microservices • Production-ready patterns**
