# API Gateway Integration Guide

Comprehensive integration patterns, event schemas, and webhook configurations for connecting API gateways with external services and internal microservices.

## Table of Contents

1. [Service Discovery Integration](#service-discovery-integration)
2. [Authentication Provider Integration](#authentication-provider-integration)
3. [Monitoring & Observability](#monitoring--observability)
4. [Message Queue Integration](#message-queue-integration)
5. [Service Mesh Integration](#service-mesh-integration)
6. [Webhook Management](#webhook-management)
7. [Event Schemas](#event-schemas)
8. [Third-Party API Integration](#third-party-api-integration)

---

## Service Discovery Integration

### Consul Integration

**Service Registration:**

```python
# consul_service_discovery.py
import consul
import socket

class ConsulServiceDiscovery:
    def __init__(self, consul_host='localhost', consul_port=8500):
        self.consul = consul.Consul(host=consul_host, port=consul_port)
    
    def register_service(self, service_name: str, service_port: int, 
                        health_check_path: str = '/health'):
        """Register a service with Consul."""
        
        service_id = f"{service_name}-{socket.gethostname()}"
        
        check = consul.Check.http(
            f"http://localhost:{service_port}{health_check_path}",
            interval='10s',
            timeout='5s',
            deregister='30s'
        )
        
        self.consul.agent.service.register(
            name=service_name,
            service_id=service_id,
            address=socket.gethostbyname(socket.gethostname()),
            port=service_port,
            check=check,
            tags=['api', 'v1', 'production']
        )
        
        return service_id
    
    def discover_service(self, service_name: str) -> list:
        """Discover healthy instances of a service."""
        
        _, services = self.consul.health.service(
            service_name,
            passing=True
        )
        
        instances = []
        for service in services:
            instances.append({
                'id': service['Service']['ID'],
                'address': service['Service']['Address'],
                'port': service['Service']['Port'],
                'tags': service['Service']['Tags']
            })
        
        return instances
    
    def deregister_service(self, service_id: str):
        """Deregister a service from Consul."""
        self.consul.agent.service.deregister(service_id)
```

**Kong + Consul Integration:**

```yaml
# kong.conf
dns_resolver = 127.0.0.1:8600  # Consul DNS
dns_order = LAST,SRV,A,CNAME

# Service using Consul DNS
services:
  - name: user-service
    url: http://user-service.service.consul:8080
    
  - name: order-service
    url: http://order-service.service.consul:8080
```

### Kubernetes Service Discovery

**Kong Ingress Controller:**

```yaml
# kong-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  annotations:
    konghq.com/strip-path: "true"
    konghq.com/plugins: rate-limiting, jwt-auth
spec:
  ingressClassName: kong
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /users
            pathType: Prefix
            backend:
              service:
                name: user-service
                port:
                  number: 8080
          
          - path: /orders
            pathType: Prefix
            backend:
              service:
                name: order-service
                port:
                  number: 8080

---
apiVersion: v1
kind: Service
metadata:
  name: user-service
spec:
  selector:
    app: user-api
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 8080
```

---

## Authentication Provider Integration

### Auth0 Integration

**JWT Validation with Auth0:**

```python
# auth0_integration.py
import httpx
import jwt
from functools import lru_cache
from typing import Optional

class Auth0Integration:
    def __init__(self, domain: str, audience: str):
        self.domain = domain
        self.audience = audience
        self.algorithms = ['RS256']
    
    @lru_cache(maxsize=1)
    def get_jwks(self) -> dict:
        """Fetch JSON Web Key Set from Auth0."""
        response = httpx.get(f"https://{self.domain}/.well-known/jwks.json")
        return response.json()
    
    def get_signing_key(self, token: str) -> str:
        """Extract signing key from JWKS."""
        unverified_header = jwt.get_unverified_header(token)
        jwks = self.get_jwks()
        
        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        
        raise Exception('Signing key not found')
    
    def verify_token(self, token: str) -> Optional[dict]:
        """Verify and decode Auth0 JWT token."""
        try:
            signing_key = self.get_signing_key(token)
            
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=f"https://{self.domain}/"
            )
            
            return payload
        except Exception as e:
            print(f"Token verification failed: {e}")
            return None
```

**Kong Plugin Configuration:**

```yaml
plugins:
  - name: openid-connect
    config:
      issuer: "https://your-tenant.auth0.com/"
      client_id: "your_client_id"
      client_secret: "your_client_secret"
      scopes:
        - openid
        - profile
        - email
      auth_methods:
        - bearer
      bearer_only: true
```

### Okta Integration

```python
# okta_integration.py
import httpx
from typing import Optional

class OktaIntegration:
    def __init__(self, domain: str, api_token: str):
        self.domain = domain
        self.api_token = api_token
        self.base_url = f"https://{domain}/api/v1"
    
    async def verify_access_token(self, token: str) -> Optional[dict]:
        """Verify access token with Okta introspection endpoint."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/oauth2/default/v1/introspect",
                data={'token': token, 'token_type_hint': 'access_token'},
                headers={'Authorization': f'SSWS {self.api_token}'}
            )
            
            data = response.json()
            
            if data.get('active'):
                return data
            
            return None
    
    async def get_user_info(self, access_token: str) -> Optional[dict]:
        """Retrieve user information using access token."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/oauth2/default/v1/userinfo",
                headers={'Authorization': f'Bearer {access_token}'}
            )
            
            if response.status_code == 200:
                return response.json()
            
            return None
```

---

## Monitoring & Observability

### Prometheus Integration

**Kong Prometheus Plugin:**

```yaml
plugins:
  - name: prometheus
    config:
      per_consumer: true
      status_code_metrics: true
      latency_metrics: true
      bandwidth_metrics: true
      upstream_health_metrics: true
```

**Custom Metrics Exporter:**

```python
# prometheus_exporter.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time

class GatewayMetrics:
    def __init__(self):
        # Request metrics
        self.request_count = Counter(
            'gateway_requests_total',
            'Total number of requests',
            ['method', 'route', 'status']
        )
        
        self.request_duration = Histogram(
            'gateway_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'route'],
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
        )
        
        # Rate limiting metrics
        self.rate_limit_exceeded = Counter(
            'gateway_rate_limit_exceeded_total',
            'Number of rate limit exceeded responses',
            ['route', 'client_id']
        )
        
        # Circuit breaker metrics
        self.circuit_breaker_state = Gauge(
            'gateway_circuit_breaker_state',
            'Circuit breaker state (0=closed, 1=open, 2=half-open)',
            ['service']
        )
        
        # Cache metrics
        self.cache_hits = Counter(
            'gateway_cache_hits_total',
            'Number of cache hits',
            ['route']
        )
        
        self.cache_misses = Counter(
            'gateway_cache_misses_total',
            'Number of cache misses',
            ['route']
        )
    
    def record_request(self, method: str, route: str, status: int, duration: float):
        """Record request metrics."""
        self.request_count.labels(method=method, route=route, status=status).inc()
        self.request_duration.labels(method=method, route=route).observe(duration)
    
    def record_rate_limit(self, route: str, client_id: str):
        """Record rate limit exceeded event."""
        self.rate_limit_exceeded.labels(route=route, client_id=client_id).inc()
    
    def update_circuit_breaker_state(self, service: str, state: int):
        """Update circuit breaker state."""
        self.circuit_breaker_state.labels(service=service).set(state)

# Start metrics server
if __name__ == '__main__':
    metrics = GatewayMetrics()
    start_http_server(9090)
```

### Jaeger Distributed Tracing

**OpenTelemetry Integration:**

```python
# tracing.py
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

def setup_tracing(service_name: str):
    """Initialize distributed tracing with Jaeger."""
    
    resource = Resource.create({"service.name": service_name})
    
    jaeger_exporter = JaegerExporter(
        agent_host_name="jaeger-agent",
        agent_port=6831,
    )
    
    provider = TracerProvider(resource=resource)
    processor = BatchSpanProcessor(jaeger_exporter)
    provider.add_span_processor(processor)
    
    trace.set_tracer_provider(provider)
    
    # Auto-instrument HTTP clients
    HTTPXClientInstrumentor().instrument()
    
    return trace.get_tracer(__name__)

# Usage in gateway
tracer = setup_tracing("api-gateway")

@app.middleware("http")
async def trace_requests(request, call_next):
    with tracer.start_as_current_span(
        f"{request.method} {request.url.path}",
        attributes={
            "http.method": request.method,
            "http.url": str(request.url),
            "http.client_ip": request.client.host
        }
    ) as span:
        response = await call_next(request)
        span.set_attribute("http.status_code", response.status_code)
        return response
```

### ELK Stack Integration

**Structured Logging:**

```python
# logging_config.py
import logging
import json
from datetime import datetime

class StructuredLogger:
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.logger = logging.getLogger(service_name)
        
        handler = logging.StreamHandler()
        handler.setFormatter(self.JsonFormatter())
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'message': record.getMessage(),
                'logger': record.name,
            }
            
            if hasattr(record, 'request_id'):
                log_data['request_id'] = record.request_id
            
            if hasattr(record, 'user_id'):
                log_data['user_id'] = record.user_id
            
            if record.exc_info:
                log_data['exception'] = self.formatException(record.exc_info)
            
            return json.dumps(log_data)
    
    def log_request(self, request_id: str, method: str, path: str, 
                   status: int, duration_ms: float, user_id: str = None):
        """Log gateway request."""
        extra = {
            'request_id': request_id,
            'user_id': user_id,
            'method': method,
            'path': path,
            'status': status,
            'duration_ms': duration_ms
        }
        
        self.logger.info(
            f"{method} {path} {status} {duration_ms}ms",
            extra=extra
        )
```

---

## Message Queue Integration

### Kafka Integration for Async Processing

```python
# kafka_integration.py
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
import json
from typing import Dict, Any

class KafkaGatewayIntegration:
    def __init__(self, bootstrap_servers: str):
        self.bootstrap_servers = bootstrap_servers
        self.producer = None
    
    async def initialize(self):
        """Initialize Kafka producer."""
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        await self.producer.start()
    
    async def publish_event(self, topic: str, event: Dict[str, Any]):
        """Publish gateway event to Kafka."""
        await self.producer.send(topic, event)
    
    async def publish_request_log(self, request_data: dict):
        """Publish request log for analytics."""
        event = {
            'timestamp': request_data['timestamp'],
            'request_id': request_data['request_id'],
            'method': request_data['method'],
            'path': request_data['path'],
            'status': request_data['status'],
            'duration_ms': request_data['duration_ms'],
            'user_id': request_data.get('user_id'),
            'ip_address': request_data['ip_address']
        }
        
        await self.publish_event('gateway.requests', event)
    
    async def publish_rate_limit_event(self, client_id: str, route: str):
        """Publish rate limit exceeded event."""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'rate_limit_exceeded',
            'client_id': client_id,
            'route': route
        }
        
        await self.publish_event('gateway.rate_limits', event)
    
    async def shutdown(self):
        """Cleanup Kafka producer."""
        await self.producer.stop()
```

### RabbitMQ Integration

```python
# rabbitmq_integration.py
import aio_pika
import json

class RabbitMQIntegration:
    def __init__(self, amqp_url: str):
        self.amqp_url = amqp_url
        self.connection = None
        self.channel = None
    
    async def connect(self):
        """Establish connection to RabbitMQ."""
        self.connection = await aio_pika.connect_robust(self.amqp_url)
        self.channel = await self.connection.channel()
        
        # Declare exchanges
        await self.channel.declare_exchange(
            'gateway.events',
            aio_pika.ExchangeType.TOPIC,
            durable=True
        )
    
    async def publish_webhook_event(self, webhook_id: str, event_type: str, payload: dict):
        """Publish webhook event for delivery."""
        
        message = aio_pika.Message(
            body=json.dumps(payload).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            headers={
                'webhook_id': webhook_id,
                'event_type': event_type
            }
        )
        
        exchange = await self.channel.get_exchange('gateway.events')
        await exchange.publish(
            message,
            routing_key=f'webhook.{event_type}'
        )
```

---

## Service Mesh Integration

### Istio Integration

**Virtual Service Configuration:**

```yaml
# istio-gateway.yaml
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: api-gateway
spec:
  selector:
    istio: ingressgateway
  servers:
    - port:
        number: 443
        name: https
        protocol: HTTPS
      tls:
        mode: SIMPLE
        credentialName: api-gateway-cert
      hosts:
        - api.example.com

---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: user-service-routes
spec:
  hosts:
    - api.example.com
  gateways:
    - api-gateway
  http:
    - match:
        - uri:
            prefix: /api/users
      route:
        - destination:
            host: user-service
            port:
              number: 8080
            subset: v1
          weight: 90
        - destination:
            host: user-service
            port:
              number: 8080
            subset: v2
          weight: 10
      retries:
        attempts: 3
        perTryTimeout: 2s
        retryOn: 5xx,reset,connect-failure
      timeout: 10s
      fault:
        delay:
          percentage:
            value: 0.1
          fixedDelay: 5s

---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: user-service
spec:
  host: user-service
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 50
        http2MaxRequests: 100
    loadBalancer:
      simple: LEAST_REQUEST
    outlierDetection:
      consecutiveErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
  subsets:
    - name: v1
      labels:
        version: v1
    - name: v2
      labels:
        version: v2
```

---

## Webhook Management

### Webhook System

```python
# webhook_manager.py
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
import httpx
import asyncio
from datetime import datetime

class WebhookConfig(BaseModel):
    id: str
    url: HttpUrl
    secret: str
    events: List[str]  # ['request.completed', 'rate_limit.exceeded']
    active: bool = True
    retry_policy: dict = {
        'max_retries': 3,
        'backoff_seconds': 60
    }

class WebhookManager:
    def __init__(self):
        self.webhooks = {}
    
    def register_webhook(self, config: WebhookConfig):
        """Register a new webhook."""
        self.webhooks[config.id] = config
    
    async def trigger_webhook(self, event_type: str, payload: dict):
        """Trigger all webhooks subscribed to event type."""
        
        tasks = []
        for webhook_id, config in self.webhooks.items():
            if event_type in config.events and config.active:
                task = self._deliver_webhook(config, event_type, payload)
                tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _deliver_webhook(self, config: WebhookConfig, 
                               event_type: str, payload: dict):
        """Deliver webhook with retry logic."""
        
        webhook_payload = {
            'event': event_type,
            'timestamp': datetime.utcnow().isoformat(),
            'data': payload
        }
        
        headers = {
            'Content-Type': 'application/json',
            'X-Webhook-Signature': self._generate_signature(
                config.secret,
                webhook_payload
            )
        }
        
        max_retries = config.retry_policy['max_retries']
        backoff = config.retry_policy['backoff_seconds']
        
        async with httpx.AsyncClient() as client:
            for attempt in range(max_retries):
                try:
                    response = await client.post(
                        str(config.url),
                        json=webhook_payload,
                        headers=headers,
                        timeout=10.0
                    )
                    
                    if response.status_code < 500:
                        return
                    
                except Exception as e:
                    print(f"Webhook delivery failed: {e}")
                
                # Exponential backoff
                await asyncio.sleep(backoff * (2 ** attempt))
    
    def _generate_signature(self, secret: str, payload: dict) -> str:
        """Generate HMAC signature for webhook verification."""
        import hmac
        import hashlib
        import json
        
        message = json.dumps(payload, sort_keys=True).encode()
        signature = hmac.new(
            secret.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        
        return f"sha256={signature}"
```

---

## Event Schemas

### Request Completed Event

```json
{
  "event_type": "request.completed",
  "timestamp": "2026-02-11T10:00:00Z",
  "request_id": "req_abc123",
  "data": {
    "method": "POST",
    "path": "/api/users",
    "status_code": 201,
    "duration_ms": 45,
    "user_id": "user_123",
    "client_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "upstream_service": "user-service",
    "cache_status": "miss"
  }
}
```

### Rate Limit Exceeded Event

```json
{
  "event_type": "rate_limit.exceeded",
  "timestamp": "2026-02-11T10:00:00Z",
  "data": {
    "client_id": "api_key_xyz789",
    "route": "/api/users",
    "limit": 100,
    "window": "1m",
    "requests_made": 101,
    "reset_at": "2026-02-11T10:01:00Z"
  }
}
```

### Circuit Breaker Opened Event

```json
{
  "event_type": "circuit_breaker.opened",
  "timestamp": "2026-02-11T10:00:00Z",
  "data": {
    "service": "order-service",
    "failure_count": 5,
    "failure_threshold": 5,
    "timeout_seconds": 60
  }
}
```

### Authentication Failed Event

```json
{
  "event_type": "auth.failed",
  "timestamp": "2026-02-11T10:00:00Z",
  "request_id": "req_def456",
  "data": {
    "reason": "invalid_token",
    "path": "/api/users",
    "client_ip": "192.168.1.100",
    "token_type": "jwt"
  }
}
```

---

## Third-Party API Integration

### Stripe Payment Gateway

```python
# stripe_integration.py
import httpx
from typing import Optional

class StripeGatewayIntegration:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.stripe.com/v1"
    
    async def validate_webhook_signature(self, payload: bytes, 
                                        signature: str, secret: str) -> bool:
        """Validate Stripe webhook signature."""
        import hmac
        import hashlib
        
        expected_signature = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, f"sha256={expected_signature}")
    
    async def create_payment_intent(self, amount: int, currency: str = "usd",
                                   metadata: dict = None) -> Optional[dict]:
        """Create Stripe payment intent via gateway."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/payment_intents",
                auth=(self.api_key, ""),
                data={
                    'amount': amount,
                    'currency': currency,
                    'metadata': metadata or {}
                }
            )
            
            if response.status_code == 200:
                return response.json()
            
            return None
```

### SendGrid Email Gateway

```python
# sendgrid_integration.py
import httpx

class SendGridGatewayIntegration:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.sendgrid.com/v3"
    
    async def send_email(self, to_email: str, subject: str, 
                        html_content: str) -> bool:
        """Send email via gateway to SendGrid."""
        
        payload = {
            'personalizations': [{
                'to': [{'email': to_email}]
            }],
            'from': {'email': 'noreply@example.com'},
            'subject': subject,
            'content': [{
                'type': 'text/html',
                'value': html_content
            }]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/mail/send",
                json=payload,
                headers={'Authorization': f'Bearer {self.api_key}'}
            )
            
            return response.status_code == 202
```

---

## Best Practices

1. **Circuit Breaker Pattern**: Implement circuit breakers for all external integrations
2. **Retry Logic**: Use exponential backoff for failed requests
3. **Timeout Management**: Set appropriate timeouts for each integration
4. **Monitoring**: Track integration health and performance metrics
5. **Security**: Validate webhooks, encrypt credentials, use mTLS where possible
6. **Rate Limiting**: Respect rate limits of third-party APIs
7. **Idempotency**: Design integrations to be idempotent
8. **Error Handling**: Log errors comprehensively for debugging

---

**Production-ready integrations • Battle-tested patterns • Enterprise-grade reliability**
