# API Gateway Architecture

Comprehensive architectural design patterns, system components, and implementation strategies for enterprise-grade API gateway solutions.

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Core Components](#core-components)
3. [Gateway Patterns](#gateway-patterns)
4. [Data Models](#data-models)
5. [API Contracts](#api-contracts)
6. [Security Architecture](#security-architecture)
7. [Performance & Scalability](#performance--scalability)
8. [Deployment Topologies](#deployment-topologies)

---

## System Architecture

### High-Level Architecture

```
                                    ┌─────────────────┐
                                    │   CDN / Edge    │
                                    │   (CloudFlare)  │
                                    └────────┬────────┘
                                             │
                      ┌──────────────────────┴──────────────────────┐
                      │                                              │
            ┌─────────▼─────────┐                          ┌────────▼────────┐
            │   Load Balancer   │                          │  Load Balancer  │
            │   (US Region)     │                          │  (EU Region)    │
            └─────────┬─────────┘                          └────────┬────────┘
                      │                                              │
         ┌────────────┼────────────┐                    ┌───────────┼────────────┐
         │            │            │                    │           │            │
    ┌────▼───┐  ┌────▼───┐  ┌────▼───┐           ┌────▼───┐ ┌────▼───┐  ┌────▼───┐
    │Gateway │  │Gateway │  │Gateway │           │Gateway │ │Gateway │  │Gateway │
    │Node 1  │  │Node 2  │  │Node 3  │           │Node 1  │ │Node 2  │  │Node 3  │
    └────┬───┘  └────┬───┘  └────┬───┘           └────┬───┘ └────┬───┘  └────┬───┘
         │           │           │                     │          │           │
         └───────────┴───────────┘                     └──────────┴───────────┘
                     │                                             │
              ┌──────┴───────┐                            ┌────────┴────────┐
              │              │                            │                 │
         ┌────▼────┐    ┌───▼────┐                  ┌───▼────┐      ┌────▼────┐
         │ Redis   │    │ Consul │                  │ Redis  │      │ Consul  │
         │ Cache   │    │Service │                  │ Cache  │      │ Service │
         │         │    │Discovery│                 │        │      │Discovery│
         └─────────┘    └────────┘                  └────────┘      └─────────┘
                              │                            │
                              └────────────┬───────────────┘
                                           │
                      ┌────────────────────┴────────────────────┐
                      │                                          │
               ┌──────▼──────┐                            ┌─────▼─────┐
               │ Microservice│                            │Microservice│
               │   Cluster   │                            │  Cluster  │
               │             │                            │           │
               │ ┌─────────┐ │                            │┌─────────┐│
               │ │User API │ │                            ││Order API││
               │ │Order API│ │                            ││Product  ││
               │ │Product  │ │                            ││Payment  ││
               │ └─────────┘ │                            │└─────────┘│
               └─────────────┘                            └───────────┘
```

### Component Layers

**1. Edge Layer**
- CDN for static content and edge caching
- DDoS protection and WAF
- TLS termination
- Geographic routing

**2. Gateway Layer**
- Request routing and load balancing
- Authentication and authorization
- Rate limiting and throttling
- Request/response transformation
- Circuit breaking and retry logic

**3. Service Discovery Layer**
- Dynamic service registration
- Health checking
- Load balancing algorithms
- Service metadata management

**4. Caching Layer**
- Distributed cache (Redis)
- Cache invalidation strategies
- Cache warming
- Cache key management

**5. Backend Services Layer**
- Microservices
- Legacy systems
- Third-party APIs
- Data stores

---

## Core Components

### 1. Router

**Responsibilities:**
- Path-based routing
- Header-based routing
- Query parameter routing
- Weight-based routing (canary deployments)
- Protocol translation

**Configuration Example (Kong):**

```yaml
routes:
  - name: user-api-v1
    paths:
      - /v1/users
    methods:
      - GET
      - POST
    service: user-service-v1
    
  - name: user-api-v2
    paths:
      - /v2/users
    methods:
      - GET
      - POST
    service: user-service-v2
    strip_path: true
    
  - name: canary-route
    paths:
      - /api/features/new
    service: feature-service-canary
    # 10% traffic to canary
    plugins:
      - name: traffic-split
        config:
          upstream_weights:
            - weight: 90
              target: feature-service-stable
            - weight: 10
              target: feature-service-canary
```

### 2. Authentication Handler

**Supported Methods:**
- API Keys
- JWT (JSON Web Tokens)
- OAuth 2.0 / OpenID Connect
- mTLS (Mutual TLS)
- Basic Auth
- Custom authentication plugins

**JWT Validation Flow:**

```python
# jwt_validator.py
import jwt
from datetime import datetime
from functools import wraps
from flask import request, jsonify

class JWTValidator:
    def __init__(self, public_key, algorithm='RS256'):
        self.public_key = public_key
        self.algorithm = algorithm
    
    def validate_token(self, token):
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                audience='api.example.com',
                issuer='https://auth.example.com'
            )
            
            # Check expiration
            if datetime.fromtimestamp(payload['exp']) < datetime.now():
                return None, 'Token expired'
            
            # Check custom claims
            if 'scope' not in payload:
                return None, 'Missing scope claim'
            
            return payload, None
            
        except jwt.InvalidTokenError as e:
            return None, str(e)
    
    def require_auth(self, required_scopes=None):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                auth_header = request.headers.get('Authorization', '')
                
                if not auth_header.startswith('Bearer '):
                    return jsonify({'error': 'Missing or invalid authorization header'}), 401
                
                token = auth_header[7:]
                payload, error = self.validate_token(token)
                
                if error:
                    return jsonify({'error': error}), 401
                
                # Check scopes
                if required_scopes:
                    token_scopes = set(payload.get('scope', '').split())
                    if not set(required_scopes).issubset(token_scopes):
                        return jsonify({'error': 'Insufficient permissions'}), 403
                
                request.user = payload
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
```

### 3. Rate Limiter

**Algorithms:**

**Token Bucket Algorithm:**
```python
# token_bucket.py
import time
import redis
from typing import Tuple

class TokenBucket:
    def __init__(self, redis_client: redis.Redis, capacity: int, refill_rate: int):
        """
        Args:
            capacity: Maximum tokens in bucket
            refill_rate: Tokens added per second
        """
        self.redis = redis_client
        self.capacity = capacity
        self.refill_rate = refill_rate
    
    def allow_request(self, key: str) -> Tuple[bool, dict]:
        """Check if request is allowed and return rate limit info."""
        
        lua_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or capacity
        local last_refill = tonumber(bucket[2]) or now
        
        -- Refill tokens based on time elapsed
        local elapsed = now - last_refill
        local tokens_to_add = elapsed * refill_rate
        tokens = math.min(capacity, tokens + tokens_to_add)
        
        local allowed = 0
        if tokens >= 1 then
            tokens = tokens - 1
            allowed = 1
        end
        
        -- Update bucket
        redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
        redis.call('EXPIRE', key, 3600)
        
        return {allowed, math.floor(tokens), capacity}
        """
        
        now = time.time()
        result = self.redis.eval(
            lua_script,
            1,
            f"rate_limit:{key}",
            self.capacity,
            self.refill_rate,
            now
        )
        
        allowed, remaining, limit = result
        
        return bool(allowed), {
            'limit': limit,
            'remaining': remaining,
            'reset': int(now) + 1
        }
```

**Sliding Window Log:**
```python
# sliding_window.py
import time
import redis

class SlidingWindowRateLimiter:
    def __init__(self, redis_client: redis.Redis, window_size: int, max_requests: int):
        self.redis = redis_client
        self.window_size = window_size  # seconds
        self.max_requests = max_requests
    
    def allow_request(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_size
        
        pipe = self.redis.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(f"rate_limit:{key}", 0, window_start)
        
        # Count requests in current window
        pipe.zcard(f"rate_limit:{key}")
        
        # Add current request
        pipe.zadd(f"rate_limit:{key}", {str(now): now})
        
        # Set expiry
        pipe.expire(f"rate_limit:{key}", self.window_size)
        
        results = pipe.execute()
        request_count = results[1]
        
        return request_count < self.max_requests
```

### 4. Circuit Breaker

**Implementation:**

```python
# circuit_breaker.py
from enum import Enum
from datetime import datetime, timedelta
import threading

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60, success_threshold=2):
        self.failure_threshold = failure_threshold
        self.timeout = timeout  # seconds to wait before trying half_open
        self.success_threshold = success_threshold
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.lock = threading.Lock()
    
    def call(self, func, *args, **kwargs):
        with self.lock:
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                else:
                    raise Exception("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e
    
    def _on_success(self):
        with self.lock:
            self.failure_count = 0
            
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.success_threshold:
                    self.state = CircuitState.CLOSED
                    self.success_count = 0
    
    def _on_failure(self):
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = datetime.now()
            
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
    
    def _should_attempt_reset(self):
        return (
            self.last_failure_time and
            datetime.now() >= self.last_failure_time + timedelta(seconds=self.timeout)
        )
    
    def get_state(self):
        return self.state.value
```

### 5. Request Transformer

**Transformation Types:**
- Header manipulation
- Query parameter modification
- Body transformation
- Protocol conversion (REST to gRPC)

```python
# transformer.py
from typing import Dict, Any
import json

class RequestTransformer:
    @staticmethod
    def add_headers(request, headers: Dict[str, str]):
        """Add custom headers to request."""
        for key, value in headers.items():
            request.headers[key] = value
        return request
    
    @staticmethod
    def transform_body(request, mapping: Dict[str, str]):
        """Transform request body fields."""
        if request.content_type == 'application/json':
            body = json.loads(request.body)
            transformed = {}
            
            for old_key, new_key in mapping.items():
                if old_key in body:
                    transformed[new_key] = body[old_key]
            
            request.body = json.dumps(transformed)
        
        return request
    
    @staticmethod
    def aggregate_responses(responses: list) -> Dict[str, Any]:
        """Aggregate multiple service responses."""
        aggregated = {}
        
        for response in responses:
            service_name = response.get('service')
            data = response.get('data')
            aggregated[service_name] = data
        
        return aggregated
```

---

## Gateway Patterns

### 1. Backend for Frontend (BFF)

Separate gateways for different client types:

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│ Web Client   │       │Mobile Client │       │  IoT Device  │
└──────┬───────┘       └──────┬───────┘       └──────┬───────┘
       │                      │                       │
       ▼                      ▼                       ▼
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│  Web BFF     │       │ Mobile BFF   │       │  IoT BFF     │
│              │       │              │       │              │
│ • Full data  │       │ • Optimized  │       │ • Minimal    │
│ • Rich UI    │       │ • Compressed │       │ • Binary     │
│ • Caching    │       │ • Battery    │       │ • Low        │
│              │       │   aware      │       │   bandwidth  │
└──────┬───────┘       └──────┬───────┘       └──────┬───────┘
       └──────────────────────┴───────────────────────┘
                              │
                      ┌───────┴───────┐
                      │               │
               ┌──────▼──────┐ ┌─────▼──────┐
               │User Service │ │Order Service│
               └─────────────┘ └────────────┘
```

### 2. API Composition

Aggregate multiple service calls:

```python
# api_composer.py
import asyncio
import httpx

class APIComposer:
    def __init__(self):
        self.client = httpx.AsyncClient()
    
    async def get_user_profile(self, user_id: str):
        """Compose user profile from multiple services."""
        
        # Parallel service calls
        user_task = self.client.get(f"http://user-service/users/{user_id}")
        orders_task = self.client.get(f"http://order-service/users/{user_id}/orders")
        preferences_task = self.client.get(f"http://pref-service/users/{user_id}/prefs")
        
        responses = await asyncio.gather(
            user_task,
            orders_task,
            preferences_task,
            return_exceptions=True
        )
        
        # Handle responses
        user_data = responses[0].json() if not isinstance(responses[0], Exception) else None
        orders_data = responses[1].json() if not isinstance(responses[1], Exception) else []
        prefs_data = responses[2].json() if not isinstance(responses[2], Exception) else {}
        
        # Compose response
        return {
            'user': user_data,
            'recent_orders': orders_data.get('items', [])[:5],
            'preferences': prefs_data
        }
```

### 3. Strangler Fig Pattern

Gradually migrate from legacy to new services:

```nginx
# nginx.conf - Strangler pattern
location /api/legacy-users {
    # Route based on feature flag header
    set $backend "legacy";
    
    if ($http_x_use_new_api = "true") {
        set $backend "new";
    }
    
    proxy_pass http://$backend-user-service;
}
```

---

## Data Models

### Gateway Configuration Model

```python
# models/gateway_config.py
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from enum import Enum

class Protocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    GRPC = "grpc"
    WEBSOCKET = "ws"

class LoadBalanceMethod(str, Enum):
    ROUND_ROBIN = "round-robin"
    LEAST_CONN = "least-connections"
    IP_HASH = "ip-hash"
    WEIGHTED = "weighted"

class HealthCheck(BaseModel):
    path: str = "/health"
    interval: int = 30  # seconds
    timeout: int = 5
    healthy_threshold: int = 2
    unhealthy_threshold: int = 3

class Upstream(BaseModel):
    id: str
    name: str
    protocol: Protocol
    servers: List[str]
    load_balance: LoadBalanceMethod = LoadBalanceMethod.ROUND_ROBIN
    health_check: Optional[HealthCheck] = None
    connection_timeout: int = 60
    read_timeout: int = 60
    retries: int = 3

class RateLimitConfig(BaseModel):
    enabled: bool = True
    requests_per_minute: int = 100
    burst: int = 20
    key_by: str = "ip"  # ip, user_id, api_key

class CacheConfig(BaseModel):
    enabled: bool = False
    ttl: int = 300  # seconds
    vary_on: List[str] = ["Accept-Encoding"]
    cache_methods: List[str] = ["GET", "HEAD"]

class Route(BaseModel):
    id: str
    path: str
    methods: List[str] = ["GET"]
    upstream_id: str
    strip_path: bool = False
    preserve_host: bool = False
    rate_limit: Optional[RateLimitConfig] = None
    cache: Optional[CacheConfig] = None
    auth_required: bool = True
    timeout: int = 30

class GatewayConfig(BaseModel):
    upstreams: List[Upstream]
    routes: List[Route]
    global_rate_limit: Optional[RateLimitConfig] = None
```

### API Key Model

```python
# models/api_key.py
from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional

class APIKey(BaseModel):
    id: str
    key: str  # hashed
    name: str
    user_id: str
    scopes: List[str]
    rate_limit_tier: str  # free, basic, premium, enterprise
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_active: bool = True
    
    requests_per_minute: int = 60
    daily_quota: int = 10000
    monthly_quota: int = 300000
```

---

## API Contracts

### Gateway Management API

**Base URL:** `https://gateway-admin.example.com/api/v1`

**Authentication:** Bearer token (admin JWT)

### Endpoints

#### Create Route

```http
POST /routes
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "path": "/api/users",
  "methods": ["GET", "POST"],
  "upstream_id": "user-service-prod",
  "strip_path": false,
  "auth_required": true,
  "rate_limit": {
    "enabled": true,
    "requests_per_minute": 100,
    "burst": 20,
    "key_by": "api_key"
  },
  "cache": {
    "enabled": true,
    "ttl": 300,
    "cache_methods": ["GET"]
  }
}
```

**Response:**
```json
{
  "id": "route_abc123",
  "path": "/api/users",
  "status": "active",
  "created_at": "2026-02-11T10:00:00Z"
}
```

#### Update Route

```http
PATCH /routes/{route_id}
Content-Type: application/json

{
  "rate_limit": {
    "requests_per_minute": 200
  }
}
```

#### Get Metrics

```http
GET /metrics/routes/{route_id}?period=1h

Response:
{
  "route_id": "route_abc123",
  "period": "1h",
  "metrics": {
    "total_requests": 45230,
    "successful_requests": 44890,
    "failed_requests": 340,
    "avg_latency_ms": 45,
    "p95_latency_ms": 120,
    "p99_latency_ms": 250,
    "rate_limit_hits": 156,
    "cache_hit_rate": 0.67
  }
}
```

---

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────┐
│ Layer 1: Edge Protection (WAF, DDoS)           │
├─────────────────────────────────────────────────┤
│ Layer 2: TLS Termination & Validation          │
├─────────────────────────────────────────────────┤
│ Layer 3: Authentication (JWT, OAuth, mTLS)     │
├─────────────────────────────────────────────────┤
│ Layer 4: Authorization (RBAC, ABAC)            │
├─────────────────────────────────────────────────┤
│ Layer 5: Rate Limiting & Throttling            │
├─────────────────────────────────────────────────┤
│ Layer 6: Input Validation & Sanitization       │
├─────────────────────────────────────────────────┤
│ Layer 7: Service-to-Service Auth (mTLS)        │
└─────────────────────────────────────────────────┘
```

### mTLS Implementation

```yaml
# Kong mTLS config
services:
  - name: secure-service
    url: https://internal-api:8443
    client_certificate:
      id: cert_client_abc123
    tls_verify: true
    ca_certificates:
      - ca_cert_internal

certificates:
  - id: cert_client_abc123
    cert: "-----BEGIN CERTIFICATE-----\n..."
    key: "-----BEGIN PRIVATE KEY-----\n..."
    
ca_certificates:
  - id: ca_cert_internal
    cert: "-----BEGIN CERTIFICATE-----\n..."
```

---

## Performance & Scalability

### Caching Strategy

**Multi-Level Caching:**

```
Client Request
      │
      ▼
┌─────────────┐  Hit   ┌──────────┐
│ CDN Cache   │───────>│ Response │
└──────┬──────┘        └──────────┘
       │ Miss
       ▼
┌─────────────┐  Hit   ┌──────────┐
│ Gateway     │───────>│ Response │
│ Cache       │        └──────────┘
└──────┬──────┘
       │ Miss
       ▼
┌─────────────┐  Hit   ┌──────────┐
│ Service     │───────>│ Response │
│ Cache       │        └──────────┘
└──────┬──────┘
       │ Miss
       ▼
┌─────────────┐        ┌──────────┐
│ Database    │───────>│ Response │
└─────────────┘        └──────────┘
```

### Connection Pooling

```python
# connection_pool.py
import httpx

class ConnectionPool:
    def __init__(self):
        self.pools = {}
    
    def get_client(self, service_name: str) -> httpx.AsyncClient:
        if service_name not in self.pools:
            self.pools[service_name] = httpx.AsyncClient(
                limits=httpx.Limits(
                    max_keepalive_connections=20,
                    max_connections=100,
                    keepalive_expiry=30.0
                ),
                timeout=httpx.Timeout(30.0),
                http2=True
            )
        
        return self.pools[service_name]
```

### Horizontal Scaling

- Stateless gateway nodes
- Session affinity via consistent hashing (when needed)
- Shared cache layer (Redis Cluster)
- Service discovery for dynamic scaling

---

## Deployment Topologies

### Single Region

```
                  ┌──────────────┐
                  │Load Balancer │
                  └──────┬───────┘
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼───┐      ┌────▼───┐     ┌────▼───┐
    │Gateway │      │Gateway │     │Gateway │
    │  AZ-1  │      │  AZ-2  │     │  AZ-3  │
    └────────┘      └────────┘     └────────┘
```

### Multi-Region with Active-Active

```
       DNS (GeoDNS / Traffic Manager)
              │
    ┌─────────┴─────────┐
    │                   │
┌───▼────┐         ┌───▼────┐
│US-EAST │         │EU-WEST │
│Gateway │<------->│Gateway │
│Cluster │  Sync   │Cluster │
└────────┘         └────────┘
```

**Benefits:**
- Low latency (geo-proximity)
- High availability
- Disaster recovery
- Compliance (data residency)

---

**Built for scale • Optimized for performance • Production-hardened patterns**
