# API Gateway Workflows

Comprehensive development, deployment, and operational workflows for API gateway lifecycle management.

## Table of Contents

1. [Development Workflow](#development-workflow)
2. [Testing Strategy](#testing-strategy)
3. [CI/CD Pipeline](#cicd-pipeline)
4. [Deployment Process](#deployment-process)
5. [Configuration Management](#configuration-management)
6. [Monitoring & Alerting](#monitoring--alerting)
7. [Incident Response](#incident-response)
8. [Capacity Planning](#capacity-planning)

---

## Development Workflow

### 1. Local Development Setup

**Prerequisites:**
- Docker & Docker Compose
- Kong Gateway or preferred gateway solution
- PostgreSQL (for Kong configuration storage)
- Redis (for rate limiting and caching)

**Docker Compose Setup:**

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: kong
      POSTGRES_DB: kong
      POSTGRES_PASSWORD: kongpass
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "kong"]
      interval: 10s
      timeout: 5s
      retries: 5

  kong-migration:
    image: kong:3.5
    command: kong migrations bootstrap
    environment:
      KONG_DATABASE: postgres
      KONG_PG_HOST: postgres
      KONG_PG_USER: kong
      KONG_PG_PASSWORD: kongpass
    depends_on:
      postgres:
        condition: service_healthy

  kong:
    image: kong:3.5
    environment:
      KONG_DATABASE: postgres
      KONG_PG_HOST: postgres
      KONG_PG_USER: kong
      KONG_PG_PASSWORD: kongpass
      KONG_PROXY_ACCESS_LOG: /dev/stdout
      KONG_ADMIN_ACCESS_LOG: /dev/stdout
      KONG_PROXY_ERROR_LOG: /dev/stderr
      KONG_ADMIN_ERROR_LOG: /dev/stderr
      KONG_ADMIN_LISTEN: 0.0.0.0:8001
      KONG_ADMIN_GUI_URL: http://localhost:8002
    ports:
      - "8000:8000"  # Proxy
      - "8443:8443"  # Proxy SSL
      - "8001:8001"  # Admin API
      - "8002:8002"  # Admin GUI
    depends_on:
      - kong-migration
      - redis
    healthcheck:
      test: ["CMD", "kong", "health"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

  # Mock backend services for testing
  user-service:
    image: mockserver/mockserver:latest
    ports:
      - "8080:1080"
    environment:
      MOCKSERVER_INITIALIZATION_JSON_PATH: /config/user-service.json
    volumes:
      - ./mocks/user-service.json:/config/user-service.json

  order-service:
    image: mockserver/mockserver:latest
    ports:
      - "8081:1080"
    environment:
      MOCKSERVER_INITIALIZATION_JSON_PATH: /config/order-service.json
    volumes:
      - ./mocks/order-service.json:/config/order-service.json

volumes:
  postgres_data:
  redis_data:
```

### 2. Gateway Configuration Workflow

**Step 1: Define Configuration**

```yaml
# config/gateway.yaml
_format_version: "3.0"
_transform: true

services:
  - name: user-service
    url: http://user-service:1080
    retries: 3
    connect_timeout: 5000
    write_timeout: 60000
    read_timeout: 60000
    
    routes:
      - name: users-list
        methods: [GET]
        paths: [/api/users]
        strip_path: false
        
      - name: users-create
        methods: [POST]
        paths: [/api/users]
        strip_path: false
    
    plugins:
      - name: rate-limiting
        config:
          second: 10
          minute: 100
          policy: redis
          redis_host: redis
          redis_port: 6379
          fault_tolerant: true
      
      - name: jwt
        config:
          key_claim_name: iss
          secret_is_base64: false
      
      - name: correlation-id
        config:
          header_name: X-Request-ID
          generator: uuid
          echo_downstream: true
      
      - name: prometheus
        config:
          per_consumer: true

  - name: order-service
    url: http://order-service:1080
    
    routes:
      - name: orders-list
        methods: [GET]
        paths: [/api/orders]
        
      - name: orders-create
        methods: [POST]
        paths: [/api/orders]
    
    plugins:
      - name: rate-limiting
        config:
          minute: 50
          hour: 1000
          policy: redis
          redis_host: redis
          redis_port: 6379

# Global plugins
plugins:
  - name: cors
    config:
      origins:
        - http://localhost:3000
        - https://app.example.com
      methods:
        - GET
        - POST
        - PUT
        - DELETE
        - OPTIONS
      headers:
        - Accept
        - Authorization
        - Content-Type
      exposed_headers:
        - X-Request-ID
      credentials: true
      max_age: 3600
```

**Step 2: Validate Configuration**

```bash
#!/bin/bash
# scripts/validate-config.sh

# Validate YAML syntax
yamllint config/gateway.yaml

# Validate Kong configuration
docker run --rm \
  -v $(pwd)/config:/config \
  kong:3.5 \
  kong config parse /config/gateway.yaml

echo "✅ Configuration validation passed"
```

**Step 3: Apply Configuration**

```bash
#!/bin/bash
# scripts/apply-config.sh

# Using deck (Kong's declarative configuration tool)
deck sync \
  --kong-addr http://localhost:8001 \
  --state config/gateway.yaml \
  --select-tag dev

echo "✅ Configuration applied successfully"
```

### 3. Development Best Practices

**Version Control:**
- Store all gateway configurations in Git
- Use branches for feature development
- Require code reviews for configuration changes
- Tag releases for production deployments

**Configuration as Code:**
```python
# scripts/generate_config.py
from typing import List, Dict
import yaml

class GatewayConfigGenerator:
    def __init__(self):
        self.config = {
            '_format_version': '3.0',
            'services': [],
            'plugins': []
        }
    
    def add_service(self, name: str, url: str, routes: List[Dict]):
        """Add a service with routes."""
        service = {
            'name': name,
            'url': url,
            'routes': routes,
            'plugins': []
        }
        self.config['services'].append(service)
        return self
    
    def add_rate_limiting(self, service_name: str, 
                         requests_per_minute: int):
        """Add rate limiting to service."""
        for service in self.config['services']:
            if service['name'] == service_name:
                service['plugins'].append({
                    'name': 'rate-limiting',
                    'config': {
                        'minute': requests_per_minute,
                        'policy': 'redis',
                        'redis_host': 'redis',
                        'redis_port': 6379
                    }
                })
        return self
    
    def export(self, filename: str):
        """Export configuration to YAML file."""
        with open(filename, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)

# Usage
generator = GatewayConfigGenerator()
generator.add_service(
    'user-service',
    'http://user-service:8080',
    [
        {'name': 'users', 'methods': ['GET', 'POST'], 
         'paths': ['/api/users']}
    ]
).add_rate_limiting('user-service', 100).export('config/gateway.yaml')
```

---

## Testing Strategy

### 1. Unit Tests

**Test Gateway Configuration:**

```python
# tests/test_config.py
import pytest
import yaml
from jsonschema import validate

def test_gateway_config_valid():
    """Test that gateway config is valid YAML."""
    with open('config/gateway.yaml') as f:
        config = yaml.safe_load(f)
    
    assert '_format_version' in config
    assert 'services' in config
    assert len(config['services']) > 0

def test_all_services_have_routes():
    """Test that all services have at least one route."""
    with open('config/gateway.yaml') as f:
        config = yaml.safe_load(f)
    
    for service in config['services']:
        assert 'routes' in service
        assert len(service['routes']) > 0

def test_rate_limiting_configured():
    """Test that critical services have rate limiting."""
    with open('config/gateway.yaml') as f:
        config = yaml.safe_load(f)
    
    for service in config['services']:
        if service['name'] in ['user-service', 'order-service']:
            plugins = service.get('plugins', [])
            plugin_names = [p['name'] for p in plugins]
            assert 'rate-limiting' in plugin_names
```

### 2. Integration Tests

```python
# tests/test_integration.py
import pytest
import httpx

@pytest.fixture
def gateway_client():
    return httpx.AsyncClient(base_url="http://localhost:8000")

@pytest.mark.asyncio
async def test_user_service_route(gateway_client):
    """Test that user service is accessible through gateway."""
    response = await gateway_client.get("/api/users")
    assert response.status_code in [200, 401]  # 401 if auth required

@pytest.mark.asyncio
async def test_rate_limiting(gateway_client):
    """Test that rate limiting is enforced."""
    responses = []
    
    # Make requests until rate limit is hit
    for i in range(150):
        response = await gateway_client.get("/api/users")
        responses.append(response.status_code)
    
    # Should have at least one 429 (Too Many Requests)
    assert 429 in responses

@pytest.mark.asyncio
async def test_cors_headers(gateway_client):
    """Test that CORS headers are present."""
    response = await gateway_client.options(
        "/api/users",
        headers={"Origin": "http://localhost:3000"}
    )
    
    assert "Access-Control-Allow-Origin" in response.headers
    assert "Access-Control-Allow-Methods" in response.headers

@pytest.mark.asyncio
async def test_jwt_authentication(gateway_client):
    """Test JWT authentication."""
    # Without token
    response = await gateway_client.get("/api/users")
    assert response.status_code == 401
    
    # With invalid token
    response = await gateway_client.get(
        "/api/users",
        headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 401
```

### 3. Load Testing

```python
# tests/load_test.py
from locust import HttpUser, task, between

class GatewayLoadTest(HttpUser):
    wait_time = between(1, 3)
    host = "http://localhost:8000"
    
    @task(3)
    def get_users(self):
        """GET /api/users (3x weight)."""
        headers = {"Authorization": f"Bearer {self.get_token()}"}
        self.client.get("/api/users", headers=headers)
    
    @task(2)
    def get_orders(self):
        """GET /api/orders (2x weight)."""
        headers = {"Authorization": f"Bearer {self.get_token()}"}
        self.client.get("/api/orders", headers=headers)
    
    @task(1)
    def create_order(self):
        """POST /api/orders (1x weight)."""
        headers = {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type": "application/json"
        }
        self.client.post(
            "/api/orders",
            json={"product_id": "prod_123", "quantity": 1},
            headers=headers
        )
    
    def get_token(self):
        """Get or cache auth token."""
        if not hasattr(self, '_token'):
            self._token = "test_token_here"
        return self._token

# Run: locust -f tests/load_test.py --users 100 --spawn-rate 10
```

---

## CI/CD Pipeline

### GitHub Actions Workflow

```yaml
# .github/workflows/gateway-ci.yml
name: Gateway CI/CD

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  KONG_VERSION: 3.5

jobs:
  validate:
    name: Validate Configuration
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install yamllint jsonschema
      
      - name: Lint YAML
        run: yamllint config/gateway.yaml
      
      - name: Validate Kong config
        run: |
          docker run --rm \
            -v $(pwd)/config:/config \
            kong:${{ env.KONG_VERSION }} \
            kong config parse /config/gateway.yaml

  test:
    name: Run Tests
    runs-on: ubuntu-latest
    needs: validate
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: kong
          POSTGRES_DB: kong
          POSTGRES_PASSWORD: kongpass
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 3s
          --health-retries 3
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install pytest pytest-asyncio httpx pyyaml
      
      - name: Start Kong
        run: |
          docker run -d --name kong \
            --network host \
            -e KONG_DATABASE=postgres \
            -e KONG_PG_HOST=localhost \
            -e KONG_PG_USER=kong \
            -e KONG_PG_PASSWORD=kongpass \
            kong:${{ env.KONG_VERSION }}
          
          # Wait for Kong to be ready
          sleep 10
      
      - name: Apply configuration
        run: |
          docker run --rm \
            --network host \
            -v $(pwd)/config:/config \
            kong/deck:latest \
            sync --kong-addr http://localhost:8001 \
            --state /config/gateway.yaml
      
      - name: Run unit tests
        run: pytest tests/test_config.py -v
      
      - name: Run integration tests
        run: pytest tests/test_integration.py -v

  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: test
    if: github.ref == 'refs/heads/develop'
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Deploy to staging
        run: |
          # Using deck to sync configuration
          docker run --rm \
            -v $(pwd)/config:/config \
            -e KONG_ADMIN_TOKEN=${{ secrets.STAGING_KONG_TOKEN }} \
            kong/deck:latest \
            sync --kong-addr https://staging-gateway-admin.example.com \
            --state /config/gateway.yaml \
            --select-tag staging
      
      - name: Run smoke tests
        run: |
          curl -f https://staging-gateway.example.com/health || exit 1

  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: test
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: https://api.example.com
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Create backup
        run: |
          docker run --rm \
            -e KONG_ADMIN_TOKEN=${{ secrets.PROD_KONG_TOKEN }} \
            kong/deck:latest \
            dump --kong-addr https://prod-gateway-admin.example.com \
            --output-file /tmp/backup.yaml
          
          aws s3 cp /tmp/backup.yaml \
            s3://gateway-backups/$(date +%Y%m%d-%H%M%S)-backup.yaml
      
      - name: Deploy to production
        run: |
          docker run --rm \
            -v $(pwd)/config:/config \
            -e KONG_ADMIN_TOKEN=${{ secrets.PROD_KONG_TOKEN }} \
            kong/deck:latest \
            sync --kong-addr https://prod-gateway-admin.example.com \
            --state /config/gateway.yaml \
            --select-tag production
      
      - name: Run smoke tests
        run: |
          curl -f https://api.example.com/health || exit 1
      
      - name: Notify deployment
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: 'Gateway deployed to production'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

---

## Deployment Process

### Blue-Green Deployment

```bash
#!/bin/bash
# scripts/blue-green-deploy.sh

CURRENT_ENV=$(kubectl get service gateway-service -o jsonpath='{.spec.selector.version}')
NEW_ENV=$([ "$CURRENT_ENV" == "blue" ] && echo "green" || echo "blue")

echo "Current environment: $CURRENT_ENV"
echo "Deploying to: $NEW_ENV"

# Deploy new version
kubectl apply -f k8s/gateway-$NEW_ENV.yaml

# Wait for new pods to be ready
kubectl wait --for=condition=ready pod \
  -l app=gateway,version=$NEW_ENV \
  --timeout=300s

# Run smoke tests
./scripts/smoke-test.sh https://gateway-$NEW_ENV.internal.example.com

if [ $? -eq 0 ]; then
  echo "Smoke tests passed. Switching traffic..."
  
  # Switch traffic
  kubectl patch service gateway-service \
    -p "{\"spec\":{\"selector\":{\"version\":\"$NEW_ENV\"}}}"
  
  echo "✅ Deployment successful. Traffic now on $NEW_ENV"
  
  # Keep old environment for rollback capability
  echo "Old environment ($CURRENT_ENV) kept for 1 hour for rollback"
else
  echo "❌ Smoke tests failed. Rolling back..."
  kubectl delete -f k8s/gateway-$NEW_ENV.yaml
  exit 1
fi
```

### Canary Deployment

```yaml
# k8s/canary-deployment.yaml
apiVersion: v1
kind: Service
metadata:
  name: gateway-stable
spec:
  selector:
    app: gateway
    version: stable
  ports:
    - port: 8000

---
apiVersion: v1
kind: Service
metadata:
  name: gateway-canary
spec:
  selector:
    app: gateway
    version: canary
  ports:
    - port: 8000

---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: gateway-traffic-split
spec:
  hosts:
    - gateway-service
  http:
    - match:
        - headers:
            x-canary:
              exact: "true"
      route:
        - destination:
            host: gateway-canary
    - route:
        - destination:
            host: gateway-stable
          weight: 90
        - destination:
            host: gateway-canary
          weight: 10
```

---

## Configuration Management

### Environment-Specific Configurations

```bash
# scripts/generate-env-config.sh
#!/bin/bash

ENV=$1  # dev, staging, production

case $ENV in
  dev)
    REDIS_HOST="redis.dev.internal"
    DB_HOST="postgres.dev.internal"
    RATE_LIMIT_MULT=1
    ;;
  staging)
    REDIS_HOST="redis.staging.internal"
    DB_HOST="postgres.staging.internal"
    RATE_LIMIT_MULT=1
    ;;
  production)
    REDIS_HOST="redis.prod.internal"
    DB_HOST="postgres.prod.internal"
    RATE_LIMIT_MULT=2  # Higher limits in prod
    ;;
esac

# Generate config from template
envsubst < config/gateway.template.yaml > config/gateway.$ENV.yaml

echo "Generated configuration for $ENV environment"
```

### Secrets Management

```python
# scripts/manage_secrets.py
import boto3
import json

class SecretsManager:
    def __init__(self, region='us-east-1'):
        self.client = boto3.client('secretsmanager', region_name=region)
    
    def store_secret(self, name: str, value: dict):
        """Store secret in AWS Secrets Manager."""
        try:
            self.client.create_secret(
                Name=name,
                SecretString=json.dumps(value)
            )
        except self.client.exceptions.ResourceExistsException:
            self.client.update_secret(
                SecretId=name,
                SecretString=json.dumps(value)
            )
    
    def get_secret(self, name: str) -> dict:
        """Retrieve secret from AWS Secrets Manager."""
        response = self.client.get_secret_value(SecretId=name)
        return json.loads(response['SecretString'])

# Usage
secrets = SecretsManager()
secrets.store_secret('gateway/jwt-secret', {
    'public_key': 'public_key_content',
    'private_key': 'private_key_content'
})
```

---

## Monitoring & Alerting

### Prometheus Alerts

```yaml
# prometheus/alerts.yml
groups:
  - name: gateway_alerts
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate(gateway_requests_total{status=~"5.."}[5m])) /
          sum(rate(gateway_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Gateway error rate above 5%"
          description: "Error rate is {{ $value | humanizePercentage }}"
      
      - alert: HighLatency
        expr: |
          histogram_quantile(0.95,
            rate(gateway_request_duration_seconds_bucket[5m])
          ) > 1.0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Gateway p95 latency above 1s"
      
      - alert: RateLimitHigh
        expr: |
          rate(gateway_rate_limit_exceeded_total[5m]) > 10
        for: 5m
        labels:
          severity: info
        annotations:
          summary: "High rate of rate limit hits"
      
      - alert: CircuitBreakerOpen
        expr: gateway_circuit_breaker_state > 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Circuit breaker opened for {{ $labels.service }}"
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "API Gateway Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "sum(rate(gateway_requests_total[5m])) by (route)"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "sum(rate(gateway_requests_total{status=~\"5..\"}[5m])) by (route)"
          }
        ]
      },
      {
        "title": "Latency (p50, p95, p99)",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(gateway_request_duration_seconds_bucket[5m]))",
            "legendFormat": "p50"
          },
          {
            "expr": "histogram_quantile(0.95, rate(gateway_request_duration_seconds_bucket[5m]))",
            "legendFormat": "p95"
          },
          {
            "expr": "histogram_quantile(0.99, rate(gateway_request_duration_seconds_bucket[5m]))",
            "legendFormat": "p99"
          }
        ]
      }
    ]
  }
}
```

---

## Incident Response

### Runbook: High Error Rate

```markdown
# High Error Rate Incident Response

## Detection
Alert: `HighErrorRate` fired in Prometheus

## Immediate Actions
1. Check Grafana dashboard for affected routes
2. Review logs in ELK/CloudWatch for error patterns
3. Check upstream service health

## Investigation Steps
1. Identify which services are returning errors
2. Check if errors are isolated to specific routes
3. Review recent deployments (last 2 hours)
4. Check circuit breaker states

## Mitigation
- If specific service failing: Open circuit breaker manually
- If bad deployment: Rollback to previous version
- If external API issue: Enable cached responses
- If DDoS: Apply emergency rate limits

## Commands
```bash
# Check gateway logs
kubectl logs -l app=gateway --tail=100

# Check circuit breaker state
curl http://gateway-admin:8001/status/circuit-breaker

# Emergency rate limit
deck patch --select-tag emergency-rate-limit

# Rollback deployment
./scripts/rollback.sh
```

## Post-Incident
- Update incident log
- Schedule post-mortem
- Document lessons learned
```

---

## Capacity Planning

### Scaling Guidelines

**Horizontal Scaling Triggers:**
- CPU usage > 70% for 5 minutes
- Memory usage > 80%
- Request rate > 80% of tested capacity
- P95 latency > 500ms

**Kubernetes HPA:**

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: gateway-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: gateway
  minReplicas: 3
  maxReplicas: 20
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
    - type: Pods
      pods:
        metric:
          name: gateway_requests_per_second
        target:
          type: AverageValue
          averageValue: "1000"
```

---

**Production-ready workflows • Battle-tested processes • Zero-downtime deployments**
