# Cenexo Unified Platform

A unified, modular web platform for managing complex internet infrastructure and digital services with multi-tenant architecture, built on FastAPI with enterprise-grade security and scalability features.

## Overview

The Cenexo Unified Platform is designed to provide a comprehensive backend solution for managing various digital services and internet infrastructure components. Built with a multi-tenant architecture, it supports tenant isolation, dynamic service loading, and extensive monitoring capabilities.

## Key Features

### 🏗️ **Architecture & Scalability**
- **Multi-tenant Architecture**: Complete tenant isolation with shared infrastructure
- **Service-oriented Design**: Modular services with dynamic loading and registration
- **Horizontal Scalability**: Each service can scale independently
- **Database Optimization**: Efficient multi-tenant data management with SQLAlchemy

### 🔒 **Security & Compliance**
- **Enhanced Authentication**: JWT-based authentication with role management
- **Tenant Isolation**: Complete data and service isolation between tenants
- **Audit Logging**: Comprehensive audit trails for all operations
- **Rate Limiting**: Configurable rate limiting per tenant and user
- **Security Headers**: Comprehensive security headers and CORS protection

### 📊 **Monitoring & Observability**
- **Prometheus Metrics**: Built-in metrics collection and monitoring
- **Structured Logging**: JSON-based structured logging with audit trails
- **Health Checks**: Comprehensive health monitoring for all services
- **Performance Monitoring**: Request latency and system metrics tracking

### 🛠️ **Service Management**
- **Dynamic Service Registry**: Automatic service discovery and registration
- **Configuration Management**: Per-tenant service configuration
- **Service Health Monitoring**: Real-time service health status
- **Admin Interface**: Comprehensive administrative capabilities

### 📈 **Infrastructure Services**
- **Cenexo Scanner**: Enhanced security scanner with multi-tenant support
- **Service Discovery**: Dynamic service discovery and load balancing
- **Configuration Management**: Centralized configuration management
- **Monitoring Dashboard**: Real-time platform monitoring

## Services

### Cenexo Scanner Service
An enhanced network security scanner with multi-tenant support and improved architecture.

**Features:**
- Multi-tenant isolation and security
- IP address and CIDR notation support
- Hostname resolution and scanning
- Multiple scan types (basic, comprehensive, custom)
- Service version detection
- Result caching and retrieval
- Comprehensive error handling
- Tenant-based access controls
- Audit logging for all scan activities

**Scan Types:**
- `basic`: TCP SYN scan with common ports
- `comprehensive`: Full scan with service version detection
- `custom`: Configurable scan parameters

### Service Registry
Dynamic service registration and discovery system.

**Features:**
- Automatic service registration
- Service health monitoring
- Configuration management
- Service dependency tracking
- API versioning support

### Admin Interface
Comprehensive administrative interface for platform management.

**Features:**
- Tenant management (create, update, deactivate)
- User management across tenants
- Service configuration and monitoring
- Audit log viewing and analysis
- Platform statistics and health monitoring

## Installation

1. **Clone the repository** (if applicable)
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Set up environment variables**:
   - Copy `.env` and modify as needed
   - Or set environment variables directly
   - For development: `ENVIRONMENT=development` (uses SQLite automatically)
   - For production: `ENVIRONMENT=production` (uses PostgreSQL)
4. **Database Setup**:
  - **Development (SQLite)**: No setup required - database files created automatically
  - **Production (PostgreSQL)**: Create database and user with minimal required privileges
  ```sql
  -- Use your secrets management system (Vault, AWS Secrets Manager, etc.)
  -- to generate and store strong, unique passwords
  CREATE DATABASE cenexo_platform;
  CREATE USER cenexo_user WITH ENCRYPTED PASSWORD 'your_hashed_password_here';
  GRANT CONNECT, CREATE ON DATABASE cenexo_platform TO cenexo_user;
  ```
5. **Install NMAP** (required for security scanner):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap

   # macOS
   brew install nmap

   # CentOS/RHEL
   sudo yum install nmap
   ```

## Usage

### Development Mode (SQLite)
```bash
# SQLite database will be created automatically
export ENVIRONMENT=development
python main.py
```

### Production Mode (PostgreSQL)
```bash
# Set production environment and PostgreSQL URL
export ENVIRONMENT=production
export DATABASE_URL="postgresql://user:password@localhost:5432/cenexo_platform"
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Database Migration
The platform automatically handles database schema creation. For production deployments with PostgreSQL, you can use Alembic for migrations:

```bash
# Initialize Alembic (if needed)
alembic init alembic

# Generate migration
alembic revision --autogenerate -m "Initial migration"

# Apply migrations
alembic upgrade head
```

## API Endpoints

### Core Endpoints
- `GET /` - Platform information and health check
- `GET /health` - Enhanced health check with system metrics
- `GET /platform/info` - Platform information and capabilities
- `GET /docs` - Interactive API documentation
- `GET /redoc` - Alternative API documentation

### Service Discovery (`/api/v1/services`)
- `GET /api/v1/services/` - List all registered services
- `GET /api/v1/services/{service_name}/info` - Get service information
- `GET /api/v1/services/health` - Get health status of all services

### Service Registry (`/api/v1/registry`)
- `POST /api/v1/registry/services/{service_name}/config` - Update service configuration
- `GET /api/v1/registry/services/{service_name}/config` - Get service configuration

### Monitoring (`/api/v1/monitoring`)
- `GET /api/v1/monitoring/health` - Comprehensive platform health
- `GET /api/v1/monitoring/metrics` - Prometheus metrics
- `GET /api/v1/monitoring/system` - System performance metrics
- `GET /api/v1/monitoring/services/{service_name}/metrics` - Service-specific metrics
- `GET /api/v1/monitoring/database/status` - Database connection status

### Admin Interface (`/api/v1/admin`) - Requires Admin Access
- `GET /api/v1/admin/tenants` - List all tenants
- `POST /api/v1/admin/tenants` - Create new tenant
- `GET /api/v1/admin/tenants/{tenant_id}` - Get tenant details
- `PUT /api/v1/admin/tenants/{tenant_id}` - Update tenant
- `DELETE /api/v1/admin/tenants/{tenant_id}` - Deactivate tenant
- `GET /api/v1/admin/users` - List users across tenants
- `GET /api/v1/admin/services` - List services across tenants
- `GET /api/v1/admin/audit-logs` - View audit logs
- `GET /api/v1/admin/platform/stats` - Platform statistics
- `GET /api/v1/admin/health` - Admin health check

### Cenexo Scanner Service (`/api/v1/cenexo-scanner`)
- `POST /api/v1/cenexo-scanner/scan` - Perform security scan (tenant-aware)
- `GET /api/v1/cenexo-scanner/scan/{task_id}` - Get scan results
- `GET /api/v1/cenexo-scanner/tasks/{task_id}/status` - Get task status
- `GET /api/v1/cenexo-scanner/health` - Service health check
- `GET /api/v1/cenexo-scanner/info` - Service information
- `GET /api/v1/cenexo-scanner/config` - Service configuration

## Environment Variables

### Core Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | Application environment |
| `PORT` | `8000` | Server port |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | CORS allowed origins |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Trusted hosts |

### Database Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./cenexo_platform.db` (dev)<br>`postgresql://user:password@localhost:5432/cenexo_platform` (prod) | Main database URL |
| `TEST_DATABASE_URL` | `sqlite:///./cenexo_test.db` (dev)<br>`postgresql://test_user:test_password@localhost:5432/cenexo_test` (prod) | Test database URL |
| `DB_POOL_SIZE` | `10` | Database connection pool size (PostgreSQL only) |
| `DB_MAX_OVERFLOW` | `20` | Maximum overflow connections (PostgreSQL only) |
| `DB_POOL_TIMEOUT` | `30` | Connection timeout in seconds (PostgreSQL only) |
| `DB_POOL_RECYCLE` | `3600` | Connection recycle time in seconds (PostgreSQL only) |

### Multi-tenant Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_TENANT_DOMAIN` | `localhost` | Default tenant domain |
| `REQUIRE_TENANT_HEADER` | `true` | Require X-Tenant-ID header |
| `TENANT_HEADER_NAME` | `X-Tenant-ID` | Tenant identification header |

### Cenexo Scanner Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `NMAP_TIMEOUT` | `300` | NMAP scan timeout in seconds |
| `NMAP_SCAN_INTENSITY` | `1` | Scan intensity (1-5) |
| `NMAP_MAX_TARGETS` | `10` | Maximum targets per scan |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis URL for caching |
| `SCAN_CACHE_TTL` | `3600` | Cache TTL in seconds |
| `ALLOWED_SCAN_NETWORKS` | `` | Allowed network ranges (comma-separated) |
| `SCAN_AUTHORIZATION_REQUIRED` | `true` | Require authorization for scanning |
| `SCAN_AUDIT_LOG_ENABLED` | `true` | Enable audit logging for scans |
| `SCAN_MAX_CONCURRENT_SCANS` | `3` | Maximum concurrent scans allowed |
| `SCAN_MAX_DURATION` | `600` | Maximum scan duration in seconds |

### Security Controls Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET_KEY` | `change_in_production` | JWT secret key |
| `JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token expiration time |
| `RATE_LIMIT_PER_MINUTE` | `60` | Default rate limit per minute |
| `ADMIN_API_KEY` | `` | Admin API key for admin endpoints |

### Monitoring Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `PROMETHEUS_ENABLED` | `true` | Enable Prometheus metrics |
| `LOG_LEVEL` | `INFO` | Logging level |
| `STRUCTURED_LOGGING` | `true` | Enable structured JSON logging |
| `AUDIT_LOG_ENABLED` | `true` | Enable audit logging |

### Service Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `CENEXO_SCANNER_ENABLED` | `true` | Enable Cenexo Scanner service |
| `CENEXO_SCANNER_VERSION` | `1.0.0` | Cenexo Scanner version |
| `SERVICE_DISCOVERY_ENABLED` | `true` | Enable service discovery |
| `SERVICE_REGISTRY_ENABLED` | `true` | Enable service registry |

## Security Features

- **CORS Protection**: Configurable allowed origins
- **Trusted Host Middleware**: Prevents host header attacks
- **Environment-based Configuration**: Secure credential management
- **Input Validation**: Comprehensive validation for scan targets
- **Network Allowlisting**: Restricts scanning to authorized networks only
- **Authorization Controls**: Requires authentication for scanning operations
- **Audit Logging**: Comprehensive logging of all scan activities
- **Error Handling**: Secure error responses without information leakage
- **Service Isolation**: Each service runs in isolation

## Database Configuration

### Development (SQLite)
- **Database File**: `cenexo_platform.db` (created automatically)
- **No Setup Required**: SQLite database is created on first run
- **File Location**: Same directory as the application
- **Limitations**: Not suitable for concurrent access or production use

### Production (PostgreSQL)
- **Database Server**: Requires PostgreSQL server
- **Connection Pooling**: Configurable connection pool for scalability
- **Concurrent Access**: Full support for multiple concurrent connections
- **Backup/Recovery**: Standard PostgreSQL backup and recovery procedures

### Automatic Switching
The platform automatically chooses the appropriate database based on the `ENVIRONMENT` variable:
- `ENVIRONMENT=development` → SQLite
- `ENVIRONMENT=production` → PostgreSQL

## Note on Caching

The current implementation uses in-memory caching for scan results. Redis caching is planned for future releases to provide better scalability and persistence across application restarts.

## Usage Examples

### Basic Scan
```bash
curl -X POST "http://localhost:8000/api/v1/security-scanner/scan" \
     -H "Content-Type: application/json" \
     -d '{
       "targets": ["192.168.1.1"],
       "scan_type": "basic",
       "ports": "1-1024"
     }'
```

### Comprehensive Scan with CIDR
```bash
curl -X POST "http://localhost:8000/api/v1/security-scanner/scan" \
     -H "Content-Type: application/json" \
     -d '{
       "targets": ["192.168.1.0/24", "example.com"],
       "scan_type": "comprehensive",
       "ports": "1-1024",
       "timeout": 300
     }'
```

### Get Scan Results
```bash
curl "http://localhost:8000/api/v1/security-scanner/scan/{scan_id}"
```

## Adding New Services

1. Create a new service class inheriting from `BaseService`
2. Implement the `setup_routes()` method
3. Add the service to the `service_modules` list in `services/__init__.py`
4. Create appropriate Pydantic models in `services/models.py`

## Development

The application includes auto-reload in development mode for rapid development.

## License

MIT License