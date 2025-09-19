# Modular FastAPI Application

A modular FastAPI application built with security best practices, supporting pluggable services and following industry standards.

## Features

- **Modular Architecture**: Pluggable service system for easy extension
- **FastAPI Framework**: Modern, fast web framework for building APIs
- **Security First**: CORS, Trusted Host middleware, and secure defaults
- **Environment Configuration**: Environment variables for flexible deployment
- **Health Checks**: Built-in health check endpoints for all services
- **Auto Documentation**: Automatic API documentation at `/docs`
- **Service Registry**: Dynamic service loading and management

## Services

### Security Scanner Service
A comprehensive network security scanner using NMAP with JSON output.

**Features:**
- IP address and CIDR notation support
- Hostname resolution and scanning
- Multiple scan types (basic, comprehensive, custom)
- Service version detection
- Result caching and retrieval
- Comprehensive error handling

**Scan Types:**
- `basic`: TCP SYN scan with common ports
- `comprehensive`: Full scan with service version detection
- `custom`: Configurable scan parameters

## Installation

1. **Clone the repository** (if applicable)
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Set up environment variables**:
   - Copy `.env` and modify as needed
   - Or set environment variables directly
4. **Install NMAP** (required for security scanner):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap

   # macOS
   brew install nmap

   # CentOS/RHEL
   sudo yum install nmap
   ```

## Usage

### Development Mode
```bash
python main.py
```

### Production Mode
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## API Endpoints

### Core Endpoints
- `GET /` - Root endpoint (health check)
- `GET /health` - Application health check
- `GET /docs` - Interactive API documentation
- `GET /redoc` - Alternative API documentation

### Security Scanner Service (`/api/v1/security-scanner`)
- `POST /api/v1/security-scanner/scan` - Perform security scan
- `GET /api/v1/security-scanner/scan/{scan_id}` - Get scan results
- `GET /api/v1/security-scanner/health` - Service health check
- `GET /api/v1/security-scanner/info` - Service information

## Environment Variables

### Core Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | Application environment |
| `PORT` | `8000` | Server port |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | CORS allowed origins |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Trusted hosts |

### Security Scanner Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `NMAP_TIMEOUT` | `300` | NMAP scan timeout in seconds |
| `NMAP_SCAN_INTENSITY` | `1` | Scan intensity (1-5) |
| `NMAP_MAX_TARGETS` | `10` | Maximum targets per scan |
| `REDIS_URL` | `redis://:secure_password@localhost:6379/0` | Redis URL for caching (with auth) |
| `SCAN_CACHE_TTL` | `3600` | Cache TTL in seconds |

### Security Controls Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_SCAN_NETWORKS` | `192.168.0.0/16,10.0.0.0/8,127.0.0.1/32` | Allowed network ranges for scanning |
| `SCAN_AUDIT_LOG_ENABLED` | `true` | Enable audit logging for scans |
| `SCAN_AUTHORIZATION_REQUIRED` | `true` | Require authorization for scanning |
| `SCAN_MAX_CONCURRENT_SCANS` | `3` | Maximum concurrent scans allowed |
| `SCAN_MAX_DURATION` | `600` | Maximum scan duration in seconds |

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