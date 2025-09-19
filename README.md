# Minimal FastAPI Application

A minimal FastAPI application built with security best practices and following industry standards.

## Features

- **FastAPI Framework**: Modern, fast web framework for building APIs
- **Security First**: CORS, Trusted Host middleware, and secure defaults
- **Environment Configuration**: Environment variables for flexible deployment
- **Health Checks**: Built-in health check endpoints
- **Auto Documentation**: Automatic API documentation at `/docs`

## Installation

1. **Clone the repository** (if applicable)
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Set up environment variables**:
   - Copy `.env` and modify as needed
   - Or set environment variables directly

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

- `GET /` - Root endpoint (health check)
- `GET /health` - Health check endpoint
- `GET /api/v1/test` - Test endpoint
- `GET /docs` - Interactive API documentation
- `GET /redoc` - Alternative API documentation

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | Application environment |
| `PORT` | `8000` | Server port |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | CORS allowed origins |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Trusted hosts |

## Security Features

- **CORS Protection**: Configurable allowed origins
- **Trusted Host Middleware**: Prevents host header attacks
- **Environment-based Configuration**: Secure credential management
- **Minimal Attack Surface**: Only essential endpoints exposed

## Development

The application includes auto-reload in development mode for rapid development.

## License

MIT License