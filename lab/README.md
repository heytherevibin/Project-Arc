# Arc Lab Environment

Intentionally vulnerable applications for testing Arc's pentesting capabilities.

## Quick Start

```bash
# From project root
make lab

# Or manually
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d
```

## Available Targets

| Target     | URL                        | Description                          |
|------------|----------------------------|--------------------------------------|
| DVWA       | http://localhost:8880      | Damn Vulnerable Web Application      |
| Juice Shop | http://localhost:8881      | OWASP Juice Shop                     |
| WebGoat    | http://localhost:8882      | OWASP WebGoat                        |

## Security Warning

These services are **intentionally vulnerable**. They are bound to `127.0.0.1` only and placed on an internal Docker network. **Never expose them to the internet.**

## Teardown

```bash
make lab-down
```
