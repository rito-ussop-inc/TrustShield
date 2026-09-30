# TrustShield

![GitHub repo size](https://img.shields.io/github/repo-size/Ritoyash/TrustShield)
![GitHub language count](https://img.shields.io/github/languages/count/Ritoyash/TrustShield)
![GitHub top language](https://img.shields.io/github/languages/top/Ritoyash/TrustShield)
![GitHub last commit](https://img.shields.io/github/last-commit/Ritoyash/TrustShield)
![GitHub issues](https://img.shields.io/github/issues/Ritoyash/TrustShield)
![GitHub pull requests](https://img.shields.io/github/issues-pr/Ritoyash/TrustShield)

A comprehensive threat detection and analysis system for URLs, messages, documents, and QR codes.

## Features

- Multi-modal threat analysis (URL, message, document, QR code)
- Machine learning classification for phishing and malware detection
- Integration with threat intelligence feeds (PhishTank, URLhaus, Google Web Risk)
- SSRF protection and secure fetching
- Rate limiting and input validation
- RESTful API with FastAPI backend
- Modern React frontend with Tailwind CSS
- Docker ready for easy deployment
- GitHub Actions CI/CD pipeline

## Architecture

### Backend (Python/FastAPI)
- `trust_engine/`: Core scoring and trust evaluation
- `analyzers/`: Specialized analyzers for different content types
- `ml/`: Machine learning models and inference
- `threat_intel/`: Threat intelligence integrations
- `services/`: Business logic and orchestration
- `security/`: SSRF protection and security utilities
- `database/`: Data persistence layer

### Frontend (React/Vite/TypeScript)
- `src/components/`: Reusable UI components
- `src/pages/`: Application pages
- `src/services/`: API service layer
- `src/types/`: TypeScript type definitions
- `src/utils/`: Utility functions (risk calculation, etc.)

## Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+
- npm or yarn

### Backend Setup
1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment
4. Install dependencies: `pip install -r backend/requirements.txt`
5. Copy `.env.example` to `.env` and fill in required API keys
6. Run migrations (if any): `alembic upgrade head` (if using Alembic)
7. Start the server: `uvicorn backend.app.main:app --reload`

### Frontend Setup
1. Navigate to `frontend` directory
2. Install dependencies: `npm install`
3. Start development server: `npm run dev`

### Docker Deployment
```bash
docker build -t trustshield .
docker run -p 8000:8000 --env-file .env trustshield
```

### Environment Variables
See `.env.example` for required variables.

## API Documentation
Once the backend is running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Testing
Run tests with:
```bash
# Backend
pytest backend/

# Frontend
npm test --prefix frontend
```

## CI/CD
GitHub Actions workflow configured in `.github/workflows/ci.yml` runs tests on every push and pull request.

## License
MIT

## Acknowledgments
- Built for hackathon victory 🏆
- Inspired by TRD specifications