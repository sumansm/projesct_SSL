# SSL Checker Pro

A professional SSL certificate validation and security analysis platform.

## 🚀 Quick Start

**Just run one command:**

```bash
docker-compose up
```

That's it! The application will be available at `http://localhost:3000`

## ✨ Features

- **Single Domain Check**: Analyze individual SSL certificates
- **Batch Processing**: Check multiple domains at once
- **Comprehensive Analysis**: Certificate details, validity, security status
- **Certificate Chain**: View complete certificate hierarchy
- **Professional UI**: Clean, modern interface
- **Real-time Results**: Instant SSL certificate validation

## 🔧 What Happens Automatically

- ✅ Dependencies are installed automatically
- ✅ Application builds and starts
- ✅ Health checks ensure everything is working
- ✅ Logs are saved to `./logs` directory
- ✅ Application restarts automatically if needed

## 📱 Usage

1. **Single Check**: Enter a domain name and click "Analyze SSL Certificate"
2. **Batch Check**: Enter multiple domains (one per line) and check all at once
3. **Analytics**: View statistics of your SSL checks

## 🛡️ Security Features

- **Free • Secure • Private**: No data collection, runs locally
- **Rate Limiting**: Prevents abuse
- **Input Validation**: Sanitizes all inputs
- **CORS Protection**: Secure cross-origin handling

## 🐳 Docker Commands

```bash
# Start the application
docker-compose up

# Start in background
docker-compose up -d

# Stop the application
docker-compose down

# View logs
docker-compose logs

# Rebuild and start
docker-compose up --build
```

## 📊 API Endpoints

- `GET /` - Main application
- `POST /api/check` - Single domain SSL check
- `POST /api/batch-check` - Multiple domains SSL check
- `GET /api/health` - Health check

## 🔍 Example Usage

```bash
# Check a single domain
curl -X POST http://localhost:3000/api/check \
  -H "Content-Type: application/json" \
  -d '{"domain":"google.com"}'

# Check multiple domains
curl -X POST http://localhost:3000/api/batch-check \
  -H "Content-Type: application/json" \
  -d '{"domains":["google.com","github.com","stackoverflow.com"]}'
```

## 📁 Project Structure

```
projesct_SSL/
├── app.js              # Main application server
├── index.html          # Frontend interface
├── docker-compose.yml  # Docker orchestration
├── Dockerfile          # Container configuration
├── package.json        # Dependencies
├── logs/               # Application logs
└── README.md           # This file
```

## 🎯 Requirements

- Docker
- Docker Compose

That's all you need! No Node.js installation required.

## 🔄 Updates

To update the application:

```bash
docker-compose down
docker-compose up --build
```

## 📝 License

Free to use for personal and commercial purposes.

---

**SSL Checker Pro** - Free • Secure • Private
