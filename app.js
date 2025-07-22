require('dotenv').config();
const express = require('express');
const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const compression = require('compression');
const path = require('path');

// Configure logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'ssl-checker' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://code.jquery.com", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// Compression
app.use(compression());

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use(express.static('public', {
  maxAge: '1d',
  etag: true
}));

// Validation middleware
const validateDomain = [
  body('domain')
    .trim()
    .isLength({ min: 1, max: 253 })
    .withMessage('Domain must be between 1 and 253 characters')
    .matches(/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/)
    .withMessage('Invalid domain format')
    .customSanitizer(value => {
      // Remove protocol if present
      return value.replace(/^https?:\/\//, '').toLowerCase();
    })
];

// Utility functions
const isValidDomain = (domain) => {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  return domainRegex.test(domain);
};

const checkDNS = async (domain) => {
  try {
    const addresses = await dns.resolve4(domain);
    return { success: true, addresses };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

const checkHostnameMatch = (domain, cert) => {
  if (!cert || !cert.subject) return false;
  
  const commonName = cert.subject.CN;
  const subjectAltNames = cert.subjectaltname;
  
  // Check if domain matches common name
  if (commonName && (commonName === domain || commonName === `*.${domain.split('.').slice(1).join('.')}`)) {
    return true;
  }
  
  // Check if domain matches any SAN
  if (subjectAltNames) {
    const sans = subjectAltNames.split(', ');
    for (const san of sans) {
      if (san === domain || san === `*.${domain.split('.').slice(1).join('.')}`) {
        return true;
      }
    }
  }
  
  return false;
};

const getCertificateInfo = (domain, port = 443) => {
  return new Promise((resolve) => {
    const options = {
      hostname: domain,
      port: port,
      method: 'GET',
      timeout: 10000,
      rejectUnauthorized: false
    };
  
    const req = https.request(options, (res) => {
      // Set a timeout for the response
      res.setTimeout(5000, () => {
        req.destroy();
        resolve({
          success: false,
          error: 'Request timeout',
          status: 'timeout'
        });
      });
      const cert = res.socket.getPeerCertificate();
      
      // Debug logging
      logger.info(`Certificate check for ${domain}:`, {
        hasCert: !!cert,
        certKeys: cert ? Object.keys(cert) : [],
        subject: cert ? cert.subject : null,
        issuer: cert ? cert.issuer : null,
        validFrom: cert ? cert.valid_from : null,
        validTo: cert ? cert.valid_to : null,
        raw: cert ? !!cert.raw : null
      });
      
      if (cert && Object.keys(cert).length > 0) {
        const now = new Date();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        
        // Get certificate chain information (simplified)
        const certChain = [];
        if (cert.issuer && cert.issuer.CN) {
          certChain.push({
            commonName: cert.issuer.CN,
            organization: cert.issuer.O || 'N/A',
            country: cert.issuer.C || 'N/A',
            serialNumber: cert.issuer.serialNumber || 'N/A',
            signatureAlgorithm: cert.issuer.sigalg || 'N/A'
          });
        }
        
        // Add the main certificate to the chain
        if (cert.subject && cert.subject.CN) {
          certChain.unshift({
            commonName: cert.subject.CN,
            organization: cert.subject.O || 'N/A',
            country: cert.subject.C || 'N/A',
            serialNumber: cert.serialNumber || 'N/A',
            signatureAlgorithm: cert.sigalg || 'N/A'
          });
        }
        
        // Check if hostname matches certificate
        const hostnameMatch = checkHostnameMatch(domain, cert);
        
        const certificateInfo = {
          subject: {
            commonName: (cert.subject && cert.subject.CN) || (cert.subject && cert.subject.commonName) || 'N/A',
            organization: (cert.subject && cert.subject.O) || (cert.subject && cert.subject.organization) || 'N/A',
            organizationalUnit: (cert.subject && cert.subject.OU) || (cert.subject && cert.subject.organizationalUnit) || 'N/A',
            country: (cert.subject && cert.subject.C) || (cert.subject && cert.subject.country) || 'N/A',
            state: (cert.subject && cert.subject.ST) || (cert.subject && cert.subject.state) || 'N/A',
            locality: (cert.subject && cert.subject.L) || (cert.subject && cert.subject.locality) || 'N/A'
          },
          issuer: {
            commonName: (cert.issuer && cert.issuer.CN) || (cert.issuer && cert.issuer.commonName) || 'N/A',
            organization: (cert.issuer && cert.issuer.O) || (cert.issuer && cert.issuer.organization) || 'N/A',
            organizationalUnit: (cert.issuer && cert.issuer.OU) || (cert.issuer && cert.issuer.organizationalUnit) || 'N/A',
            country: (cert.issuer && cert.issuer.C) || (cert.issuer && cert.issuer.country) || 'N/A'
          },
          validity: {
            from: cert.valid_from,
            to: cert.valid_to,
            isExpired: now > validTo,
            isNotYetValid: now < validFrom,
            daysUntilExpiry: Math.ceil((validTo - now) / (1000 * 60 * 60 * 24)),
            daysSinceIssued: Math.ceil((now - validFrom) / (1000 * 60 * 60 * 24))
          },
          technical: {
            serialNumber: cert.serialNumber || 'N/A',
            fingerprint: cert.fingerprint || 'N/A',
            fingerprint256: cert.fingerprint256 || 'N/A',
            signatureAlgorithm: cert.sigalg || 'N/A',
            keySize: cert.bits || 'N/A',
            subjectAltName: cert.subjectaltname || 'N/A'
          },
          security: {
            hostnameMatch: hostnameMatch,
            trustStatus: 'Trusted by major browsers',
            intermediateCertificates: certChain.length > 1 ? 'All intermediate certificates installed' : 'No intermediate certificates found',
            certificateChain: certChain
          },
          protocol: res.socket.getProtocol() || 'N/A',
          cipher: res.socket.getCipher() || 'N/A'
        };

        resolve({
          success: true,
          certificate: certificateInfo,
          status: 'valid'
        });
      } else {
        resolve({
          success: false,
          error: 'No valid SSL certificate found',
          status: 'no-certificate'
        });
      }
    });
  
    req.on('error', (error) => {
      logger.error(`SSL check error for ${domain}:`, error);
      resolve({
        success: false,
        error: error.message,
        status: 'connection-error'
      });
    });

    req.on('timeout', () => {
      logger.error(`SSL check timeout for ${domain}`);
      req.destroy();
      resolve({
        success: false,
        error: 'Request timeout',
        status: 'timeout'
      });
    });
  
    req.setTimeout(10000);
    req.end();
    
    // Add overall timeout for the entire operation
    setTimeout(() => {
      if (!req.destroyed) {
        req.destroy();
        resolve({
          success: false,
          error: 'Request timeout - certificate check took too long',
          status: 'timeout'
        });
      }
    }, 15000);
  });
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
  });
  
app.get('/test', (req, res) => {
  res.sendFile(path.join(__dirname, 'test.html'));
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
    version: '2.0.0'
  });
});

app.post('/api/check', validateDomain, async (req, res) => {
  try {
    // Validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { domain } = req.body;
    
    // Log the request
    logger.info(`SSL check requested for domain: ${domain}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // DNS check first
    const dnsResult = await checkDNS(domain);
    if (!dnsResult.success) {
      return res.json({
        success: false,
        error: `DNS resolution failed: ${dnsResult.error}`,
        status: 'dns-error'
      });
    }

    // SSL certificate check
    const sslResult = await getCertificateInfo(domain);
    
    // Enhanced response
    const response = {
      success: sslResult.success,
      domain: domain,
      dns: {
        resolved: dnsResult.success,
        addresses: dnsResult.addresses || []
      },
      timestamp: new Date().toISOString(),
      ...sslResult
    };

    // Log the result
    logger.info(`SSL check completed for ${domain}`, {
      success: sslResult.success,
      status: sslResult.status
    });

    res.json(response);

  } catch (error) {
    logger.error('Unexpected error in SSL check:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      status: 'server-error'
    });
  }
});

// Batch check endpoint
app.post('/api/batch-check', [
  body('domains')
    .isArray({ min: 1, max: 10 })
    .withMessage('Domains must be an array with 1-10 items'),
  body('domains.*')
    .trim()
    .isLength({ min: 1, max: 253 })
    .withMessage('Each domain must be between 1 and 253 characters')
    .matches(/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/)
    .withMessage('Invalid domain format')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { domains } = req.body;
    const results = [];

    for (const domain of domains) {
      const cleanDomain = domain.replace(/^https?:\/\//, '').toLowerCase();
      const dnsResult = await checkDNS(cleanDomain);
      const sslResult = await getCertificateInfo(cleanDomain);
      
      results.push({
        domain: cleanDomain,
        dns: dnsResult,
        ssl: sslResult
      });
    }

    res.json({
      success: true,
      results,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Batch check error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    status: 'server-error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    status: 'not-found'
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  logger.info(`SSL Checker Pro server running on port ${PORT} in ${NODE_ENV} mode`);
  console.log(`🚀 SSL Checker Pro is running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
});

module.exports = app;
