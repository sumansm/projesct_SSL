const request = require('supertest');
const app = require('../app');

describe('SSL Checker Pro API', () => {
  describe('GET /api/health', () => {
    it('should return health status', async () => {
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      expect(response.body).toHaveProperty('status', 'healthy');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body).toHaveProperty('uptime');
      expect(response.body).toHaveProperty('environment');
      expect(response.body).toHaveProperty('version');
    });
  });

  describe('POST /api/check', () => {
    it('should validate domain input', async () => {
      const response = await request(app)
        .post('/api/check')
        .send({ domain: '' })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Validation failed');
    });

    it('should reject invalid domain format', async () => {
      const response = await request(app)
        .post('/api/check')
        .send({ domain: 'invalid-domain-format' })
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should handle valid domain check', async () => {
      const response = await request(app)
        .post('/api/check')
        .send({ domain: 'google.com' })
        .expect(200);

      expect(response.body).toHaveProperty('success');
      expect(response.body).toHaveProperty('domain', 'google.com');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body).toHaveProperty('dns');
    });
  });

  describe('POST /api/batch-check', () => {
    it('should validate batch input', async () => {
      const response = await request(app)
        .post('/api/batch-check')
        .send({ domains: [] })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Validation failed');
    });

    it('should reject too many domains', async () => {
      const domains = Array.from({ length: 11 }, (_, i) => `domain${i}.com`);
      const response = await request(app)
        .post('/api/batch-check')
        .send({ domains })
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should handle valid batch check', async () => {
      const response = await request(app)
        .post('/api/batch-check')
        .send({ domains: ['google.com', 'github.com'] })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body).toHaveProperty('results');
      expect(response.body.results).toHaveLength(2);
    });
  });

  describe('Error handling', () => {
    it('should return 404 for unknown endpoints', async () => {
      const response = await request(app)
        .get('/api/unknown')
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Endpoint not found');
    });
  });
}); 