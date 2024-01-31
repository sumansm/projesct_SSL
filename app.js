const express = require('express');
const https = require('https');

const app = express();
const port = 3000;

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
  res.sendFile('index.html', { root: __dirname });
});
app.post('/check', (req, res) => {
    const { domain } = req.body;
  
    const options = {
      method: 'GET',
      hostname: domain,
      port: 443,
    };
  
    const request = https.request(options, (response) => {
      const certificate = response.socket.getPeerCertificate();
  
      if (certificate) {
        res.json({
          success: true,
          certificateData: {
            subject: certificate.subject,
            issuer: certificate.issuer,
            valid_from: certificate.valid_from,
            valid_to: certificate.valid_to,
          },
        });
      } else {
        res.json({
          success: false,
          error: 'No SSL certificate found for the specified domain.',
        });
      }
    });
  
    request.on('error', (error) => {
      res.json({
        success: false,
        error: error.message,
      });
    });
  
    request.end();
  });
  

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
