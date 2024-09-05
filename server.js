const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jwt-simple');
const crypto = require('crypto');
const { User, Client, AuthCode } = require('./models');

const app = express();
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost/oauth2-example');

// Utility function to generate random strings
function generateRandomString(length) {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

// Register a new client
app.post('/clients/register', async (req, res) => {
  const { redirectUris, grants } = req.body;
  const client = new Client({
    clientId: generateRandomString(16),
    clientSecret: generateRandomString(32),
    redirectUris,
    grants
  });
  await client.save();
  res.json({ clientId: client.clientId, clientSecret: client.clientSecret });
});

// Authorization Code Grant Flow
app.get('/authorize', async (req, res) => {
  const { response_type, client_id, redirect_uri, state } = req.query;

  // Find client and validate redirect URI
  const client = await Client.findOne({ clientId: client_id });
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'Invalid client or redirect URI' });
  }

  // Generate authorization code
  const code = generateRandomString(32);
  const authCode = new AuthCode({
    code,
    clientId: client_id,
    userId: '60c72b2f9b1e8a001c8f5f66',  // Mocked user ID
    redirectUri: redirect_uri,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000)  // 5 minutes expiry
  });
  await authCode.save();

  res.redirect(`${redirect_uri}?code=${code}&state=${state}`);
});

// Exchange Authorization Code for Access Token
app.post('/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

  // Validate client credentials
  const client = await Client.findOne({ clientId: client_id, clientSecret: client_secret });
  if (!client) return res.status(401).json({ error: 'Invalid client credentials' });

  if (grant_type === 'authorization_code') {
    const authCode = await AuthCode.findOne({ code, clientId: client_id, redirectUri: redirect_uri });
    if (!authCode || authCode.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'Invalid or expired authorization code' });
    }

    // Generate access token and refresh token
    const accessToken = jwt.encode({ userId: authCode.userId, clientId: client_id }, 'access_token_secret', 'HS256', { expiresIn: '1h' });
    const refreshToken = jwt.encode({ userId: authCode.userId, clientId: client_id }, 'refresh_token_secret', 'HS256', { expiresIn: '7d' });

    res.json({ accessToken, refreshToken });
    await AuthCode.deleteOne({ code });  // Clean up authorization code
  } else {
    res.status(400).json({ error: 'Unsupported grant type' });
  }
});

// Refresh Access Token
app.post('/token/refresh', async (req, res) => {
  const { grant_type, refresh_token, client_id, client_secret } = req.body;

  // Validate client credentials
  const client = await Client.findOne({ clientId: client_id, clientSecret: client_secret });
  if (!client) return res.status(401).json({ error: 'Invalid client credentials' });

  if (grant_type === 'refresh_token') {
    try {
      const decoded = jwt.decode(refresh_token, 'refresh_token_secret');
      const accessToken = jwt.encode({ userId: decoded.userId, clientId: client_id }, 'access_token_secret', 'HS256', { expiresIn: '1h' });
      const newRefreshToken = jwt.encode({ userId: decoded.userId, clientId: client_id }, 'refresh_token_secret', 'HS256', { expiresIn: '7d' });
      res.json({ accessToken, refreshToken: newRefreshToken });
    } catch (err) {
      res.status(400).json({ error: 'Invalid refresh token' });
    }
  } else {
    res.status(400).json({ error: 'Unsupported grant type' });
  }
});

// Protect a resource
app.get('/resource', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  try {
    const decoded = jwt.decode(token, 'access_token_secret');
    // Here you would check if the token is valid and if the user has access to the requested resource
    res.json({ message: 'Access granted', userId: decoded.userId });
  } catch (err) {
    res.status(401).json({ error: 'Invalid access token' });
  }
});

app.listen(3000, () => {
  console.log('OAuth 2.0 server running on http://localhost:3000');
});
