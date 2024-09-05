const mongoose = require('mongoose');

// User schema
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});

// Client schema
const ClientSchema = new mongoose.Schema({
  clientId: { type: String, unique: true, required: true },
  clientSecret: { type: String, required: true },
  redirectUris: [String],
  grants: [String]  
});

// Authorization Code schema
const AuthCodeSchema = new mongoose.Schema({
  code: { type: String, unique: true, required: true },
  clientId: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  redirectUri: { type: String, required: true },
  expiresAt: { type: Date, required: true }
});

const User = mongoose.model('User', UserSchema);
const Client = mongoose.model('Client', ClientSchema);
const AuthCode = mongoose.model('AuthCode', AuthCodeSchema);

module.exports = { User, Client, AuthCode };
