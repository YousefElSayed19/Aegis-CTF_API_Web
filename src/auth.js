const jwt = require('jsonwebtoken');
const db = require('./db');

const SECRET = 'aegis-internal-portal-2024';

function issueToken(employee) {
  return jwt.sign(
    {
      employee_id: employee.employee_id,
      username: employee.username,
      role: db.displayRole(employee)
    },
    SECRET,
    { algorithm: 'HS256', expiresIn: '2h' }
  );
}

function verifyStrict(token) {
  return jwt.verify(token, SECRET, { algorithms: ['HS256'] });
}


function verifyLegacy(token) {
  return verifyStrict(token);
}


function verifyGrpcToken(token) {
  if (!token || typeof token !== 'string' || token.split('.').length < 2) {
    throw new Error('missing or malformed token');
  }
  const [headerB64, payloadB64] = token.split('.');
  JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
  
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

  return payload;
}

function extractBearer(req) {
  const header = req.headers['authorization'] || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) return null;
  return token;
}

module.exports = {
  SECRET,
  issueToken,
  verifyStrict,
  verifyLegacy,
  verifyGrpcToken,
  extractBearer
};
