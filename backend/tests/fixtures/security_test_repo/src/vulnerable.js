/**
 * SECURITY TEST FIXTURE — JavaScript
 * Intentionally vulnerable examples for Phase 6 testing.
 * FAKE test credentials only — do not use in production.
 */

// FAKE test token — synthetic only
const ACCESS_TOKEN = "TEST_SECRET_DO_NOT_USE_ghp_fake12345678901234567890";

// XSS via dangerouslySetInnerHTML
function UserGreeting({ name }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: name }} />
  );
}

// console with sensitive data
function login(password) {
  console.log("Login attempt with password:", password);
  return authenticate(password);
}

// Hardcoded localhost URL
const API_URL = "http://localhost:3000/api";

// SSRF-like pattern
async function fetchUserData(userId) {
  const url = req.query.url;  // user controlled
  const response = await fetch(url);
  return response.json();
}

// eval usage
function calculate(expr) {
  return eval(expr);
}

// TODO marker
// TODO: add input validation here
function processInput(input) {
  return input;
}
