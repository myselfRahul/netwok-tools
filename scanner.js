'use strict';

const net = require('node:net');

const PORT_INFO = Object.freeze({
  21: ['FTP', 'HIGH', 7.5, 'FTP may transmit credentials without encryption'],
  22: ['SSH', 'INFO', 0, 'SSH administration service detected'],
  23: ['Telnet', 'HIGH', 8.0, 'Telnet is an unencrypted remote administration protocol'],
  25: ['SMTP', 'INFO', 0, 'SMTP mail service detected'],
  53: ['DNS', 'INFO', 0, 'DNS service detected'],
  80: ['HTTP', 'INFO', 0, 'Unencrypted HTTP service detected'],
  110: ['POP3', 'HIGH', 7.5, 'POP3 may transmit credentials without encryption'],
  143: ['IMAP', 'HIGH', 7.5, 'IMAP may transmit credentials without encryption'],
  443: ['HTTPS', 'INFO', 0, 'TLS-protected web service detected'],
  445: ['SMB', 'HIGH', 8.0, 'SMB exposure should be restricted to trusted networks'],
  1433: ['Microsoft SQL Server', 'HIGH', 8.0, 'Database listener should not be broadly exposed'],
  3306: ['MySQL', 'HIGH', 8.0, 'Database listener should not be broadly exposed'],
  3389: ['RDP', 'HIGH', 8.0, 'Remote desktop exposure should be restricted'],
  5432: ['PostgreSQL', 'HIGH', 8.0, 'Database listener should not be broadly exposed'],
  6379: ['Redis', 'HIGH', 8.0, 'Redis should not be exposed to untrusted networks'],
  8080: ['HTTP alternate', 'INFO', 0, 'Alternative HTTP service detected'],
  8443: ['HTTPS alternate', 'INFO', 0, 'Alternative HTTPS service detected'],
  27017: ['MongoDB', 'HIGH', 8.0, 'Database listener should not be broadly exposed']
});

function connectProbe(ip, port, timeoutMs, bannerTimeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    let banner = '';
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      const timer = setTimeout(() => finish({ open: true, banner: sanitizeBanner(banner) }), bannerTimeoutMs);
      timer.unref?.();
      socket.once('close', () => clearTimeout(timer));
    });
    socket.on('data', (chunk) => {
      if (banner.length < 256) banner += chunk.toString('utf8').slice(0, 256 - banner.length);
      if (banner.length >= 256 || banner.includes('\n')) {
        finish({ open: true, banner: sanitizeBanner(banner) });
      }
    });
    socket.once('timeout', () => finish({ open: false }));
    socket.once('error', (err) => {
      if (err.code === 'ECONNREFUSED') finish({ open: false, refused: true });
      else finish({ open: false });
    });
    socket.connect(port, ip);
  });
}

function sanitizeBanner(value) {
  return String(value || '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 200);
}

function assessPort(port, banner) {
  const info = PORT_INFO[port] || ['Unknown', 'INFO', 0, 'Unclassified TCP service'];
  const findings = [];
  // These are exposure indicators, not CVE confirmations. No CVE is asserted from a banner substring.
  if ([23, 21, 110, 143].includes(port)) {
    findings.push({
      title: `${info[0]} may expose credentials`,
      severity: info[1],
      cvss: info[2],
      evidence: `TCP/${port} accepted a connection`,
      remediation: 'Disable the cleartext service or require a secure transport such as SSH, SFTP, POP3S or IMAPS.'
    });
  } else if ([445, 1433, 3306, 3389, 5432, 6379, 27017].includes(port)) {
    findings.push({
      title: `${info[0]} network exposure`,
      severity: info[1],
      cvss: info[2],
      evidence: `TCP/${port} accepted a connection`,
      remediation: 'Restrict access using host firewall rules, network segmentation and least-privilege access.'
    });
  }
  return {
    port, service: info[0], severity: info[1], heuristicCvss: info[2],
    description: info[3], banner: banner || '', findings
  };
}

async function scanHost(ip, ports, options, signal) {
  const results = [];
  for (const port of ports) {
    if (signal.aborted) break;
    const result = await connectProbe(ip, port, options.connectTimeoutMs, options.bannerTimeoutMs);
    if (result.open) results.push(assessPort(port, result.banner));
  }
  return { ip, reachable: results.length > 0, openPorts: results };
}

module.exports = { scanHost, assessPort, sanitizeBanner, PORT_INFO };
