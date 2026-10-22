/**
 * CoAPForge Pro - 10-Point Zero-Trust CoAP & DTLS Security Auditor
 * Standard: IETF RFC 7252, RFC 7641, RFC 7959, RFC 7925 (CoAP DTLS Profile), RFC 8613 (OSCORE)
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CoAPSecurityAuditor = factory();
  }
})(typeof self !== 'undefined' ? self : this, function() {
  'use strict';

  const AUDIT_RULES = [
    {
      id: 'dtls_transport_security',
      title: 'DTLS 1.2/1.3 Transport Encryption (RFC 7925)',
      weight: 10,
      description: 'Enforces mutual TLS over UDP (coaps:// port 5684) using X.509 certificates or Pre-Shared Keys (PSK). Disables unencrypted plaintext UDP port 5683.',
      evaluate: (cfg) => {
        if (!cfg.dtls_enabled) {
          return { pass: false, score: 0, reason: 'CRITICAL: DTLS is disabled. Unencrypted UDP port 5683 exposes all sensor telemetry and control commands to passive eavesdropping and packet injection.' };
        }
        if (cfg.dtls_version !== '1.2' && cfg.dtls_version !== '1.3') {
          return { pass: false, score: 5, reason: 'WARNING: DTLS version is outdated or unspecified. DTLS 1.2 (RFC 7925) or DTLS 1.3 is required.' };
        }
        return { pass: true, score: 10, reason: `COMPLIANT: DTLS ${cfg.dtls_version} active with ${cfg.auth_mode || 'PSK/X.509'} authentication on UDP port 5684.` };
      }
    },
    {
      id: 'amplification_defense',
      title: 'UDP Amplification & Reflection Defense (RFC 7967)',
      weight: 10,
      description: 'Restricts amplification factor on anonymous or unverified requests. Requires client handshake verification or No-Response option to prevent DDoS reflection attacks.',
      evaluate: (cfg) => {
        if (cfg.amplification_protection === true) {
          return { pass: true, score: 10, reason: 'COMPLIANT: Amplification protection active (Response-to-Request ratio capped <= 3x for unverified peers; No-Response option supported).' };
        }
        return { pass: false, score: 0, reason: 'FAIL: No amplification throttling configured. CoAP server can be weaponized as a high-volume UDP reflection amplifier in DDoS attacks.' };
      }
    },
    {
      id: 'strict_option_validation',
      title: 'Strict Option Delta & Sequence Validation',
      weight: 10,
      description: 'Validates that option headers follow strictly ascending option numbers and well-formed delta/length nibbles. Discards malformed or out-of-order options.',
      evaluate: (cfg) => {
        if (cfg.strict_option_parsing === true) {
          return { pass: true, score: 10, reason: 'COMPLIANT: Strict RFC 7252 option parser active. Out-of-order or duplicate options are immediately rejected with 4.02 Bad Option.' };
        }
        return { pass: false, score: 0, reason: 'FAIL: Lenient option parsing enabled. Vulnerable to parser differential attacks and option injection fuzzing.' };
      }
    },
    {
      id: 'token_entropy',
      title: 'Cryptographic Token Entropy (>= 4 Bytes)',
      weight: 10,
      description: 'Requires tokens to have at least 4 bytes of cryptographically secure pseudo-random entropy (CSPRNG) to prevent off-path response spoofing.',
      evaluate: (cfg) => {
        const tLen = cfg.token_length_bytes !== undefined ? cfg.token_length_bytes : 0;
        if (tLen >= 4 && cfg.csprng_tokens === true) {
          return { pass: true, score: 10, reason: `COMPLIANT: High-entropy tokens (${tLen} bytes) generated via CSPRNG. Prevents off-path response spoofing.` };
        } else if (tLen > 0) {
          return { pass: false, score: 4, reason: `WEAK: Token length is only ${tLen} bytes or non-CSPRNG. Susceptible to brute-force response hijacking.` };
        }
        return { pass: false, score: 0, reason: 'FAIL: Zero-length or predictable sequential tokens configured. Vulnerable to blind injection.' };
      }
    },
    {
      id: 'observe_pruning',
      title: 'Observe Zombie Subscription Pruning (RFC 7641)',
      weight: 10,
      description: 'Periodically transmits Confirmable (CON) notifications or enforces an inactivity timeout to detect crashed observers and deallocate memory.',
      evaluate: (cfg) => {
        if (cfg.observe_con_interval_sec && cfg.observe_con_interval_sec <= 300) {
          return { pass: true, score: 10, reason: `COMPLIANT: CON heartbeat verification active every ${cfg.observe_con_interval_sec}s. Zombie observer state automatically purged upon failed MAX_RETRANSMIT.` };
        }
        return { pass: false, score: 0, reason: 'FAIL: No CON heartbeat for Observe subscriptions. Dead clients will leak server RAM indefinitely.' };
      }
    },
    {
      id: 'blockwise_memory_capping',
      title: 'Block-Wise Transfer Memory Capping (RFC 7959)',
      weight: 10,
      description: 'Enforces maximum SZX size (<= 1024 bytes) and limits total concurrent block reassembly buffers per client to prevent memory exhaustion DoS.',
      evaluate: (cfg) => {
        const maxBlock = cfg.max_block_size_bytes || 0;
        const maxBuffer = cfg.max_reassembly_buffer_kb || 0;
        if (maxBlock <= 1024 && maxBlock >= 16 && maxBuffer > 0 && maxBuffer <= 512) {
          return { pass: true, score: 10, reason: `COMPLIANT: Block size capped at ${maxBlock}B (SZX=${Math.log2(maxBlock)-4}), total reassembly buffer bounded to ${maxBuffer}KB per client.` };
        }
        return { pass: false, score: 2, reason: 'FAIL: Unbounded block reassembly buffer or invalid block size. Susceptible to memory exhaustion attacks.' };
      }
    },
    {
      id: 'anti_replay_window',
      title: 'Anti-Replay Window & Deduplication',
      weight: 10,
      description: 'Tracks message ID deduplication and DTLS epoch/sequence sliding window (>= 64 packets) to prevent replayed actuator commands.',
      evaluate: (cfg) => {
        if (cfg.anti_replay_enabled === true && (cfg.replay_window_size || 64) >= 64) {
          return { pass: true, score: 10, reason: `COMPLIANT: Anti-replay sliding window active (${cfg.replay_window_size || 64} packets). Replayed commands discarded.` };
        }
        return { pass: false, score: 0, reason: 'FAIL: Anti-replay protection disabled. Stale or duplicated actuator packets will be executed by endpoints.' };
      }
    },
    {
      id: 'resource_access_control',
      title: 'Resource-Level Access Control (RBAC / OSCORE)',
      weight: 10,
      description: 'Restricts sensitive REST methods (POST, PUT, DELETE on /firmware, /actuator, /config) to authenticated identities with least-privilege permissions.',
      evaluate: (cfg) => {
        if (cfg.rbac_enabled === true && cfg.default_policy === 'DENY') {
          return { pass: true, score: 10, reason: 'COMPLIANT: Granular RBAC active with default-deny. Sensitive write endpoints strictly restricted.' };
        }
        return { pass: false, score: 0, reason: 'FAIL: No resource-level authorization. Any client can issue PUT/DELETE requests to administrative endpoints.' };
      }
    },
    {
      id: 'ingress_rate_limiting',
      title: 'Ingress Request Rate Limiting (Token Bucket)',
      weight: 10,
      description: 'Limits maximum CoAP requests per second per IP/subnet (e.g. <= 20 req/s) to block packet flood and denial-of-service attempts.',
      evaluate: (cfg) => {
        if (cfg.rate_limit_enabled === true && cfg.max_requests_per_sec <= 50) {
          return { pass: true, score: 10, reason: `COMPLIANT: Token-bucket ingress rate limiting active (${cfg.max_requests_per_sec} req/s per IP).` };
        }
        return { pass: false, score: 0, reason: 'FAIL: No ingress rate limiting. Endpoints can be flooded with rapid CoAP queries causing battery and CPU drain.' };
      }
    },
    {
      id: 'payload_schema_validation',
      title: 'Payload Schema & Content-Format Enforcement',
      weight: 10,
      description: 'Validates that incoming payloads strictly conform to declared Content-Format (JSON, CBOR) and passes schema validation before processing.',
      evaluate: (cfg) => {
        if (cfg.schema_validation === true && cfg.max_payload_bytes <= 65536) {
          return { pass: true, score: 10, reason: `COMPLIANT: Strict payload schema validation enabled with maximum size limit of ${cfg.max_payload_bytes} bytes.` };
        }
        return { pass: false, score: 0, reason: 'FAIL: Payloads accepted without schema bounds. Vulnerable to JSON/CBOR parser bomb attacks.' };
      }
    }
  ];

  // Industry Preset Configuration Profiles
  const PRESETS = {
    smart_metering_ami: {
      name: 'Smart Grid AMI & Utility Metering (RFC 7925 Hardened)',
      dtls_enabled: true,
      dtls_version: '1.2',
      auth_mode: 'X.509 Mutual Certificate (ECDSA P-256)',
      amplification_protection: true,
      strict_option_parsing: true,
      token_length_bytes: 8,
      csprng_tokens: true,
      observe_con_interval_sec: 60,
      max_block_size_bytes: 512,
      max_reassembly_buffer_kb: 128,
      anti_replay_enabled: true,
      replay_window_size: 64,
      rbac_enabled: true,
      default_policy: 'DENY',
      rate_limit_enabled: true,
      max_requests_per_sec: 10,
      schema_validation: true,
      max_payload_bytes: 4096
    },
    medical_wearable: {
      name: 'Connected Healthcare Patient Monitor (Zero-Trust DTLS-PSK)',
      dtls_enabled: true,
      dtls_version: '1.3',
      auth_mode: 'DTLS-PSK (AES-128-CCM-8)',
      amplification_protection: true,
      strict_option_parsing: true,
      token_length_bytes: 4,
      csprng_tokens: true,
      observe_con_interval_sec: 30,
      max_block_size_bytes: 256,
      max_reassembly_buffer_kb: 64,
      anti_replay_enabled: true,
      replay_window_size: 128,
      rbac_enabled: true,
      default_policy: 'DENY',
      rate_limit_enabled: true,
      max_requests_per_sec: 5,
      schema_validation: true,
      max_payload_bytes: 2048
    },
    vulnerable_unencrypted: {
      name: 'Vulnerable Legacy Smart Home Hub (Raw UDP 5683)',
      dtls_enabled: false,
      dtls_version: 'none',
      auth_mode: 'Anonymous (None)',
      amplification_protection: false,
      strict_option_parsing: false,
      token_length_bytes: 0,
      csprng_tokens: false,
      observe_con_interval_sec: 0,
      max_block_size_bytes: 2048,
      max_reassembly_buffer_kb: 0,
      anti_replay_enabled: false,
      replay_window_size: 0,
      rbac_enabled: false,
      default_policy: 'ALLOW',
      rate_limit_enabled: false,
      max_requests_per_sec: 10000,
      schema_validation: false,
      max_payload_bytes: 1048576
    }
  };

  function audit(config) {
    let results = [];
    let totalScore = 0;
    let maxScore = 100;

    for (let rule of AUDIT_RULES) {
      let res = rule.evaluate(config);
      totalScore += res.score;
      results.push({
        id: rule.id,
        title: rule.title,
        weight: rule.weight,
        score: res.score,
        pass: res.pass,
        reason: res.reason
      });
    }

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 85) grade = 'A';
    else if (totalScore >= 75) grade = 'B';
    else if (totalScore >= 65) grade = 'C';
    else if (totalScore >= 50) grade = 'D';

    return {
      score: totalScore,
      maxScore,
      percentage: Math.round((totalScore / maxScore) * 100),
      grade,
      passed: totalScore >= 80,
      rules: results
    };
  }

  return {
    AUDIT_RULES,
    PRESETS,
    audit
  };
});
