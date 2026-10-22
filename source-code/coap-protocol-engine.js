/**
 * CoAPForge Pro - Core Protocol & Wireframe Framing Engine
 * Standard: IETF RFC 7252 (CoAP), RFC 7641 (Observe), RFC 7959 (Block-Wise)
 * IEEE 802.3 Ethernet II + IETF RFC 791 IPv4 + RFC 768 UDP + RFC 1071 Checksum
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CoAPProtocolEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function() {
  'use strict';

  // CoAP Constants
  const TYPES = {
    CON: 0, // Confirmable
    NON: 1, // Non-confirmable
    ACK: 2, // Acknowledgement
    RST: 3  // Reset
  };

  const TYPE_NAMES = {
    0: 'CON (Confirmable)',
    1: 'NON (Non-confirmable)',
    2: 'ACK (Acknowledgement)',
    3: 'RST (Reset)'
  };

  // CoAP Method Codes (Class 0)
  const CODES = {
    EMPTY: 0x00,
    GET: 0x01,
    POST: 0x02,
    PUT: 0x03,
    DELETE: 0x04,
    // Response Codes
    CREATED: 0x41,      // 2.01
    DELETED: 0x42,      // 2.02
    VALID: 0x43,        // 2.03
    CHANGED: 0x44,      // 2.04
    CONTENT: 0x45,      // 2.05
    CONTINUE: 0x5F,     // 2.31 (Block1)
    BAD_REQUEST: 0x80,  // 4.00
    UNAUTHORIZED: 0x81, // 4.01
    BAD_OPTION: 0x82,   // 4.02
    FORBIDDEN: 0x83,    // 4.03
    NOT_FOUND: 0x84,    // 4.04
    METHOD_NOT_ALLOWED: 0x85, // 4.05
    NOT_ACCEPTABLE: 0x86,     // 4.06
    ENTITY_INCOMPLETE: 0x88,  // 4.08 (Block-wise)
    PRECONDITION_FAILED: 0x8C,// 4.12
    REQUEST_TOO_LARGE: 0x8D,  // 4.13
    UNSUPPORTED_FORMAT: 0x8F, // 4.15
    INTERNAL_SERVER_ERROR: 0xA0, // 5.00
    NOT_IMPLEMENTED: 0xA1,       // 5.01
    BAD_GATEWAY: 0xA2,           // 5.02
    SERVICE_UNAVAILABLE: 0xA3,   // 5.03
    GATEWAY_TIMEOUT: 0xA4,       // 5.04
    PROXYING_NOT_SUPPORTED: 0xA5 // 5.05
  };

  const CODE_NAMES = {
    0x00: '0.00 Empty',
    0x01: '0.01 GET',
    0x02: '0.02 POST',
    0x03: '0.03 PUT',
    0x04: '0.04 DELETE',
    0x41: '2.01 Created',
    0x42: '2.02 Deleted',
    0x43: '2.03 Valid',
    0x44: '2.04 Changed',
    0x45: '2.05 Content',
    0x5F: '2.31 Continue',
    0x80: '4.00 Bad Request',
    0x81: '4.01 Unauthorized',
    0x82: '4.02 Bad Option',
    0x83: '4.03 Forbidden',
    0x84: '4.04 Not Found',
    0x85: '4.05 Method Not Allowed',
    0x86: '4.06 Not Acceptable',
    0x88: '4.08 Request Entity Incomplete',
    0x8C: '4.12 Precondition Failed',
    0x8D: '4.13 Request Entity Too Large',
    0x8F: '4.15 Unsupported Content-Format',
    0xA0: '5.00 Internal Server Error',
    0xA1: '5.01 Not Implemented',
    0xA2: '5.02 Bad Gateway',
    0xA3: '5.03 Service Unavailable',
    0xA4: '5.04 Gateway Timeout',
    0xA5: '5.05 Proxying Not Supported'
  };

  // CoAP Standard Option Numbers (IETF RFC 7252 / 7641 / 7959)
  const OPTIONS = {
    IF_MATCH: 1,
    URI_HOST: 3,
    ETAG: 4,
    IF_NONE_MATCH: 5,
    OBSERVE: 6,         // RFC 7641
    URI_PORT: 7,
    LOCATION_PATH: 8,
    URI_PATH: 11,
    CONTENT_FORMAT: 12,
    MAX_AGE: 14,
    URI_QUERY: 15,
    ACCEPT: 17,
    LOCATION_QUERY: 20,
    BLOCK2: 23,         // RFC 7959
    BLOCK1: 27,         // RFC 7959
    SIZE2: 28,          // RFC 7959
    PROXY_URI: 35,
    PROXY_SCHEME: 39,
    SIZE1: 60
  };

  const OPTION_NAMES = {
    1: 'If-Match',
    3: 'Uri-Host',
    4: 'ETag',
    5: 'If-None-Match',
    6: 'Observe',
    7: 'Uri-Port',
    8: 'Location-Path',
    11: 'Uri-Path',
    12: 'Content-Format',
    14: 'Max-Age',
    15: 'Uri-Query',
    17: 'Accept',
    20: 'Location-Query',
    23: 'Block2',
    27: 'Block1',
    28: 'Size2',
    35: 'Proxy-Uri',
    39: 'Proxy-Scheme',
    60: 'Size1'
  };

  const CONTENT_FORMATS = {
    0: 'text/plain;charset=utf-8',
    40: 'application/link-format',
    41: 'application/xml',
    42: 'application/octet-stream',
    47: 'application/exi',
    50: 'application/json',
    60: 'application/cbor'
  };

  // CRC32 Table for IEEE 802.3 Ethernet Frame Check Sequence
  const CRC32_TABLE = (function() {
    let c, table = [];
    for (let n = 0; n < 256; n++) {
      c = n;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[n] = c >>> 0;
    }
    return table;
  })();

  function calculateCRC32(bytes) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) {
      crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
    }
    return ((crc ^ 0xFFFFFFFF) >>> 0);
  }

  // RFC 1071 16-bit One's Complement Internet Checksum
  function calculateRFC1071Checksum(bytes) {
    let sum = 0;
    for (let i = 0; i < bytes.length; i += 2) {
      let b1 = bytes[i];
      let b2 = (i + 1 < bytes.length) ? bytes[i + 1] : 0;
      sum += (b1 << 8) | b2;
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (~sum) & 0xFFFF;
  }

  // Calculate Option Delta/Length Nibble & Extended Bytes
  function encodeOptionField(val) {
    if (val < 13) {
      return { nibble: val, extBytes: [] };
    } else if (val < 269) {
      return { nibble: 13, extBytes: [val - 13] };
    } else if (val < 65805) {
      let diff = val - 269;
      return { nibble: 14, extBytes: [(diff >> 8) & 0xFF, diff & 0xFF] };
    } else {
      throw new Error(`CoAP Option value too large: ${val}`);
    }
  }

  function decodeOptionField(nibble, reader) {
    if (nibble < 13) {
      return nibble;
    } else if (nibble === 13) {
      if (reader.pos >= reader.bytes.length) throw new Error('Truncated 1-byte option field extension');
      return reader.bytes[reader.pos++] + 13;
    } else if (nibble === 14) {
      if (reader.pos + 1 >= reader.bytes.length) throw new Error('Truncated 2-byte option field extension');
      let b1 = reader.bytes[reader.pos++];
      let b2 = reader.bytes[reader.pos++];
      return ((b1 << 8) | b2) + 269;
    } else {
      throw new Error('Invalid option field nibble 15 in header');
    }
  }

  // Encode Block1 / Block2 Option Value (RFC 7959)
  // Value = (NUM << 4) | (M << 3) | SZX
  function encodeBlockOption(num, m, szx) {
    let raw = (num << 4) | ((m ? 1 : 0) << 3) | (szx & 0x07);
    if (raw < 256) {
      return [raw & 0xFF];
    } else if (raw < 65536) {
      return [(raw >> 8) & 0xFF, raw & 0xFF];
    } else {
      return [(raw >> 16) & 0xFF, (raw >> 8) & 0xFF, raw & 0xFF];
    }
  }

  function decodeBlockOption(bytes) {
    let val = 0;
    for (let b of bytes) {
      val = (val << 8) | b;
    }
    let szx = val & 0x07;
    let m = Boolean((val >> 3) & 0x01);
    let num = val >> 4;
    let blockSize = 1 << (szx + 4);
    return { num, m, szx, blockSize, raw: val };
  }

  // Encode arbitrary Uint value into minimal bytes
  function encodeUint(val) {
    if (val === 0) return [];
    let bytes = [];
    while (val > 0) {
      bytes.unshift(val & 0xFF);
      val = Math.floor(val / 256);
    }
    return bytes;
  }

  function decodeUint(bytes) {
    let val = 0;
    for (let b of bytes) {
      val = (val * 256) + b;
    }
    return val;
  }

  // Forge a raw CoAP packet (RFC 7252)
  function forgeCoAPPacket(options) {
    const ver = 1;
    const type = (options.type !== undefined) ? options.type : TYPES.CON;
    const code = (options.code !== undefined) ? options.code : CODES.GET;
    const messageId = (options.messageId !== undefined) ? (options.messageId & 0xFFFF) : 0x1234;
    const token = options.token ? Array.from(options.token) : [0x7A, 0x8B];
    const tkl = Math.min(token.length, 8);

    let packet = [];

    // Byte 0: Ver (2) | Type (2) | TKL (4)
    let b0 = ((ver & 0x03) << 6) | ((type & 0x03) << 4) | (tkl & 0x0F);
    packet.push(b0);
    // Byte 1: Code
    packet.push(code & 0xFF);
    // Bytes 2..3: Message ID
    packet.push((messageId >> 8) & 0xFF);
    packet.push(messageId & 0xFF);

    // Token (0..8 bytes)
    for (let i = 0; i < tkl; i++) {
      packet.push(token[i] & 0xFF);
    }

    // Sort options strictly ascending by Option Number
    let rawOptions = options.options || [];
    // Normalize options
    let optList = [];
    for (let opt of rawOptions) {
      let num = opt.num;
      let valBytes = [];
      if (typeof opt.value === 'string') {
        valBytes = Array.from(new TextEncoder().encode(opt.value));
      } else if (Array.isArray(opt.value) || (typeof Uint8Array !== 'undefined' && opt.value instanceof Uint8Array)) {
        valBytes = Array.from(opt.value);
      } else if (typeof opt.value === 'number') {
        valBytes = encodeUint(opt.value);
      }
      optList.push({ num, valBytes });
    }
    optList.sort((a, b) => a.num - b.num);

    let lastNum = 0;
    for (let opt of optList) {
      let delta = opt.num - lastNum;
      lastNum = opt.num;
      let len = opt.valBytes.length;

      let dEnc = encodeOptionField(delta);
      let lEnc = encodeOptionField(len);

      let headerByte = ((dEnc.nibble & 0x0F) << 4) | (lEnc.nibble & 0x0F);
      packet.push(headerByte);
      for (let eb of dEnc.extBytes) packet.push(eb);
      for (let eb of lEnc.extBytes) packet.push(eb);
      for (let vb of opt.valBytes) packet.push(vb);
    }

    // Payload Marker & Payload
    let payloadBytes = [];
    if (typeof options.payload === 'string') {
      payloadBytes = Array.from(new TextEncoder().encode(options.payload));
    } else if (Array.isArray(options.payload) || (typeof Uint8Array !== 'undefined' && options.payload instanceof Uint8Array)) {
      payloadBytes = Array.from(options.payload);
    }

    if (payloadBytes.length > 0) {
      packet.push(0xFF); // Payload Marker
      for (let pb of payloadBytes) packet.push(pb);
    }

    return new Uint8Array(packet);
  }

  // Dissect a CoAP packet (RFC 7252)
  function dissectCoAPPacket(bytes) {
    if (!bytes || bytes.length < 4) {
      throw new Error(`CoAP frame too short: ${bytes ? bytes.length : 0} bytes (minimum 4 bytes required)`);
    }

    let b0 = bytes[0];
    let ver = (b0 >> 6) & 0x03;
    let type = (b0 >> 4) & 0x03;
    let tkl = b0 & 0x0F;

    if (ver !== 1) {
      throw new Error(`Unsupported CoAP version: ${ver} (must be 1)`);
    }
    if (tkl > 8) {
      throw new Error(`Invalid Token Length ${tkl} (maximum 8 bytes per RFC 7252)`);
    }

    let code = bytes[1];
    let codeClass = (code >> 5) & 0x07;
    let codeDetail = code & 0x1F;
    let codeStr = `${codeClass}.${codeDetail < 10 ? '0' + codeDetail : codeDetail}`;
    let codeName = CODE_NAMES[code] || `Code ${codeStr}`;

    let messageId = (bytes[2] << 8) | bytes[3];

    let pos = 4;
    let token = [];
    for (let i = 0; i < tkl; i++) {
      if (pos >= bytes.length) throw new Error('Truncated token in CoAP frame');
      token.push(bytes[pos++]);
    }

    let reader = { bytes, pos };
    let parsedOptions = [];
    let lastOptionNum = 0;
    let payload = new Uint8Array(0);

    while (reader.pos < bytes.length) {
      let b = bytes[reader.pos++];
      if (b === 0xFF) {
        // Payload Marker encountered
        payload = bytes.slice(reader.pos);
        break;
      }

      let deltaNibble = (b >> 4) & 0x0F;
      let lenNibble = b & 0x0F;

      let delta = decodeOptionField(deltaNibble, reader);
      let len = decodeOptionField(lenNibble, reader);

      let optionNum = lastOptionNum + delta;
      lastOptionNum = optionNum;

      if (reader.pos + len > bytes.length) {
        throw new Error(`Option ${optionNum} truncated: requires ${len} bytes, only ${bytes.length - reader.pos} left`);
      }

      let valBytes = bytes.slice(reader.pos, reader.pos + len);
      reader.pos += len;

      let repr = '';
      let optName = OPTION_NAMES[optionNum] || `Option ${optionNum}`;

      if (optionNum === OPTIONS.URI_PATH || optionNum === OPTIONS.URI_HOST || optionNum === OPTIONS.LOCATION_PATH || optionNum === OPTIONS.URI_QUERY) {
        repr = new TextDecoder().decode(valBytes);
      } else if (optionNum === OPTIONS.CONTENT_FORMAT || optionNum === OPTIONS.ACCEPT) {
        let fmtId = decodeUint(valBytes);
        repr = `${fmtId} (${CONTENT_FORMATS[fmtId] || 'Unknown'})`;
      } else if (optionNum === OPTIONS.BLOCK1 || optionNum === OPTIONS.BLOCK2) {
        let blk = decodeBlockOption(valBytes);
        repr = `NUM=${blk.num}, M=${blk.m ? 1 : 0}, SZX=${blk.szx} (${blk.blockSize}B)`;
      } else if (optionNum === OPTIONS.OBSERVE) {
        let obsVal = decodeUint(valBytes);
        repr = obsVal === 0 ? '0 (Register)' : obsVal === 1 ? '1 (Deregister)' : `${obsVal}`;
      } else {
        repr = Array.from(valBytes).map(x => x.toString(16).padStart(2, '0')).join(' ');
      }

      parsedOptions.push({
        num: optionNum,
        name: optName,
        delta,
        len,
        rawBytes: Array.from(valBytes),
        valueRepr: repr
      });
    }

    let payloadStr = '';
    try {
      payloadStr = new TextDecoder('utf-8', { fatal: false }).decode(payload);
    } catch (_) {
      payloadStr = `[Binary: ${payload.length} bytes]`;
    }

    return {
      version: ver,
      type,
      typeName: TYPE_NAMES[type] || `Type ${type}`,
      code,
      codeStr,
      codeName,
      messageId,
      token: Array.from(token),
      tokenHex: Array.from(token).map(b => b.toString(16).padStart(2, '0')).join(''),
      options: parsedOptions,
      payload: Array.from(payload),
      payloadStr,
      rawLength: bytes.length
    };
  }

  // Split payload into RFC 7959 Block-Wise Transfer chunks
  function sliceBlockwise(payloadStr, blockSize = 64, isRequest = true) {
    let fullBytes = Array.from(new TextEncoder().encode(payloadStr));
    let szxMap = { 16: 0, 32: 1, 64: 2, 128: 3, 256: 4, 512: 5, 1024: 6 };
    let szx = szxMap[blockSize];
    if (szx === undefined) szx = 2; // Default 64 bytes
    let actualSize = 1 << (szx + 4);

    let blocks = [];
    let totalBlocks = Math.ceil(fullBytes.length / actualSize) || 1;

    for (let i = 0; i < totalBlocks; i++) {
      let start = i * actualSize;
      let end = Math.min(start + actualSize, fullBytes.length);
      let slice = fullBytes.slice(start, end);
      let more = (i < totalBlocks - 1);

      let blkOpt = encodeBlockOption(i, more, szx);
      blocks.push({
        num: i,
        more,
        szx,
        blockSize: actualSize,
        totalBlocks,
        payloadSlice: slice,
        payloadSliceStr: new TextDecoder().decode(new Uint8Array(slice)),
        blockOptionBytes: blkOpt,
        blockOptionHex: blkOpt.map(b => b.toString(16).padStart(2, '0')).join(''),
        isBlock1: isRequest,
        isBlock2: !isRequest
      });
    }
    return blocks;
  }

  // Simulate RFC 7252 Exponential Backoff Retransmissions
  function simulateRetransmission(conParams = {}) {
    const ackTimeout = conParams.ackTimeout || 2.0; // 2 seconds
    const ackRandomFactor = conParams.ackRandomFactor || 1.5;
    const maxRetransmit = conParams.maxRetransmit !== undefined ? conParams.maxRetransmit : 4;
    const rtt = conParams.rtt || 0.15; // 150ms round-trip
    const packetLossRate = conParams.packetLossRate !== undefined ? conParams.packetLossRate : 0.4; // 40% loss simulation

    let attempts = [];
    let currentTimeout = ackTimeout;
    let simTime = 0.0;
    let success = false;

    for (let attempt = 0; attempt <= maxRetransmit; attempt++) {
      let isLost = (attempt < maxRetransmit && Math.random() < packetLossRate) || (attempt === 0 && packetLossRate > 0);
      let eventName = attempt === 0 ? 'Initial CON Transmission' : `Retransmit #${attempt}`;

      attempts.push({
        attempt,
        name: eventName,
        startTimeSec: parseFloat(simTime.toFixed(3)),
        timeoutSec: parseFloat(currentTimeout.toFixed(3)),
        outcome: isLost ? 'TIMEOUT (Packet/ACK Lost)' : 'SUCCESS (ACK Received)',
        lossSimulated: isLost
      });

      if (!isLost) {
        simTime += rtt;
        success = true;
        break;
      }

      simTime += currentTimeout;
      currentTimeout *= 2; // Exponential backoff
    }

    return {
      success,
      totalDurationSec: parseFloat(simTime.toFixed(3)),
      maxRetransmit,
      ackTimeout,
      attempts
    };
  }

  // Assemble Complete Ethernet II + IPv4 + UDP + CoAP Packet Frame
  function forgeEthernetIpUdpCoap(coapBytes, config = {}) {
    const srcMac = config.srcMac || [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
    const dstMac = config.dstMac || [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const srcIp = config.srcIp || [192, 168, 1, 50];
    const dstIp = config.dstIp || [192, 168, 1, 1];
    const srcPort = config.srcPort || 49152;
    const dstPort = config.dstPort || 5683; // CoAP Default

    let ipTotalLength = 20 + 8 + coapBytes.length; // IP (20) + UDP (8) + CoAP
    let ipHeader = [
      0x45,               // Version 4, Header Length 5 (20 bytes)
      0x00,               // DSCP / ECN
      (ipTotalLength >> 8) & 0xFF,
      ipTotalLength & 0xFF,
      0x1A, 0x2B,         // Identification
      0x40, 0x00,         // Don't Fragment (DF)
      64,                 // TTL (64 hops)
      17,                 // Protocol: UDP (17)
      0x00, 0x00,         // Header Checksum (calculated below)
      srcIp[0], srcIp[1], srcIp[2], srcIp[3],
      dstIp[0], dstIp[1], dstIp[2], dstIp[3]
    ];

    let ipCksum = calculateRFC1071Checksum(ipHeader);
    ipHeader[10] = (ipCksum >> 8) & 0xFF;
    ipHeader[11] = ipCksum & 0xFF;

    // UDP Header (8 bytes)
    let udpLength = 8 + coapBytes.length;
    let udpHeader = [
      (srcPort >> 8) & 0xFF, srcPort & 0xFF,
      (dstPort >> 8) & 0xFF, dstPort & 0xFF,
      (udpLength >> 8) & 0xFF, udpLength & 0xFF,
      0x00, 0x00          // UDP Checksum (calculated below)
    ];

    // UDP Pseudo-Header for Checksum
    let pseudoHeader = [
      srcIp[0], srcIp[1], srcIp[2], srcIp[3],
      dstIp[0], dstIp[1], dstIp[2], dstIp[3],
      0x00, 17, // Zero, Protocol UDP
      (udpLength >> 8) & 0xFF, udpLength & 0xFF
    ];

    let udpPayloadForChecksum = pseudoHeader.concat(udpHeader).concat(Array.from(coapBytes));
    let udpCksum = calculateRFC1071Checksum(udpPayloadForChecksum);
    if (udpCksum === 0) udpCksum = 0xFFFF; // RFC 768 rule: 0 checksum transmitted as 0xFFFF
    udpHeader[6] = (udpCksum >> 8) & 0xFF;
    udpHeader[7] = udpCksum & 0xFF;

    // Ethernet II Header (14 bytes)
    let ethHeader = dstMac.concat(srcMac).concat([0x08, 0x00]); // EtherType 0x0800 IPv4

    let frameNoFcs = ethHeader.concat(ipHeader).concat(udpHeader).concat(Array.from(coapBytes));

    // Pad to Ethernet minimum payload 46 bytes (total frame 60 bytes before FCS)
    while (frameNoFcs.length < 60) {
      frameNoFcs.push(0x00);
    }

    let fcs = calculateCRC32(frameNoFcs);
    let finalFrame = frameNoFcs.concat([
      (fcs >> 24) & 0xFF,
      (fcs >> 16) & 0xFF,
      (fcs >> 8) & 0xFF,
      fcs & 0xFF
    ]);

    return new Uint8Array(finalFrame);
  }

  // Build standard PCAP file binary buffer
  function buildPcap(frames, timestampSec = 1791000000) {
    let pcapBytes = [];

    // PCAP Global Header (24 bytes)
    // Magic: 0xA1B2C3D4 (standard microsecond resolution)
    pcapBytes.push(0xD4, 0xC3, 0xB2, 0xA1); // Little endian magic
    pcapBytes.push(0x02, 0x00); // Version Major (2)
    pcapBytes.push(0x04, 0x00); // Version Minor (4)
    pcapBytes.push(0x00, 0x00, 0x00, 0x00); // Thiszone (GMT 0)
    pcapBytes.push(0x00, 0x00, 0x00, 0x00); // Sigfigs (0)
    pcapBytes.push(0xFF, 0xFF, 0x00, 0x00); // Snaplen (65535)
    pcapBytes.push(0x01, 0x00, 0x00, 0x00); // Network: LINKTYPE_ETHERNET (1)

    for (let i = 0; i < frames.length; i++) {
      let frame = frames[i];
      let len = frame.length;
      let tsSec = timestampSec + i;
      let tsUsec = 100000 * i;

      // Packet Record Header (16 bytes, little endian)
      pcapBytes.push(tsSec & 0xFF, (tsSec >> 8) & 0xFF, (tsSec >> 16) & 0xFF, (tsSec >> 24) & 0xFF);
      pcapBytes.push(tsUsec & 0xFF, (tsUsec >> 8) & 0xFF, (tsUsec >> 16) & 0xFF, (tsUsec >> 24) & 0xFF);
      pcapBytes.push(len & 0xFF, (len >> 8) & 0xFF, (len >> 16) & 0xFF, (len >> 24) & 0xFF); // Incl Len
      pcapBytes.push(len & 0xFF, (len >> 8) & 0xFF, (len >> 16) & 0xFF, (len >> 24) & 0xFF); // Orig Len

      for (let b of frame) {
        pcapBytes.push(b);
      }
    }

    return new Uint8Array(pcapBytes);
  }

  // Format Wireshark-Style Hex Dump
  function formatWiresharkHexDump(bytes) {
    let lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      let offset = i.toString(16).padStart(4, '0');
      let hexPart = [];
      let asciiPart = [];
      for (let j = 0; j < 16; j++) {
        if (i + j < bytes.length) {
          let b = bytes[i + j];
          hexPart.push(b.toString(16).padStart(2, '0'));
          asciiPart.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '.');
        } else {
          hexPart.push('  ');
          asciiPart.push(' ');
        }
      }
      let leftHalf = hexPart.slice(0, 8).join(' ');
      let rightHalf = hexPart.slice(8, 16).join(' ');
      lines.push(`${offset}   ${leftHalf}  ${rightHalf}   ${asciiPart.join('')}`);
    }
    return lines.join('\n');
  }

  return {
    TYPES,
    TYPE_NAMES,
    CODES,
    CODE_NAMES,
    OPTIONS,
    OPTION_NAMES,
    CONTENT_FORMATS,
    calculateCRC32,
    calculateRFC1071Checksum,
    encodeOptionField,
    decodeOptionField,
    encodeBlockOption,
    decodeBlockOption,
    encodeUint,
    decodeUint,
    forgeCoAPPacket,
    dissectCoAPPacket,
    sliceBlockwise,
    simulateRetransmission,
    forgeEthernetIpUdpCoap,
    buildPcap,
    formatWiresharkHexDump
  };
});
