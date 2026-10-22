/**
 * CoAPForge Pro - Web Application Controller & State Manager
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // DOM Elements
  const profileSelect = document.getElementById('profileSelect');
  const msgType = document.getElementById('msgType');
  const msgCode = document.getElementById('msgCode');
  const uriPath = document.getElementById('uriPath');
  const contentFormat = document.getElementById('contentFormat');
  const tokenHex = document.getElementById('tokenHex');
  const observeOpt = document.getElementById('observeOpt');
  const blockSzx = document.getElementById('blockSzx');
  const payload = document.getElementById('payload');
  const btnForge = document.getElementById('btnForge');
  const btnDownloadPcap = document.getElementById('btnDownloadPcap');

  const kpiType = document.getElementById('kpiType');
  const kpiTypeSub = document.getElementById('kpiTypeSub');
  const kpiWireSize = document.getElementById('kpiWireSize');
  const kpiOptCount = document.getElementById('kpiOptCount');
  const kpiAuditScore = document.getElementById('kpiAuditScore');
  const kpiAuditGrade = document.getElementById('kpiAuditGrade');

  const hexDump = document.getElementById('hexDump');
  const decodedTree = document.getElementById('decodedTree');
  const optionsTable = document.getElementById('optionsTable');
  const blockwiseInfo = document.getElementById('blockwiseInfo');
  const blockSlicesTable = document.getElementById('blockSlicesTable');
  const retransmitTimeline = document.getElementById('retransmitTimeline');
  const batteryStats = document.getElementById('batteryStats');
  const auditList = document.getElementById('auditList');
  const synthPlatform = document.getElementById('synthPlatform');
  const synthOutput = document.getElementById('synthOutput');
  const btnCopySynth = document.getElementById('btnCopySynth');

  let currentCoapBytes = null;
  let currentWireFrame = null;
  let currentPcapBytes = null;

  // Tab Switching
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add('active');
    });
  });

  // Profile Change Handler
  profileSelect.addEventListener('change', () => {
    const pKey = profileSelect.value;
    const p = CoAPSecurityAuditor.PRESETS[pKey];
    if (!p) return;

    if (pKey === 'smart_metering_ami') {
      msgType.value = '0'; // CON
      msgCode.value = '69'; // 2.05 Content
      uriPath.value = 'grid/meter/01/consumption';
      contentFormat.value = '50'; // JSON
      tokenHex.value = 'a1b2c3d4';
      observeOpt.value = 'none';
      blockSzx.value = '128';
      payload.value = '{"kwh_delivered": 1420.85, "voltage": 240.2, "tamper": false}';
    } else if (pKey === 'medical_wearable') {
      msgType.value = '0'; // CON
      msgCode.value = '1'; // GET
      uriPath.value = 'patient/spo2/stream';
      contentFormat.value = '60'; // CBOR
      tokenHex.value = '55aa33cc';
      observeOpt.value = '0'; // Register Observe
      blockSzx.value = '64';
      payload.value = '{"interval_ms": 1000, "alarm_threshold": 92}';
    } else if (pKey === 'vulnerable_unencrypted') {
      msgType.value = '1'; // NON
      msgCode.value = '3'; // PUT
      uriPath.value = 'admin/door/unlock';
      contentFormat.value = '0'; // text/plain
      tokenHex.value = ''; // 0 bytes
      observeOpt.value = 'none';
      blockSzx.value = 'none';
      payload.value = 'FORCE_UNLOCK_ALL';
    }

    renderAll();
  });

  // Parse token hex string to byte array
  function parseTokenHex(hex) {
    if (!hex) return [];
    let clean = hex.replace(/[^0-9a-fA-F]/g, '');
    let bytes = [];
    for (let i = 0; i < clean.length; i += 2) {
      bytes.push(parseInt(clean.substr(i, 2), 16) || 0);
    }
    return bytes.slice(0, 8); // Max 8 bytes
  }

  // Primary Render Function
  function renderAll() {
    const typeVal = parseInt(msgType.value, 10);
    const codeVal = parseInt(msgCode.value, 10);
    const pathVal = uriPath.value.trim();
    const fmtVal = parseInt(contentFormat.value, 10);
    const tokenBytes = parseTokenHex(tokenHex.value);
    const obsVal = observeOpt.value;
    const blkVal = blockSzx.value;
    const payloadText = payload.value;

    // Assemble Options
    let optList = [];

    // Option 11: Uri-Path (can have multiple segments)
    if (pathVal) {
      let segments = pathVal.split('/').filter(s => s.length > 0);
      for (let seg of segments) {
        optList.push({ num: CoAPProtocolEngine.OPTIONS.URI_PATH, value: seg });
      }
    }

    // Option 12: Content-Format
    if (!isNaN(fmtVal)) {
      optList.push({ num: CoAPProtocolEngine.OPTIONS.CONTENT_FORMAT, value: fmtVal });
    }

    // Option 6: Observe
    if (obsVal !== 'none') {
      optList.push({ num: CoAPProtocolEngine.OPTIONS.OBSERVE, value: parseInt(obsVal, 10) });
    }

    // Option 23 / 27: Block-Wise Transfer (if enabled)
    let isBlockwise = (blkVal !== 'none');
    let blockSizeBytes = isBlockwise ? parseInt(blkVal, 10) : 64;

    if (isBlockwise) {
      // Determine if Block1 (Request) or Block2 (Response)
      let isReq = (codeVal >= 1 && codeVal <= 4);
      let optNum = isReq ? CoAPProtocolEngine.OPTIONS.BLOCK1 : CoAPProtocolEngine.OPTIONS.BLOCK2;
      let szxMap = { 16: 0, 32: 1, 64: 2, 128: 3, 256: 4, 512: 5, 1024: 6 };
      let szx = szxMap[blockSizeBytes] !== undefined ? szxMap[blockSizeBytes] : 2;
      let totalBytes = new TextEncoder().encode(payloadText).length;
      let more = totalBytes > blockSizeBytes;
      let blkBytes = CoAPProtocolEngine.encodeBlockOption(0, more, szx);
      optList.push({ num: optNum, value: blkBytes });
    }

    // Build CoAP Message
    let coapOpts = {
      type: typeVal,
      code: codeVal,
      messageId: 0x4A12,
      token: tokenBytes,
      options: optList,
      payload: isBlockwise ? payloadText.substr(0, blockSizeBytes) : payloadText
    };

    currentCoapBytes = CoAPProtocolEngine.forgeCoAPPacket(coapOpts);
    currentWireFrame = CoAPProtocolEngine.forgeEthernetIpUdpCoap(currentCoapBytes);
    currentPcapBytes = CoAPProtocolEngine.buildPcap([currentWireFrame]);

    // Dissect for verification
    let dissected = CoAPProtocolEngine.dissectCoAPPacket(currentCoapBytes);

    // Update KPI Stats Strip
    let typeNamesShort = ['CON', 'NON', 'ACK', 'RST'];
    kpiType.textContent = `${typeNamesShort[typeVal]} (${dissected.codeStr})`;
    let b0Hex = currentCoapBytes[0].toString(16).padStart(2, '0').toUpperCase();
    kpiTypeSub.textContent = `Control Byte 0x${b0Hex}`;
    kpiWireSize.textContent = `${currentWireFrame.length} Bytes`;
    kpiOptCount.textContent = `${dissected.options.length} Option${dissected.options.length === 1 ? '' : 's'}`;

    // Evaluate Security Audit
    const currentPresetKey = profileSelect.value;
    const currentPreset = CoAPSecurityAuditor.PRESETS[currentPresetKey] || CoAPSecurityAuditor.PRESETS.smart_metering_ami;
    const auditRes = CoAPSecurityAuditor.audit(currentPreset);

    kpiAuditScore.textContent = `${auditRes.score}/100`;
    kpiAuditGrade.textContent = `Grade ${auditRes.grade} (${auditRes.passed ? 'Certified' : 'At-Risk'})`;
    kpiAuditScore.style.color = auditRes.score >= 80 ? 'var(--accent-green)' : 'var(--accent-red)';

    // Tab 1: Hex Dump & Protocol Tree
    hexDump.textContent = CoAPProtocolEngine.formatWiresharkHexDump(currentWireFrame);

    let treeHtml = `
      <div><strong>Frame Length:</strong> ${currentWireFrame.length} bytes (IEEE 802.3 Ethernet II + IPv4 + UDP + CoAP)</div>
      <div><strong>CoAP Version:</strong> ${dissected.version} | <strong>Type:</strong> ${dissected.typeName}</div>
      <div><strong>Code:</strong> ${dissected.codeName} (0x${dissected.code.toString(16).padStart(2, '0')})</div>
      <div><strong>Message ID:</strong> 0x${dissected.messageId.toString(16).padStart(4, '0')} (${dissected.messageId})</div>
      <div><strong>Token:</strong> ${dissected.token.length > 0 ? '0x' + dissected.tokenHex + ' (' + dissected.token.length + ' bytes)' : 'None (0 bytes)'}</div>
      <div><strong>Options (${dissected.options.length}):</strong></div>
    `;
    dissected.options.forEach((opt, idx) => {
      treeHtml += `<div style="padding-left: 16px;">• [Opt ${idx+1}] #${opt.num} <strong>${opt.name}</strong> (Len ${opt.len}): ${opt.valueRepr}</div>`;
    });
    if (dissected.payload.length > 0) {
      treeHtml += `<div><strong>Payload Marker:</strong> 0xFF present</div>`;
      treeHtml += `<div><strong>Application Payload (${dissected.payload.length} bytes):</strong> <span style="color: var(--accent-amber);">${dissected.payloadStr}</span></div>`;
    }
    decodedTree.innerHTML = treeHtml;

    // Tab 2: Option Delta & Block-Wise Slices
    renderOptionDeltaTable(dissected.options);
    renderBlockwiseSlices(payloadText, blockSizeBytes, typeVal <= 4);

    // Tab 3: Retransmission Simulation & Battery Budget
    renderRetransmissionTimeline(typeVal === 0);

    // Tab 4: Zero-Trust Audit & Synthesizer
    renderSecurityAudit(auditRes);
    renderSynthesizer(currentPreset);
  }

  // Render Option Delta Table
  function renderOptionDeltaTable(opts) {
    if (!opts || opts.length === 0) {
      optionsTable.innerHTML = '<div style="color: var(--text-dim); padding: 8px 0;">No CoAP options present in this packet.</div>';
      return;
    }

    let rows = opts.map(o => {
      let dEnc = CoAPProtocolEngine.encodeOptionField(o.delta);
      let lEnc = CoAPProtocolEngine.encodeOptionField(o.len);
      let headerByte = ((dEnc.nibble & 0x0F) << 4) | (lEnc.nibble & 0x0F);
      let headerByteHex = headerByte.toString(16).padStart(2, '0').toUpperCase();

      return `
        <tr style="border-bottom: 1px solid var(--border-color);">
          <td style="padding: 8px; font-weight: 700; color: var(--accent-cyan);">#${o.num}</td>
          <td style="padding: 8px;">${o.name}</td>
          <td style="padding: 8px; font-family: var(--font-mono);">${o.delta}</td>
          <td style="padding: 8px; font-family: var(--font-mono);">${o.len} B</td>
          <td style="padding: 8px; font-family: var(--font-mono); color: var(--accent-amber);">0x${headerByteHex}</td>
          <td style="padding: 8px; color: var(--text-muted);">${o.valueRepr}</td>
        </tr>
      `;
    }).join('');

    optionsTable.innerHTML = `
      <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
        <thead>
          <tr style="border-bottom: 2px solid var(--border-color); color: var(--text-muted);">
            <th style="padding: 8px;">OPT #</th>
            <th style="padding: 8px;">NAME</th>
            <th style="padding: 8px;">DELTA</th>
            <th style="padding: 8px;">LENGTH</th>
            <th style="padding: 8px;">HEADER NIBBLES</th>
            <th style="padding: 8px;">VALUE</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  }

  // Render Block-Wise Slices
  function renderBlockwiseSlices(fullPayload, blockSize, isRequest) {
    let slices = CoAPProtocolEngine.sliceBlockwise(fullPayload, blockSize, isRequest);
    blockwiseInfo.textContent = `Payload size: ${new TextEncoder().encode(fullPayload).length} bytes | Block size: ${blockSize} bytes (SZX=${slices[0] ? slices[0].szx : 2}) | Total chunks: ${slices.length}`;

    let rows = slices.map(s => {
      return `
        <tr style="border-bottom: 1px solid var(--border-color);">
          <td style="padding: 8px; font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan);">Block #${s.num}</td>
          <td style="padding: 8px; font-family: var(--font-mono);">${s.blockSize} Bytes</td>
          <td style="padding: 8px; font-family: var(--font-mono); color: ${s.more ? 'var(--accent-amber)' : 'var(--accent-green)'}; font-weight: 600;">${s.more ? '1 (More)' : '0 (Final)'}</td>
          <td style="padding: 8px; font-family: var(--font-mono); color: var(--accent-teal);">0x${s.blockOptionHex}</td>
          <td style="padding: 8px; font-family: var(--font-mono); color: var(--text-muted); font-size: 11px;">${s.payloadSliceStr}</td>
        </tr>
      `;
    }).join('');

    blockSlicesTable.innerHTML = `
      <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
        <thead>
          <tr style="border-bottom: 2px solid var(--border-color); color: var(--text-muted);">
            <th style="padding: 8px;">BLOCK #</th>
            <th style="padding: 8px;">CHUNK SIZE</th>
            <th style="padding: 8px;">MORE (M)</th>
            <th style="padding: 8px;">BLOCK OPTION HEX</th>
            <th style="padding: 8px;">PAYLOAD SLICE</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  }

  // Render Retransmission Timeline
  function renderRetransmissionTimeline(isCon) {
    if (!isCon) {
      retransmitTimeline.innerHTML = '<div style="color: var(--text-dim); padding: 10px 0;">Non-Confirmable (NON) mode active: zero retransmissions, zero state tracking overhead.</div>';
      batteryStats.innerHTML = '<div><strong>Radio TX Burst:</strong> ~15ms @ 20mA (0.000083 mAh per report). Ideal for battery-powered environmental sensors.</div>';
      return;
    }

    let sim = CoAPProtocolEngine.simulateRetransmission({
      ackTimeout: 2.0,
      ackRandomFactor: 1.5,
      maxRetransmit: 4,
      rtt: 0.12,
      packetLossRate: 0.35 // 35% simulated cellular loss
    });

    let items = sim.attempts.map(a => {
      let isSuccess = a.outcome.includes('SUCCESS');
      return `
        <div class="timeline-item ${isSuccess ? 'success' : 'lost'}">
          <div style="font-weight: 700; color: ${isSuccess ? 'var(--accent-green)' : 'var(--accent-red)'}; font-size: 13px;">
            ${a.name} - At T+${a.startTimeSec}s
          </div>
          <div style="font-size: 12px; color: var(--text-muted);">
            Timeout window: ${a.timeoutSec}s | Status: <strong>${a.outcome}</strong>
          </div>
        </div>
      `;
    }).join('');

    retransmitTimeline.innerHTML = items;

    // Power consumption calculation
    let txCount = sim.attempts.length;
    let powerPerTxMah = 0.000083; // approx for NB-IoT / 802.15.4 radio active burst
    let totalPower = (txCount * powerPerTxMah).toFixed(6);

    batteryStats.innerHTML = `
      <div><strong>Total Retransmit Attempts:</strong> ${txCount} transmission(s) | <strong>Duration to ACK:</strong> ${sim.totalDurationSec}s</div>
      <div><strong>Energy Consumed per Report:</strong> <span style="color: var(--accent-amber); font-weight: 700;">${totalPower} mAh</span></div>
      <div><strong>Battery Impact (2000 mAh Li-SOCl2 cell):</strong> Supports approx. ${Math.floor(2000 / (txCount * powerPerTxMah)).toLocaleString()} transmissions before cell replacement.</div>
    `;
  }

  // Render Security Audit List
  function renderSecurityAudit(auditRes) {
    let items = auditRes.rules.map(r => {
      return `
        <div class="audit-item ${r.pass ? 'pass' : 'fail'}">
          <div class="audit-info">
            <h4>${r.title}</h4>
            <p>${r.reason}</p>
          </div>
          <div class="audit-score-pill ${r.pass ? 'pill-pass' : 'pill-fail'}">
            ${r.score}/${r.weight} PTS
          </div>
        </div>
      `;
    }).join('');
    auditList.innerHTML = items;
  }

  // Render Synthesizer Output
  function renderSynthesizer(preset) {
    const plat = synthPlatform.value;
    let code = '';
    if (plat === 'libcoap') code = CoAPConfigSynthesizer.generateLibCoAP(preset);
    else if (plat === 'aiocoap') code = CoAPConfigSynthesizer.generateAiocoap(preset);
    else if (plat === 'nodecoap') code = CoAPConfigSynthesizer.generateNodeCoap(preset);
    else if (plat === 'californium') code = CoAPConfigSynthesizer.generateCalifornium(preset);
    synthOutput.textContent = code;
  }

  synthPlatform.addEventListener('change', () => {
    const currentPresetKey = profileSelect.value;
    const currentPreset = CoAPSecurityAuditor.PRESETS[currentPresetKey] || CoAPSecurityAuditor.PRESETS.smart_metering_ami;
    renderSynthesizer(currentPreset);
  });

  btnCopySynth.addEventListener('click', () => {
    navigator.clipboard.writeText(synthOutput.textContent).then(() => {
      btnCopySynth.textContent = 'Copied!';
      setTimeout(() => btnCopySynth.textContent = 'Copy', 1500);
    });
  });

  btnForge.addEventListener('click', () => {
    renderAll();
  });

  // Download PCAP File
  btnDownloadPcap.addEventListener('click', () => {
    if (!currentPcapBytes) renderAll();
    const blob = new Blob([currentPcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `coap_capture_${Date.now()}.pcap`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // Initial Run
  renderAll();
});
