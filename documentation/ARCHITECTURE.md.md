# CoAPForge Pro (v1.0.0) — Technical Architecture & Protocol Engineering Manual

## 1\. System Overview

**CoAPForge Pro** is an enterprise IoT protocol engineering and zero-trust security studio implementing:

* **IETF RFC 7252**: The Constrained Application Protocol (CoAP).  
* **IETF RFC 7641**: Observing Resources in the Constrained Application Protocol (CoAP Pub/Sub).  
* **IETF RFC 7959**: Block-Wise Transfers in the Constrained Application Protocol (CoAP Block1 & Block2).  
* **IETF RFC 7925**: Transport Layer Security (TLS) / Datagram Transport Layer Security (DTLS) Profiles for the Internet of Things.  
* **IETF RFC 768 / RFC 1071**: Computing the Internet Checksum for UDP and IPv4.  
* **IEEE 802.3**: Ethernet II Framing and CRC32 Frame Check Sequence (FCS).

       \+-------------------------------------------------------------+

       |               Incoming CoAP Message (UDP Port 5683/5684)    |

       |  \[Ver: 2 bits | Type: 2 bits | TKL: 4 bits | Code: 8 bits\] |

       |  \[Message ID: 16 bits (Network Byte Order)\]                 |

       \+-------------------------------------------------------------+

                                      |

                                      v

       \+-------------------------------------------------------------+

       |               Token (0 to 8 bytes)                          |

       \+-------------------------------------------------------------+

                                      |

                                      v

       \+-------------------------------------------------------------+

       |               Sequential Delta-Encoded Options              |

       |  \[Option Delta (4b) | Option Length (4b) | Extended Bytes\]  |

       |  \[Option Value (Length Bytes)\]                              |

       \+-------------------------------------------------------------+

                                      |

                                      v

       \+-------------------------------------------------------------+

       |   Payload Marker (0xFF) & Application Payload (JSON/CBOR)   |

       \+-------------------------------------------------------------+

---

## 2\. Mathematical Formalisms & Framing

### 2.1 CoAP Fixed 4-Byte Header (RFC 7252 Section 3\)

* **Byte 0**:  
  - `Ver` (Bits 7..6): Version number, strictly `1` (`0b01`).  
  - `T` (Bits 5..4): Message Type:  
    - `0` (`0b00`): **CON** (Confirmable)  
    - `1` (`0b01`): **NON** (Non-confirmable)  
    - `2` (`0b10`): **ACK** (Acknowledgement)  
    - `3` (`0b11`): **RST** (Reset)  
  - `TKL` (Bits 3..0): Token Length (0 to 8 bytes). Values 9–15 are invalid.  
* **Byte 1**: `Code` (8 bits):  
  - Expressed as `c.dd` where `c` is 3 bits (0..7) and `dd` is 5 bits (0..31): \$\$\\text{Code Byte} \= (c \\ll 5\) \\lor (dd \\ & \\ 0x1F)\$\$  
* **Bytes 2..3**: `Message ID` (16-bit unsigned integer, network byte order).

### 2.2 Sequential Option Delta Encoding (RFC 7252 Section 3.1)

Options must be sorted strictly in ascending numeric order. For each option \$k\$, the delta is: \$\$\\Delta\_k \= \\text{Option\_Number}*k \- \\text{Option\_Number}*{k-1} \\quad (\\text{with } \\text{Option\_Number}\_0 \= 0)\$\$

The Option Header byte is: \$\$\\text{Header Byte} \= (\\text{Delta\_Nibble} \\ll 4\) \\lor \\text{Length\_Nibble}\$\$

Encoding rules for Delta and Length:

* Value \$0 \\le V \\le 12\$: Nibble \$= V\$, \$0\$ extension bytes.  
* Value \$13 \\le V \\le 268\$: Nibble \$= 13\$, \$1\$ extension byte storing \$(V \- 13)\$.  
* Value \$269 \\le V \\le 65804\$: Nibble \$= 14\$, \$2\$ extension bytes storing \$(V \- 269)\$ in network byte order.  
* Nibble \$= 15\$: Reserved (Used as `0xFF` Payload Marker).

### 2.3 Block-Wise Transfers (RFC 7959\)

Option 23 (`Block2` for response payloads) and Option 27 (`Block1` for request payloads) slice arbitrary large payloads across MTU-constrained links: \$\$\\text{Option Value} \= (\\text{NUM} \\ll 4\) \\lor ((\\text{M} \\ & \\ 1\) \\ll 3\) \\lor (\\text{SZX} \\ & \\ 0x07)\$\$ Where:

* \$\\text{SZX} \\in {0, 1, ..., 6}\$ represents block size \$2^{(\\text{SZX} \+ 4)}\$ bytes (\$16\\text{ B}\$ to \$1024\\text{ B}\$).  
* \$\\text{M}\$ is the More flag (\$1 \= \\text{more blocks follow}, 0 \= \\text{last block}\$).  
* \$\\text{NUM}\$ is the 0-indexed block sequence number.

### 2.4 RFC 7252 Exponential Backoff Retransmission

When a client sends a **CON** packet, it initiates a retransmission timer: \$\$\\text{Initial Timeout} \= \\text{ACK\_TIMEOUT} \\times (1.0 \+ \\text{rand}(0, \\text{ACK\_RANDOM\_FACTOR} \- 1.0))\$\$ For each failed transmission \$a \\in {1, 2, ..., \\text{MAX\_RETRANSMIT}}\$: \$\$\\text{Timeout}*a \= \\text{Timeout}*{a-1} \\times 2\$\$ If no ACK is received after \$\\text{MAX\_RETRANSMIT} \= 4\$ attempts, the transaction is declared dead.

---

## 3\. Zero-Trust Security Architecture

1. **DTLS Transport Encryption (RFC 7925\)**: Mandates mutual authentication via X.509 certificates or Pre-Shared Keys (PSK) on port 5684 (`coaps://`). Disables plaintext port 5683\.  
2. **Amplification Protection (RFC 7967\)**: Caps response amplification ratio \$\\le 3\\times\$ or requires the `No-Response` option to neutralize DDoS reflector attacks.  
3. **Strict Option Parser**: Rejects packets with out-of-order options or malformed delta extensions.  
4. **Cryptographic Token Entropy**: Enforces tokens \$\\ge 4\$ bytes generated using a cryptographically secure pseudo-random number generator (CSPRNG) to defeat off-path injection.  
5. **Observe Memory Pruning**: Periodically sends CON notifications to detect dead observer endpoints and deallocate session memory.