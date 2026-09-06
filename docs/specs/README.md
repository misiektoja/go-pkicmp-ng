# CMP Specifications

This directory contains the essential RFC specifications for **CMP v2** and **CMP v3** (Certificate Management Protocol) implementation.

## Index

1. **[RFC 9810](https://datatracker.ietf.org/doc/html/rfc9810)** - Internet X.509 PKI - Certificate Management Protocol (CMP)
   - Current CMP protocol specification (Jul 2025)
   - Obsoletes RFC 4210 and RFC 9480
   - Defines protocol versions: **CMPv2** (cmp2000) and **CMPv3** (cmp2021)
   - Adds support for management of certificates containing a Key Encapsulation Mechanism (KEM) public key and uses EnvelopedData instead of EncryptedValue.

2. **[RFC 9483](https://datatracker.ietf.org/doc/html/rfc9483)** - Lightweight CMP Profile
   - Simplified CMP profile for industrial and IoT scenarios (Nov 2023)
   - Defines mandatory header fields, message validation, and security requirements

3. **[RFC 9481](https://datatracker.ietf.org/doc/html/rfc9481)** - CMP Algorithms
   - Cryptographic algorithm conventions for CMP (Nov 2023)
   - Algorithm profiles and recommendations

4. **[RFC 9811](https://datatracker.ietf.org/doc/html/rfc9811)** - HTTP Transfer for CMP
   - Current CMP over HTTP transport specification (Jul 2025)
   - Obsoletes RFC 6712
   - HTTP mechanics for CMP message transport

5. **[RFC 4211](https://datatracker.ietf.org/doc/html/rfc4211)** - Internet X.509 PKI - Certificate Request Message Format (CRMF)
   - CRMF message format for certificate requests (Oct 2005)
   - Used in CMP for certificate enrollment

6. **[RFC 4210](https://datatracker.ietf.org/doc/html/rfc4210)** - Internet X.509 PKI - Certificate Management Protocol (CMP)
   - Original CMP v2 specification (Oct 2005)

7. **[RFC 6712](https://datatracker.ietf.org/doc/html/rfc6712)** - HTTP Transfer for CMP
   - Original CMP over HTTP specification (Sep 2012)
   - Obsoleted by RFC 9811

8. **[RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)** - Internet X.509 PKI - Certificate and CRL Profile
   - X.509 certificate structure and PKI components (May 2008)
   - Specifies `GeneralName` type used in CMP headers for sender/recipient fields
