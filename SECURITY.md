# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

## Reporting a Vulnerability

The WEIGHTTRAP project takes the security of financial AI infrastructure seriously.
If you discover a security issue regarding model integrity, cryptographic hash verification, or control plane containment failure:

1. **Do not file a public GitHub issue.**
2. Email your technical findings and reproducible proof-of-concept to `security@weighttrap.local` or the project maintainers.
3. Include:
   - Target model architecture and serialization format (`.npz`, `.onnx`, `.safetensors`).
   - Description of the tampering mechanism or policy evasion vector.
   - Proposed remediation or patch diff.

We appreciate responsible disclosure and will respond within 48 hours with a validation verdict and remediation timeline.
