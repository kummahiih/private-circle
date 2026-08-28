# AI Disclosure Statement

**Compliance**: EU AI Act Article 50(2)

## Overview

This package has been developed with assistance from artificial intelligence tools. This document provides transparency regarding the role of AI in the development process.

## AI Tools Used

The following AI tools were utilized during development:

- **Google Gemini** — Code generation and problem-solving assistance
- **xAI Grok** — Code generation and technical analysis
- **GitHub Copilot** — Code completion and implementation support

## Development Process

### Design (Human-Made)
- Architecture and design decisions are **entirely human-created**
- Security model and threat assessment are **human-designed**
- API surface and module structure are **human-defined**
- Documentation structure and operational guidelines are **human-authored**

### Implementation (AI-Assisted)
- Code generation and refinement used AI assistants for:
  - Function implementation
  - Module structure
  - Utility functions and helpers
  - Test case generation
  - Documentation examples
- AI tools accelerated development but did not autonomously decide architecture or security properties

### Review and Quality Assurance
- **All code will be comprehensively reviewed by human developers** before version 1.0.0 release
- Security review is mandatory prior to production use
- Human review process will validate:
  - Correctness of AI-generated implementations
  - Security and cryptographic soundness
  - Compliance with the stated threat model
  - Test coverage and edge cases
  - Code quality and maintainability

## Transparency Statement

Users and developers should be aware that:

1. **AI participated in code generation** — portions of implementation may reflect AI-assisted patterns
2. **Human design governance** — all high-level decisions, security model, and API design were human-driven
3. **Pre-release review required** — version 1.0.0+ will be subject to human code review before publication
4. **Security implications** — the cryptographic design and security claims remain human-validated
5. **Maintenance** — ongoing maintenance and updates will follow standard human review practices

## Limitations of AI Assistance

Users should be aware that:

- AI-generated code may contain subtle bugs or inefficiencies not caught without review
- AI assistance does not replace security audits or cryptographic review
- AI tools cannot independently verify threat model compliance
- Edge cases or performance characteristics may not be optimal without human refinement

## Version Status

- **Current**: Pre-release (AI-assisted, pending human review)
- **Target 1.0.0**: Human-reviewed release (all code reviewed by human developers)
- **Post-1.0.0**: Standard maintenance review process

## Disclaimer

This package is provided as-is. Until version 1.0.0 is released with full human review, users should:

1. Not rely on this package for production high-security applications without independent review
2. Understand the inherent limitations of AI-assisted development
3. Conduct their own security assessments
4. Report any issues or concerns to the maintainers

## Questions or Concerns?

If you have questions about AI disclosure or the development process, please open an issue on the GitHub repository.

---

**Last Updated**: 2026-08-28  
**AI Disclosure Required By**: EU AI Act Article 50(2)
