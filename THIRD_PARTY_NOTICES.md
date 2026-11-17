# Third-party notices

This package's authored source is MIT licensed. Its npm distribution does not
bundle Pi, AgentDojo, Progent, datasets, model responses or provider credentials.

| Component | Use | License |
|---|---|---|
| Ajv 8.17.1 | Runtime JSON Schema validation | MIT |
| Pi 1.5.0 (`@earendil-works/*`) | Host-provided extension API and optional SDK peer | MIT |
| AgentDojo `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | Optional native artifact replay | MIT; copyright 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer and Florian Tramèr |
| Progent `b02783b896d4bf01a2adf24738015e258db8d35b` | Optional original policy-check replay | MIT; copyright 2026 Progent |

Dependencies keep their upstream notices when installed. Pi's packages are
peer dependencies, following its package documentation; the host supplies them.
The source fixture and residual transformation used by replay come from the
authors' frozen research artifact. Upstream benchmark text/data must retain
its own license when distributed separately.

Primary API documentation inspected for this release is the published
`@earendil-works/pi-coding-agent@1.5.0` package, `docs/extensions.md`,
`docs/packages.md`, and its runtime/type declarations. Package integrity:
`sha512-xNDZ5kqowO6Z03FS2gwAkPEGk1ssxVcYKQ6qZId84mFEvwACvvyc2l0vAMOS+c5zvxLRMLBE9r4y44IGYkMJaQ==`.
