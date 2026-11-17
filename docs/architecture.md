# Architecture

```text
Pi coding CLI ── extension hooks ──┐
                                 ├── AuthorizationController ── explicit policy
Pi Agent SDK ─── tool wrappers ────┘            │
                                              ├── opaque denial
                                              ├── admitted tool execution
                                              └── completion/audit events

Frozen research artifact ── readback CLI ── metrics and consistency checks
                         └─ native replay ── pinned simulator and policy checks
```

The core does not import Pi or a model client. It checks explicit JSON policies
and issues private completion tickets. The SDK adapter binds execution to a
checked argument copy. The coding extension uses Pi's public event API and
records metadata-only custom entries. Its policy is static between explicit
trusted reloads; no rejected proposal is used to regenerate it.

The application owns the user task, how a policy is authored, and the meaning of
its tools' effects. A successful result callback is evidence of a completed
admitted tool call, not proof that a new permission is authorized. Allowed reads
and observations may still be actor-selected.

A tool error or cancellation is not a rollback guarantee. Completion records
describe what the adapter observed; native effects require application-specific
state measurements, as in the separate artifact replay.

The coding extension assumes input-transforming extensions run before it, and
all other extensions and native tool implementations are trusted. Direct effects
inside shell tools, third-party extensions or remote processes are outside its
mediation. User shell shortcuts (`!`/`!!`) are not model tool calls. The SDK tool
wrapper is the appropriate integration when an application controls the final
dispatch and needs the checked argument snapshot.

Sealed repair needs application-specific native effect projections, actor
resampling and one-shot grant semantics. Those are retained in the frozen
research implementation; this package does not pretend a generic coding-tool
hook supplies them. A future adapter must declare and test those contracts.
