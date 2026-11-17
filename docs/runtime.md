# Runtime

The runtime checks explicit JSON policies at the tool-call boundary. Use the core directly, the Pi Agent SDK wrapper, or the Pi coding-agent extension.

## Pi extension

```sh
pi install .
pi --auth-policy /absolute/path/to/policy.json
```

`/auth status` reports the active policy. `/auth reload` replaces it explicitly while the session is idle. The extension is inactive when no policy is supplied; an invalid supplied policy blocks tool calls until corrected. For the example tools, start Pi with `--no-tools -e ./examples/demo-tools.js` and use `examples/policy.json`.

## SDK

```js
import { AuthorizationController } from 'pi-authorization-control';
import { guardTools } from 'pi-authorization-control/pi-agent';

const controller = new AuthorizationController({
  policy,
  onAudit: event => audit.push(event),
  onSuccessfulResult: evidence => observations.push(evidence),
});
const guarded = guardTools(tools, controller);
```

Pass `guarded` as the agent's tools. The SDK wrapper executes a copy of the checked arguments. The completion callback runs only for admitted calls that finish successfully with unchanged arguments. Denials, explicit errors and cancellations do not qualify for that callback. Policy replacement is a trusted application operation and is disallowed while calls are pending.

## Policy

```json
{
  "version": 1,
  "id": "merchant-payment",
  "rules": [{
    "tool": "demo_pay",
    "effect": "allow",
    "arguments": {
      "type": "object",
      "required": ["recipient", "amount"],
      "additionalProperties": false,
      "properties": {
        "recipient": {"const": "demo-merchant"},
        "amount": {"const": 105}
      }
    }
  }]
}
```

Matching deny rules take precedence. Otherwise, a call must match an allow rule. Unknown tools and unmatched arguments are denied. Validation uses JSON Schema without coercion, inserted defaults or remote schema fetching. Refusals reveal no admitted argument values. Audit entries record call identity, policy identity and completion status without raw argument payloads.

Rules apply per invocation. Tool services should enforce cumulative limits and idempotency where needed. The extension mediates Pi tool calls; it does not isolate effects inside an allowed shell command. Keep policy files outside the agent's permitted writes and load the extension after input-transforming extensions. Other extensions and tool implementations are trusted code.
