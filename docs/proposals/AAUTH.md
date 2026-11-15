# AI agents acting for their users (AAuth) — proposal, not implemented

**Status:** idea under discussion, written 2026-11-14. Nothing here is built, and the open questions at the end are undecided.

## Goal

Let an AI agent act for a person against a remonce agent, under policy. The first use is read-only: an assistant debugging a failed start reads the command catalog, execution logs and allowed files for the person who asked it to.

Today the only way to do that is to hand the assistant the person's viewer token. That token is a bearer credential, policy cannot tell the assistant from the person, and nothing limits what it is used for.

## Terms

"Agent" already means something in remonce, so this document keeps the two apart:

- **agent**: the remonce agent, the process on a host that verifies requests and runs commands.
- **AI agent**: the software acting for a person. This is what AAuth calls an agent.

## AAuth in brief

[AAuth](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) is an Internet-Draft by Dick Hardt for agent-to-resource authorization. This proposal was written against `draft-hardt-oauth-aauth-protocol-11` (25 September 2026) and its companion [`draft-hardt-httpbis-signature-key-09`](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/).

- Every AI agent instance has its own signing key. It signs every HTTP request ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) and names the key in a `Signature-Key` header. No token is usable without the key.
- An AI agent may also carry an agent token from an agent provider, which gives it an identifier of the form `aauth:local@domain`.
- When a person is needed, the server answers `202` with a URL and a code. The AI agent sends the person there and polls with signed requests.
- The draft defines five access modes. The simplest with a person in it is *resource-managed*: the resource runs its own login or consent, then issues a session token bound to the AI agent's key.
- The larger modes add a *person server* that brokers consent and identity for the person, and optionally an *access server* that evaluates policy for the resource.

The draft is an individual submission, not adopted by a working group. It went through twelve revisions between April and September 2026, and its listed implementations are all marked exploratory.

## What does not fit

Remonce should not adopt AAuth as its authorization model:

- AAuth binds each AI agent to one person. It has no notion of several independent approvals.
- The three- and four-party modes need a person server reachable at request time. Remonce hands work between people as files and assumes nothing about network topology.
- A person server would be a second identity authority beside the IdP. Its subject identifier is a per-resource pseudonym, so mapping it to IdP groups would still need a login at the agent.
- It does not help CI executors. Agent tokens come from a provider that issues key-bound tokens, and GitHub or Vault workload tokens are not key-bound.

## Proposed shape

The agent takes the AAuth *resource* role in resource-managed mode. There is no person server. The IdP stays the only source of identity, and the person's consent is a signed grant made in the local signer.

| AAuth | remonce |
|---|---|
| Resource | The agent: `/api/commands`, `/api/files`, execution logs |
| Agent | The AI agent, identified by its request-signing key, plus an agent token if it has a provider |
| Person | The IdP user, as today |
| Interaction (`202`, URL, code) | The person's local signer |
| Session token (`AAuth-Access`) | A grant signed by the person, usable only with the AI agent's key |

### Flow

1. The AI agent sends a signed request to the agent.
2. The agent answers `202` with `requirement=interaction` and a code.
3. The person opens the code in their local signer. It shows the AI agent's key (and identifier, if it has one), the actions asked for, the host and the expiry.
4. The person signs a grant. This is a fresh login and a one-time key, the same mechanics as an approval.
5. The AI agent's next poll returns a session token. Later requests carry it under the request signature.

### The grant

A grant is a signed statement, sketched as:

```json
{
  "remonce": "grant/v1",
  "agent_key": "<JWK thumbprint of the AI agent's key>",
  "agent": "aauth:assistant.7f3c@agents.example",
  "actions": ["view_docs", "read_file", "view_execution"],
  "target_machines": ["db-1"],
  "expires": "2026-11-14T18:00:00Z"
}
```

- It is a file, like an approval, so it can reach the agent without a network path from the signer.
- It is revoked the way a request is, keyed on its id. The person who signed it may always revoke it.
- Its lifetime is capped by agent config, and by the IdP's key verification window like any other signature.
- The person's claims are those of the login that signed it. A group change takes effect when the grant expires or is revoked.

### Policy input

A request from an AI agent carries neither `input.viewer` nor `input.executor`. It carries:

- `input.agent`: `{ key, id, provider, grant_id, expires }`. `id` and `provider` are present only when the AI agent has an agent token.
- `input.on_behalf_of`: `{ username, claims }`, from the grant's login.

```rego
allow if {
	input.action == "view_execution"
	input.agent.provider == "https://agents.example"
	"sre" in object.get(input.on_behalf_of.claims, "groups", [])
}
```

Existing rules read `input.viewer` or `input.executor`, so an AI agent is denied until a policy says otherwise. The input is the same for the embedded engine and a remote OPA.

## Scope

1. **Read-only.** `view_docs`, `read_file` and `view_execution`. This covers the debugging case.
2. **Executor, opt-in per command.** An AI agent submits a request that people have already approved. The command's `executors` would name which AI agents may.
3. **Never an approver.** Approving stays a fresh login by a person.

## Work this implies

- **Signature verification.** RFC 9421 over a fixed set of covered components, and the `Signature-Key` header. ES256 works with the existing `p256` dependency. The draft prefers Ed25519, which needs a decision on a dependency.
- **Agent providers.** Verifying an agent token means fetching `{issuer}/.well-known/aauth-agent.json`. The agent should do that only for issuers pinned in config, as it pins the IdP.
- **AI agents without a provider.** A local coding assistant has only a key. The `hwk` scheme carries a bare key; whether draft -11 allows that in resource-managed mode needs checking against the text.
- **A bounded log read.** `/stream/{id}` is a WebSocket tail built for the UI. An AI agent needs a plain GET for the last N lines.
- **Session state.** Either the agent keeps a table of grants it has accepted, or the session token is the grant itself and the agent stays stateless.
- **Config.** An `[aauth]` section, off by default.

## Risks

- **Prompt injection.** Log and file content becomes input to an AI agent. That is contained while the AI agent can only read. It matters once the same AI agent can execute, which is the reason to ship read-only first.
- **Draft churn.** Only the stable core should be implemented: request signatures, `Signature-Key` and the `202` flow. Missions, person servers and federation stay out.

## Borrowed ideas that stand alone

These do not depend on the rest:

- **Proof of possession for executors.** Sign the `/execute` request with a key the executor's token is bound to, closing the open item that the viewer token is a bearer credential.
- **`202` with `Location` and `Prefer: wait`** as the shape for `remonce submit --wait`.

## Related: live approval

[LIVE_APPROVAL.md](LIVE_APPROVAL.md) is a separate proposal: policy can answer "needs approval by" and the agent can collect that approval through a central service. Neither proposal depends on the other.

If both existed, an AI agent's interaction would be one more held request. A policy could then ask the person to approve each access in place of a standing grant, with a slot naming them: `{"claim_equals": ["username", input.on_behalf_of.username]}`.

## Open questions

- Should AI agent access use a standing grant, live approval of each access, or either as policy chooses?
- Is a grant signed in the local signer the right backing, or should the agent run its own viewer login for the interaction? The grant keeps redirect URIs off the agent and works as a file; the login would be closer to stock AAuth.
- What is the default grant lifetime? One hour, matching the default `approval_validity`, is the starting suggestion.
- Should grants be scoped to named files and executions, or only to actions?
- Should a person server be supported later, as pinned issuers, for organisations that run one alongside their IdP?
