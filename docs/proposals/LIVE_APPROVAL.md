# Live approval — proposal, not implemented

**Status:** idea under discussion, written 2026-11-14. Nothing here is built, and the open questions at the end are undecided.

## Goal

Today a request must arrive at the agent already carrying every approval it needs. If it does not, the agent denies it and the submitter goes to find people.

Live approval adds a second way to get there: the agent learns from policy that more approvals would change the answer, holds the request, and asks a central server to collect them now. People approve in that server's UI, which looks much like the local signer's, and the agent moves on as soon as they do.

It would serve two cases with one mechanism:

- A person submits a request that is one approval short.
- A CI job runs `remonce submit --wait` and a person approves it from a notification.

This document calls the central server the **approval server**. It is today's revocation service with more to do; whether the service is renamed is an open question.

## A standard "needs" in the decision

A decision is `{ allow, reason }` today. The proposal adds an optional third field:

```json
{
  "allow": false,
  "reason": "The approvals do not meet this command's requirements",
  "needs": [
    { "slot": { "groups_in": "dba" }, "description": "someone in the dba group" }
  ]
}
```

- `needs` lists approval slots as the catalog already shows them, each with its predicate and policy's words for it, so the UI and the approval server can show and route them with no new vocabulary.
- It means: denied now, and approvals filling these slots would change that.
- A denial without `needs` is final. An executor who is not allowed, or a host restriction, never causes a callout.
- Rego can name one person: a slot with `{"claim_equals": ["username", "alice"]}` asks for Alice.
- `needs` only routes. After approvals arrive the agent verifies them and evaluates the whole policy again, so a wrong `needs` wastes a prompt and nothing more.

`needs` is useful with no approval server at all: the CLI and the UI can say "still needs: a DBA" in place of today's general reason.

The shipped `lib.rego` would compute the unfilled slots of a command's requirement. Policies written directly in Rego set `needs` themselves. Viewing actions are a plain boolean `allow` today and would need the decision object to take part.

## Flow

1. A request reaches the agent. The agent verifies it and asks policy.
2. The decision has `needs`. With no approval server configured, the agent denies and returns `needs` to the client.
3. With one configured, the agent posts the request and its approvals so far to the approval server, answers the submitter `202` with a `Location` to poll, and holds the request.
4. The approval server lists the request for the people who could fill the slots, and notifies them.
5. Someone opens it in the approval server's UI, reads the command and approves.
6. The agent receives the approval, adds it to the request, verifies everything, and asks policy again.
7. The request runs, or the hold times out and it is denied.

Approvals are independent signatures over the same request, so adding them needs no change to the signed format. This is parallel signing with the approval server as the meeting point.

The agent learns of an approval by waiting on the approval server: it keeps a request open and the server answers when something arrives, or the agent asks again at an interval. Either way the connection is from the agent to the server, the direction revocation checks already use, and the server never needs to reach an agent.

The approval server being unreachable is a denial, as it is for revocation checks.

## The approval server's UI

The UI is the local signer's, served centrally: a list of what is waiting for you, and the review page showing the command, its parameters, the requirement and the approvals so far. Approve and revoke work as they do locally.

Approving is the same flow with the same signatures. The approval server is one more OIDC client of the same IdP, so a click on approve is a fresh single sign-on login bound to a one-time key, and the approval it produces has the same form and the same cryptographic identity as one made locally. There is no second kind of approval for the agent to learn.

What differs is where the signature is made. In the local signer, the one-time key and the payload live in a process on the approver's own machine. Here they live on the approval server:

- The approver still logs in afresh at the IdP for each approval, and the result is an ordinary approval. The agent verifies it exactly as it verifies one made locally.
- A link to a pending request opens in any browser, including on a phone. Nobody needs the signer installed to approve.
- The approval server is trusted to sign what it showed. A compromised one could sign a different command with the key bound to a login a person makes there. It cannot approve anything without that person logging in.

## Trusting the approval server

This mode means trusting the approval server, much as setting `opa_url` means trusting a remote OPA server. Both are remote components whose compromise can get a command run that should not have been. A remote OPA can allow anything outright. The approval server can do less: it needs a person to log in before it can misuse that login.

Like remote OPA, it is a deployment choice, made per agent in config, and the alternative stays available: with no approval server, signing happens only in the local signer, as it does today.

One measure keeps the choice per agent. The approval server gets its own signing client at the IdP, and an agent accepts approvals for that client only if its config says so. Without that, an approval signed at the approval server would be accepted by every agent that shares the IdP, including ones that never chose to trust it. The agent would take a list of signing clients where it takes one today.

The token's audience then also records where each approval was signed. A policy that wants the local signer for particular commands can check it; nothing new is needed in a command's requirement.

## Notifications and plugins

A notification tells someone a request is waiting and links to it in the approval server's UI.

- A plugin is a local program the approval server runs, or a webhook it calls, with the pending request as JSON. Slack code and Slack credentials stay out of the remonce binary and away from the revocation path.
- A Slack app in Socket Mode needs no inbound exposure.

A plugin could go further and make a click in Slack the approval itself, with the approval server signing a statement that the person approved. That would make the chat platform an authority and need a mapping from chat identity to IdP identity. With a UI one link away, it is probably not worth it; it is left as an open question.

## Risks

- **Prompt fatigue.** A live prompt is easier to wave through than a request someone brought to you. The review page must show the full command, and the approval server should limit how often one person is asked.
- **A bigger central component.** The revocation service today can only hide revocations. The approval server signs, so it is trusted in the way described above, and it is worth protecting like the OPA server and the IdP.
- **Held requests.** The agent keeps state while it waits. Holds need a short limit and must survive or cleanly fail a restart.

## Open questions

- Does the agent call out, or does the submitter's tool take `needs` to the approval server and resubmit? The agent calling out works for any client. The submitter doing it keeps the agent stateless.
- Is this the revocation service renamed, or a separate mode of the binary that can share a process with it?
- How much of the local UI does the approval server show? The waiting list and review page need only what agents send it. The command catalog, files and logs would need it to reach agents.
- How does the approval server find people for a slot: group membership from the IdP, a routing table in its config, or a channel per slot?
- Is approval by a click in chat wanted at all?
- How long may a request be held?
