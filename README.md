# The Agent Manifold

**A desktop x402 payment manager for AI agents.**

Delegate spending authority to agents without sharing private keys. Implements the full AP2 flow: intent, authorization, settlement, and receipt. Accepts direct A2A x402 as well as HTTP x402.

![Architecture](docs/manifold_wide.png)

## The Problem

AI agents need to pay for things, but giving an agent your private key is dangerous as too many recent examples show. No amount of persuasion is guaranteed to convince a free-willed agent to behave as you ask. The Agent Manifold sits between your agents and your wallet, enforcing spending policies and requiring human approval when needed.

## How It Works

```
Agent hits paywall → 402 + Payment-Required header
                            ↓
              Agent calls POST /sign with header
                            ↓
         Manifold checks policy (daily limit, domain, etc.)
                            ↓
        Auto-approve OR human approval dialog in app
                            ↓
              Manifold signs EIP-712 authorization
                            ↓
         Agent retries request with payment header
                            ↓
            Merchant settles via x402 Facilitator
                            ↓
         Agent reports settlement via POST /callback
                            ↓
              Manifold verifies on-chain, stores receipt
```

Any agent framework can integrate via HTTP to `localhost:9402` — Claude, GPT, LangChain, custom agents, or any system that can make HTTP requests. Bearer tokens for simplicity, HMAC-SHA256 for production security. The pattern is intentionally simple: **detect paywall → request signature → retry with payment → report settlement**.

## Authorization Controls

- **Spend Policies** — Daily limits, per-request caps, auto-approve thresholds
- **Domain Restrictions** — Allowlist/blocklist which merchants can receive payments
- **Agent Isolation** — Each agent gets unique credentials, cannot access other agents' budgets
- **Human Approval** — Payments above threshold trigger a dialog in the app
- **AP2 Intent Mandates** — Signed VDCs document authorization, publishable to AP2 registry for merchant verification

![Screenshot](docs/manifoldss2.png)

## Where Authorization Happens

1. **Policy enforcement** — SigningService validates each request against the agent's SpendPolicy (daily limits, per-request caps, allowed domains, network restrictions)
2. **Human approval** — Payments above the auto-approve threshold trigger an ApprovalDialog in the desktop app; user sees agent name, amount, merchant, and policy before approving
3. **Cryptographic signature** — On approval, Manifold signs an EIP-712 authorization; the agent never sees the private key
4. **On-chain verification** — After settlement, Manifold verifies the transaction against blockchain state and records the result

## Intent Mandates & Merchant Verification

Each agent can have a signed **Intent Mandate** — an AP2 VDC documenting:
- Agent identity (code + auth key fingerprint)
- Spending limits (daily, per-request, auto-approve threshold)
- Authorized networks
- Issuing wallet address and signature

Mandates are signed with EIP-191 and can be published to the [AP2 Registry](https://ap2.primer.systems). Merchants can query the registry by agent code to verify authorization before accepting payment — confirming the agent is backed by a real human with defined spending limits.

![Internal Architecture](docs/manifold_close.png)

## Accountability & Receipts

Every transaction is logged with agent, amount, domain, timestamp, and on-chain tx_hash. Settled payments are verified against the blockchain. AP2-formatted receipts are available via `/receipt/{id}`.

```json
{
  "type": "AP2Receipt",
  "version": "ap2.primer/v0.1",
  "intent": {
    "agentCode": "XK7M2P",
    "policyName": "standard",
    "approvalMethod": "human"
  },
  "authorization": {
    "walletAddress": "0x742d35Cc6634C0532925a3b844Bc9e7595f...",
    "signedAt": "2025-01-15T14:32:01Z"
  },
  "payment": {
    "amount": "1.50",
    "currency": "USDC",
    "recipient": "0x8ba1f109551bD432803012645Ac136ddd64...",
    "network": "eip155:8453"
  },
  "settlement": {
    "txHash": "0x3a1b2c3d4e5f...",
    "status": "verified",
    "blockNumber": 12847293
  }
}
```

## Failure Handling

When a policy violation occurs (limit exceeded, blocked domain, manual rejection), the agent receives a structured error response with a reason code. This allows the agent to understand *why* the payment was declined and adjust its behavior — choosing a cheaper option, trying a different merchant, or asking the user for guidance.

The demo video shows this in action: an agent exceeds its daily limit and is forced to reconsider its approach.

![Screenshot](docs/manifoldss1.png)

## Technical Details

- **Wallet Security:** AES-256-GCM encryption, Argon2id key derivation (64MB, 3 iterations)
- **Payment Signing:** EIP-712 structured data, EIP-3009 `transferWithAuthorization`
- **Networks:** SKALE Base, SKALE Base Sepolia, Base, Base Sepolia
- **Protocol Support:** v1/v2 HTTP x402 and A2A x402 (direct JSON payloads)
- **Auth Modes:** Bearer tokens (simple) or HMAC-SHA256 (production)

## Demo

**Video:** [Watch the demo →](https://www.youtube.com/watch?v=51P_oOkBdQA)

<!-- BEGIN YOUTUBE-CARDS -->

<!-- END YOUTUBE-CARDS -->

The demo shows the full payment flow from agent request to on-chain settlement, including a failure case where a payment limit is exceeded and the agent is forced to consider a new choice.

## Download

**[Download Primer.exe →](https://github.com/primer-systems/agent-manifold/releases)**

Or run from source:
```bash
pip install -r requirements.txt
python src/app.py
```

## Links

- [Full Documentation](https://docs.primer.systems/agent-manifold.html)
- [AP2 Registry](https://ap2.primer.systems)
- [Test Paywall Builder](https://www.primer.systems/test-paywall)
- [Medium Article](https://medium.com/@primersystems/the-x402-agent-manifold-d51e72ee029d)

