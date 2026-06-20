# slack-mcp-server

A local MCP server exposing Slack as tools, with every Slack API request/response cryptographically timestamped via [FreeTSA](https://freetsa.org) (RFC 3161) — giving you trusted-third-party proof of when each piece of data was retrieved.

## Tools

- `send_message` — post a message to a channel
- `reply_to_thread` — reply to a message thread
- `read_messages` — read recent messages from a channel
- `get_full_history` — paginate a channel's entire history into one markdown response
- `start_full_history_fetch` / `get_full_history_status` — non-blocking full-history fetch with polling, for channels too large to fetch synchronously
- `list_channels` — list public channels
- `list_users` — list workspace users
- `get_user_info` — look up a user by ID
- `search_messages` — search Slack messages

## How it works

- Each Slack API call is timestamped: the request/response artifact is hashed (SHA-512) and sent to FreeTSA, producing a signed `.tsr` token alongside the original `.tsq` request and `.json` artifact. These are saved under `timestamps/<user_id>/<call_id>/` and served back over HTTP for independent verification.
- `get_full_history` output includes a header/footer noting the SHA-256 of `mcp-server.js` itself, so generated output is traceable to the exact server code that produced it.
- Messages render through templates in `templates/` (`message.md`, `history-header.md`, `history-footer.md`).

## Setup

```bash
npm install
cp .env.sample .env   # fill in SLACK_CLIENT_ID / SLACK_CLIENT_SECRET
npm start
```

Then visit `http://localhost:8080/oauth/install` to authenticate. The MCP endpoint is `http://localhost:8080/mcp`.

### Required Slack user scopes

`chat:write`, `canvases:write`, `channels:history`, `groups:history`, `im:history`, `mpim:history`, `search:read`, `users:read`, `users:read.email`

## Verifying a timestamp

Each timestamped call returns a `verification_instructions` field with direct download links. Once you have the three files plus the certs:

```bash
openssl ts -verify -in <call>.tsr -queryfile <call>.tsq -CAfile cacert.pem -untrusted tsa.crt
```
