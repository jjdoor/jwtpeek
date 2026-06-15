# jwtpeek

**Decode and inspect a JWT in your terminal.** See the header, the payload, and
a human-readable expiry verdict — without pasting your token into a website.
**Zero dependencies, fully offline, nothing uploaded.**

```bash
npx jwtpeek eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

```
Header
  {
    "alg": "HS256",
    "typ": "JWT"
  }

Payload
  {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
  }

Claims
  issued   2018-01-18 01:30:22 UTC  8y 150d ago
```

## Why

Debugging auth means constantly asking *"what's actually in this token, and has
it expired?"* The usual answers are bad: paste it into **jwt.io** (your token —
often a live credential — now lives in a browser tab and maybe a third party's
logs), or hand-assemble a pipeline nobody remembers:

```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python -m json.tool   # and base64 -d vs -D differs across macOS/Linux…
```

`jwtpeek` is one command. It runs entirely on your machine, makes no network
requests, and prints the time claims (`exp`, `iat`, `nbf`, …) as real dates plus
"expires in 3h 21m" / "EXPIRED 2d ago".

## Decode, not verify — read this

> **jwtpeek never checks the signature.** It shows you what a token *says*, not
> whether it's authentic. Anyone can forge a token that decodes cleanly. Never
> trust decoded contents for an authorization decision — verify the signature
> against the issuer's key first (that needs a secret/public key, which is out
> of scope for a decoder).

## Usage

```bash
jwtpeek <token>            # header, payload & expiry (human-readable)
jwtpeek <token> --json     # {header, payload, signature, expired, notYetValid}
jwtpeek <token> --header   # only the decoded header (JSON)
jwtpeek <token> --payload  # only the decoded payload (JSON)

pbpaste | jwtpeek          # read the token from stdin
echo "$AUTH_HEADER" | jwtpeek   # a leading "Bearer "/"Authorization:" is stripped
```

Pipe-friendly: the decoded output goes to **stdout**, the "not verified" safety
note goes to **stderr**, so `jwtpeek "$t" --json | jq .payload` stays clean.

### Scripting with the exit code

```
0   decoded OK and not expired (or no exp claim)
1   decoded OK but the token is expired
2   not a valid JWT (decode error)
```

```bash
jwtpeek "$TOKEN" >/dev/null 2>&1 && echo "still valid" || echo "expired or invalid"
```

## Install

```bash
npm install -g jwtpeek     # then: jwtpeek <token>
# or just run it once:
npx jwtpeek <token>
```

Requires Node ≥ 18. There is also a byte-for-byte Python port:
`pip install jwtpeek` ([jwtpeek-py](https://github.com/jjdoor/jwtpeek-py)).

## License

MIT
