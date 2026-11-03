# JWT Peek

**[Open the demo →](https://antonidashaci.github.io/jwt-peek/)**

Decode a JWT, check the claims that decide whether it would actually be
accepted, and verify an HS256 signature — **offline, in one tab**.

## Why offline matters

A JWT is usually a live credential. Pasting one into a website hands whoever
runs that site a working key to your account or API. Decoding a JWT is pure
string work: base64url, `JSON.parse`, and some date arithmetic. It needs no
server, so this one doesn't have one. There is no `fetch` in the source, and the
token is never written to storage.

## Run it

```bash
python -m http.server 8000
```

Or open `index.html` directly.

## What it tells you

```
alg   alg is "none": this token is unsigned and anyone can forge it
exp   Expired 14 hours ago
iat   Issued in the future: check the clock on the issuing server
aud   Audience does not include api
```

- `alg` — missing, `none`, or claiming an algorithm with an empty signature
- `exp` — expired, or **in milliseconds** instead of seconds (a NumericDate is
  seconds; the milliseconds mistake otherwise shows up as a token that expires
  in the year 57000)
- `nbf` — not valid yet
- `iat` — issued in the future, which means a clock is wrong somewhere
- `aud` / `iss` — compared against what you type, string or array
- clock leeway, for real-world skew
- every NumericDate claim as local time plus "in 3 minutes" / "2 days ago"

## Signature verification

HMAC only (HS256/384/512), via Web Crypto.

**The algorithm is a parameter you choose, never read from the token.** Taking
`alg` from the header and verifying with it is algorithm confusion: an attacker
takes an RS256 token, rewrites the header to HS256, and signs it with the public
key — which the server happily accepts as the secret. So if you ask to verify
HS512 and the header says HS256, this tells you about the mismatch instead of
quietly going along with it.

RS/ES verification would need a public key and is out of scope for a single
page; the decode and claim checks are the part you reach for twenty times a day.

## Layout

| | |
| --- | --- |
| `core.js` | decode, `inspect`, `verifyHmac` — no DOM |
| `app.js` | the UI |
| `index.html`, `styles.css` | markup and styles, dark mode included |

## Tests

```bash
npm test
```

22 tests with `node --test`: base64url edge cases, malformed tokens, the
milliseconds trap, leeway, array audiences, real HS256/384/512 signatures, and
the algorithm-confusion refusal.

## License

MIT
