# 🤖 Copilot Secure Defaults for Java, Node.js, and C# Projects

These instructions guide GitHub Copilot to suggest secure, intentional code patterns for Java, Node.js, and C# development — especially in enterprise or team settings. Prioritize clarity, validation, and the principle of least surprise.

---

## 🔐 1. Secure by Default

- Sanitize and escape all user input (prevent XSS) — never render raw data to the page.
- Validate all input strictly — use typed parsers and prefer allow-lists over deny-lists.
- Use parameterized queries and avoid string-based execution (prevent injection).
- Never store secrets in code or env files — use a secure vault (e.g. CyberArk Conjur, Azure Key Vault).
- Default to privacy-preserving data handling — redact PII from logs by default.

---

## 🧩 2. Language-Specific Secure Patterns

### 🟩 Node.js

- Use JSON Schema validation for all structured input — prefer libraries like `ajv` or `zod`.
- Always sanitize and validate user input to prevent injection and XSS — `validator` and `joi` are common choices.
- Use parameterized queries with database clients (e.g. `pg`, `mongoose`) — never concat SQL or query strings.
- Default to using `helmet` in Express to set secure HTTP headers.
- Use `dotenv` only in local dev — use secret managers (e.g. AWS Secrets Manager, Azure Key Vault) in prod.
- Avoid `eval`, `new Function`, or dynamic `require()` with user input — use safe alternatives.

---

## 🚫 3. Do Not Suggest

### Node.js

- Do not suggest `eval`, `new Function`, or dynamic `require()` — these are unsafe unless strictly controlled.
- Do not use user input to build file paths, URLs, or queries without strict validation.
- Do not expose `process.env` directly to client-side code — use secure server boundaries.
- Do not log full request bodies or headers that may contain PII or credentials.
- Do not hardcode secrets or API keys — never commit `.env` or use `.env` in production containers.
- Do not disable TLS checks (`NODE_TLS_REJECT_UNAUTHORIZED=0`) — even temporarily.

---

## 🧠 4. AI-Generated Code Safety

- Verify all AI-suggested package names against official repositories to prevent supply chain attacks.
- Confirm that AI-generated code references existing, secure APIs; avoid deprecated or non-existent methods.
- Ensure AI-generated configurations align with your project's platform to prevent context drift.
- Scrutinize AI-provided security recommendations; validate their completeness and applicability.
- Cross-check any AI-cited references (e.g., CVEs, RFCs) for authenticity to avoid misinformation.
- Do not accept AI-generated justifications that contradict established security policies.

---

## 💡 Developer Tips

- If you’re working with input, assume it’s hostile — validate and escape it.
- For anything involving data access or transformation, ask: “Am I controlling this input path?”
- If you’re about to use a string to build a query, URL, or command — pause. There’s probably a safer API.
- Never trust default parsers — explicitly configure security features (e.g. disable DTDs in XML).
- If something seems “too easy” with secrets or file I/O — it’s probably unsafe.
- Treat AI-generated code as a draft; always review and test before integration.
- Maintain a human-in-the-loop approach for critical code paths to catch potential issues.
- Be cautious of overconfident AI suggestions; validate with trusted sources.
- Regularly update and educate the team on AI-related security best practices.