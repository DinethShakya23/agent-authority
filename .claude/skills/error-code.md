# /error-code — Append a New AI-xxxx Error Code

Safely add a new error code to the append-only stable API in
`pkg/apierr/codes.go`. Never renumber or delete existing codes.

## Steps

1. **Ask for the new code details.**
   Prompt the user for:
   - Category (identity / cert / passport / sig / replay / authority / budget /
     delegation / approval / internal)
   - Short constant name (e.g. `CodeRateLimited`)
   - Human-readable description (used in the commit message only)

2. **Read `pkg/apierr/codes.go`.**
   Find the correct range for the category and identify the next unused number.
   Display the proposed code value (e.g. `AI-6006`) for user confirmation before
   writing.

3. **Append the constant.**
   Insert the new constant at the end of the correct `const` group. No comments.
   Apache 2.0 header must remain at the top of the file unchanged.

4. **Update `HTTPStatus()` if needed.**
   If the new code falls within an existing range already covered by the switch,
   no change needed. If a new range boundary is introduced, extend the switch.

5. **Verify append-only.**
   Run `git diff pkg/apierr/codes.go` and confirm only additions appear. Flag
   any deletion or modification of existing lines.

6. **Output a summary.**
   Print the new constant name and string value for use in subsequent code.
