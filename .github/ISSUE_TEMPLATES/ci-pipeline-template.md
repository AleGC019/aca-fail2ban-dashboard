# 🚦 CI Pipeline {{STATUS}}

| Item          | Value |
|---------------|-------|
| **Result**    | {{STATUS}} |
| **Workflow**  | `{{WORKFLOW}}` |
| **Branch**    | `{{REF_NAME}}` |
| **Event**     | `{{EVENT_NAME}}` |
| **Commit**    | [`{{SHORT_SHA}}`](https://github.com/{{REPO}}/commit/{{SHA}}) by **{{ACTOR}}** |
| **Run URL**   | [link]({{RUN_URL}}) |

<details>
<summary>Stage results</summary>

| Stage                | Status |
|----------------------|--------|
| Lint                 | {{LINT_STATUS}} |
| Container Build      | {{BUILD_STATUS}} |
| Integration Testing  | {{TEST_STATUS}} |
| Unit Tests           | {{UNIT_STATUS}} |
| Integration Flow     | {{INTEGRATION_STATUS}} |
| Cleanup              | {{CLEANUP_STATUS}} |

</details>

{{# if COVERAGE }}
<details>
<summary>Coverage report</summary>

Total coverage: **{{COVERAGE}} %**

</details>
{{/ if }}

## Next steps
- [ ] Investigate failed stages (if any)
- [ ] Fix lint/formatting issues
- [ ] Increase test coverage (target ≥ 80 %)

---

<sub>This Issue was generated automatically by the CI pipeline.</sub>
