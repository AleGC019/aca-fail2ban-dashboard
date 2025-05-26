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

| Stage                   | Status             |
|-------------------------|--------------------|
| Code Quality Check      | {{LINT_STATUS}}    |
| Container Build         | {{BUILD_STATUS}}   |
| Integration & Flow Test | {{INTEGRATION_STATUS}} |
| Unit Tests              | {{UNIT_STATUS}}    |
| Cleanup                 | {{CLEANUP_STATUS}} |

</details>

<details>
<summary>Coverage report</summary>

{{COVERAGE_COMMENT}}

</details>

## Next steps
- [ ] Investigate failed stages (if any)
- [ ] Fix lint/formatting issues
- [ ] Increase test coverage (target ≥ 60 %)

---

<sub>This Issue was generated automatically by the CI pipeline.</sub>
