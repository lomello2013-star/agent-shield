# CI report

Repository: https://github.com/lomello2013-star/agent-shield

Workflow: `pilot-ci`

Successful run:

```text
https://github.com/lomello2013-star/agent-shield/actions/runs/43760497846
status: completed
conclusion: success
head: d28b7f7
```

The workflow runs:

- checkout;
- Python 3.12;
- `pytest` (Windows-only tests skipped on Linux);
- Linux package build;
- release manifest;
- artifact upload.

Earlier failures were environment/dependency issues, fixed by:

- installing `numpy`, `lightgbm`, `onnxruntime`, `onnxmltools`;
- skipping Windows-only tests on the Ubuntu runner;
- skipping the Windows firewall unit test on Linux.
