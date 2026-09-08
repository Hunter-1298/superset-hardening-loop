---
kind: helm_deploy_config
title: Superset hardening: Helm and deployment security configuration (kind 5)
macro: !hl-helm-security
---
# Helm and deployment security configuration

The findings in this session are misconfigurations in the Superset Helm chart or the Docker
deployment files (`helm/superset/`, `docker/`, `docker-compose*.yml`), reported by the scanners'
configuration checks rather than by a CVE database. You change deployment defaults so that a fresh
install is secure, without breaking the chart for existing users.

## Boundaries

- Work only in `Hunter-1298/superset`, from `main`. Never touch `apache/superset`.
- Files you may change: `helm/superset/values.yaml`, `helm/superset/templates/**`,
  `helm/superset/Chart.yaml` (version bump only), `docker/`, `docker-compose*.yml`, and the docs
  that describe them. Do not change application code or Python requirements here.
- Never add scanner ignore files or `# checkov:skip` / `# trivy:ignore` comments to make a check pass.
- Respect the `SECURITY.md` trust boundaries: a deployment-time choice the operator must make
  (secrets, network exposure) stays configurable; you change the default, not the option.
- Never claim a test you did not run.

## Procedure

1. Read the findings attachment. Each finding names the check id, the resource (template file and
   kind), and the field. Group findings by the value that fixes them.
2. For each group, change the default in `values.yaml` and the template that renders it so that the
   secure setting is the default. Typical fixes: `securityContext.runAsNonRoot: true`,
   `allowPrivilegeEscalation: false`, dropped capabilities, `readOnlyRootFilesystem` where the
   container supports it, resource limits, `automountServiceAccountToken: false`, non-default
   `SECRET_KEY` handling that refuses the chart default. Record each in `values_changed`
   (`path`, `from`, `to`).
3. Bump `helm/superset/Chart.yaml` version by a patch increment.
4. Run `helm lint helm/superset` and `helm template helm/superset` before and after; attach the
   template diff and set `helm_template_diff_attachment`. Put the lint summary in `helm_lint`.
5. If the chart has a values schema or tests, run them and record the results in `tests_run`.
6. Open one PR against `main` with a `fix(helm):` or `fix(docker):` title. The body explains every
   default that changed and how an operator restores the previous behaviour if they need to.
   User-facing changes also go in `UPDATING.md`.
7. Finish with the structured output.
