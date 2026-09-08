---
kind: container_hardening
title: Superset hardening: runtime container hardening (kind 3)
macro: !hl-container-hardening
---
# Runtime container hardening

The findings in this session live in the OS or runtime layers of the production `lean` image
(Debian packages, Node runtime, system libraries), not in Superset's Python dependencies. Each
finding has a fixed version. Your job is to make the `lean` image pick up the fix without changing
what the application ships.

## Boundaries

- Work only in `Hunter-1298/superset`, from `main`. Never touch `apache/superset`.
- Files you may change: `Dockerfile`, `docker/` helper scripts, and pinned base-image references.
  Do not change Python requirements here; a Python fix belongs to the dependency-upgrade playbook.
- Never add scanner ignore files and never delete a package the application uses at runtime.
- The image must stay the same shape: same exposed port, same entrypoint, same non-root user, same
  `SUPERSET_HOME`. The fork's `lean-smoke` job starts the exact digest that CI built and checks
  `/health`; `app-runs` then exercises login, dashboards, chart data, SQL Lab and CSV export.
- Never claim a test you did not run.

## Procedure

1. Read the findings attachment: each finding names the layer (`os` or `runtime`), the package, the
   installed version and the fix version per scanner.
2. Decide the smallest change that reaches every fix version, in this order of preference:
   - a newer pinned base-image digest whose package set already contains the fixes (`base_image`);
   - an explicit `apt-get install --no-install-recommends <pkg>=<version>` upgrade in the existing
     `RUN` layer (`pin`);
   - removing a package that is only present as a build artefact (`package_removal`) — only when
     you can show it is not needed at runtime;
   - `user` or `permissions` changes when the finding is about them.
   Record every change in `changes` with its `type` and `detail`.
3. Build the `lean` target locally (`docker build --target lean .`), record image size before and
   after in `image_size_before_after`, and run the fork's `scripts/ci/lean_smoke.sh` against your
   local image. Set `lean_smoke_local` truthfully.
4. Re-scan the local image with Trivy and Grype (any recent version) to confirm the findings are
   gone; attach the JSON as evidence and list the URLs in `evidence_urls`. This is a preview only;
   the controller closes nothing until the fork's own pinned scanners confirm absence on `main`.
5. Open one PR against `main` with a `build(docker):` title. The body lists each change, the
   findings it fixes, and the local smoke and scan results.
6. Finish with the structured output.
