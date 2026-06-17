# Contributing to SOCshield

Thanks for your interest. SOCshield is a portfolio / small-environment
SOC platform. Contributions are welcome, but please read this guide
first.

---

## Code of conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/),
version 2.1. By participating, you agree to abide by its terms.

## Asking questions

* **General "how do I use X"** — open a Discussion.
* **"I found a bug"** — open an Issue with a minimal reproduction.
* **"I want to add Y"** — open an Issue first to discuss the
  design, before writing a PR.

## Reporting bugs

A useful bug report includes:

1. **What you did** — the exact command(s) or UI action(s).
2. **What you expected to happen.**
3. **What actually happened** — including the full error
   message / traceback if any.
4. **Environment** — Python version, Docker version if applicable,
   OS, `pip freeze` output.
5. **The smallest possible reproduction** — ideally a single
   command that triggers it.

## Suggesting features

Open an Issue with the `enhancement` label. Please describe:

1. **The problem** you're trying to solve.
2. **The proposed solution.**
3. **Alternatives you've considered.**
4. **Whether the change affects the "detection contract"**
   (see below).

## The "detection contract"

Some parts of SOCshield are load-bearing:

* `detectors/*` — the detection rules. Any change here can change
  which alerts fire in production.
* `app/correlator.py` — the three correlation rules. Changing the
  rule logic or thresholds affects every existing campaign.
* `app/mitre.py` — the single source of truth for ATT&CK
  technique + tactic mapping.
* `app/web/templates/*` — the dashboard's information architecture.

A PR that touches any of these is welcome **but** please open an
Issue first to discuss the design. We want every change to those
files to be a conscious decision, not a drive-by edit.

Everything else (`app/web/queries.py`, `app/web/routes.py`,
`app/web/static/*`, `app/supervisor.py`, `docker/`, `scripts/`,
`docs/`, `demo/`, `Dockerfile`, `docker-compose.yml`) is open
territory.

## Adding a new detection

1. **Open an issue** with the `new-detection` label. Include the
   MITRE technique id, the input log source, and the detection
   rule.
2. **Add the technique to `app/mitre.py`**:
   - Add the `MitreRef` to `MITRE_CATALOG`.
   - Add the detector-to-technique mapping to `DETECTOR_MITRE_MAP`.
3. **Write the detector** in `detectors/<name>_detector.py`. The
   detector must return a list of `Alert` objects built from the
   shared `Alert` dataclass, with the right `detector` field and
   `mitre_technique` / `mitre_tactic` populated.
4. **Add a log file path** to `app/watchers/<name>_watcher.py`
   that tails the input and publishes the resulting alerts on the
   bus.
5. **(Optional) add a correlator rule** in `app/correlator.py`
   if the new technique should contribute to a multi-stage
   campaign.
6. **Add a demo scenario** under `demo/scenario_N_<name>/`.
7. **Update `docs/mitre_coverage.md`** with the new technique
   (the "Future coverage goals" list will move up).

## Adding a new dashboard page

1. Add the route handler in `app/web/routes.py`.
2. Add the template in `app/web/templates/<page>.html`.
3. If the page needs new data, add a query function in
   `app/web/queries.py`. Keep it read-only.
4. Update `docs/screenshots/README.md` with the new screenshot.
5. Add the link to the sidebar in `app/web/templates/base.html`.

## Submitting a pull request

1. **Fork the repo** and create a branch off `main`.
2. **Make your change.** Run the existing test suite if any
   (`pytest`) before opening the PR.
3. **Add tests** for any new detection or correlator rule.
4. **Update documentation** — at minimum, update the README
   feature list and the relevant `docs/*.md` file.
5. **Open the PR.** Use the template. Reference any related Issue.

PRs are reviewed for:

* Correctness (does the detection actually catch what it claims?)
* Style (PEP 8, type hints, docstrings on public functions).
* Test coverage (new detection ⇒ new test).
* Documentation (no undocumented public API).

## Local development setup

```bash
git clone https://github.com/Hammad-karim/socshield.git
cd socshield

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the showcase scenario
cp -r demo/scenario_4_full_chain/logs/* logs/
python main.py
python run_dashboard.py
# → http://127.0.0.1:5000/
```

## Docker development loop

```bash
docker compose up -d --build
docker compose logs -f socshield
docker compose exec socshield python /app/scripts/validate_deployment.sh
```

## License

By contributing, you agree that your contributions will be licensed
under the [MIT License](LICENSE).
