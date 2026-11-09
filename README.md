# PhotoVault

A small, deliberately vulnerable Flask photo gallery app, built to practice
file upload exploitation specifically — second in a series of personal
security-learning projects. Companion to
[insecure-notes](https://github.com/ZProtons/insecure-notes).

This one focuses on a bug class that leads to one of the highest-impact
outcomes in web pentesting: unrestricted file upload chained into remote
code execution.

**Status:** work in progress — filling in
[`VULNERABILITIES.md`](VULNERABILITIES.md) as I find and confirm each bug
myself.

## Running it

Requires Docker.

```bash
git clone <this repo>
cd photovault
docker compose up --build
```

Then open `http://localhost:5001`.

Seeded accounts:

| Username | Password |
|---|---|
| alice | alice123 |
| bob | hunter2 |

Without Docker:

```bash
cd app
pip install -r requirements.txt
python app.py
```

## What's in here

A gallery app where users log in, upload photos, and manage their own
collection. A few of these features have a real vulnerability behind them,
each marked with a `LAB N` comment in `app/app.py`. Categories, not
spoilers:

- Unrestricted File Upload
- Broken Access Control
- Insecure Script Execution (the second half of the RCE chain)

Write-ups for each are in [`VULNERABILITIES.md`](VULNERABILITIES.md).

## ⚠️ Ethical use

This app is intentionally broken, including a path to full remote code
execution. Run it only on `localhost` or an isolated lab network, against
your own instance. Do not deploy it to a public server or cloud instance
with a public IP — the RCE in this app is real, not simulated. Nothing here
should be tried against systems you don't own or don't have explicit
written permission to test.

## Why I built this

Second project in my hands-on security learning series, after
[insecure-notes](https://github.com/ZProtons/insecure-notes). That one
covered classic web vulns (SQLi, IDOR, XSS, path traversal, SSRF); this one
is scoped to file upload vulnerabilities on their own, since they're common
in the wild and a frequent way low-severity-looking bugs chain into full
compromise.
