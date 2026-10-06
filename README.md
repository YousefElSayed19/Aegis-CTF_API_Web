# 2- README FILE

# Project AEGIS

## Scenario

AEGIS is the internal employee portal for a fictional company. From the
outside, it looks like an ordinary internal web app: a login page, an
employee profile, and a couple of simple self-service features.

Behind that simple front end, the company runs several backend services
that all talk to the same underlying data. You are not told what those
services are, how many there are, or how they connect. Figuring that out
is part of the challenge.

## Objective

Recover the full flag, in the format described below. The flag is only
assembled once you have gathered three separate credential fragments from
three separate parts of the system.

## Difficulty

**Intermediate to Advanced**. Comfort with intercepting and modifying HTTP requests (e.g. Burp Suite) will help throughout.

## Prerequisites

- Docker Desktop (or Docker Engine + Docker Compose) installed and running.
- A web browser.
- An HTTP intercepting proxy (e.g. Burp Suite) is strongly recommended.
- General familiarity with modern web API testing (REST-style APIs,
query-based APIs, and RPC-style services) will be useful. You do not
need to know in advance which of these, if any, are actually in use
here.

## Startup Instructions

1. Unzip / clone the project.
2. Open a terminal in the project's root folder.
3. Run:
    
    ```
    docker compose up --build
    ```
    
4. Wait for the log output to show the application is listening. You do
not need to configure anything else manually.

## Connection Information

Once running, the challenge is reachable at:

```
http://localhost:3000
```

This is your only entry point. Everything else you need to interact with
is reachable starting from here — but not necessarily obviously so.

## Starting Access

You do not begin with valid credentials handed to you directly. A low-privilege employee account exists somewhere within the application and can be discovered from the starting page — look carefully.

## Reset Instructions

All challenge state is kept in memory and is tied to the running
container. To reset the challenge to a clean, initial state at any time:

```
docker compose restart
```

This fully resets all progress with no manual file changes required.

## Flag Format

```
duck{...}
```

The flag will not appear until you have made progress in three distinct
parts of the system. Partial progress will be acknowledged along the way,
but the final flag only assembles once everything required has been
completed.

## Player Rules

- Only interact with the services this challenge exposes on your local
machine. No external hosts or services are in scope.
- Do not attempt to brute-force the login form itself with generic
credential lists — the intended starting account is discoverable
through the application, not through guessing.
- Automated scanning/fuzzing tools are allowed and, in places, expected.
- If you get stuck, re-read every response carefully — the application
gives you more information than it first appears to.

Good luck.