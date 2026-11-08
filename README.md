# Defensive Login Event Analysis — SOC Practice

**Target roles:** Cybersecurity Intern, Security Analyst Intern, SOC Intern.

## Scenario
Analyze a **synthetic** authentication event dataset to identify repeated failed sign-ins followed by a success. This is a defensive monitoring demonstration, not a real breach analysis.

## Run
```bash
python analyze_logs.py
python -m unittest discover -s tests -v
```

## Detection logic
1. Group failures by `source_ip` and `user`.
2. Flag 3 or more failures within 10 minutes.
3. Note if a successful login for the same user and IP occurs within 10 minutes of the last failure.
4. Export findings to `findings.json` (created when run).

## Triage considerations
- Confirm whether the IP is an approved VPN, shared NAT, or automated test.
- Check MFA outcomes and device inventory in authorized systems.
- A detection is an **indicator requiring review**, not proof of compromise.
- Escalate according to an organization's incident response process.

## Interview talking points
What is a false positive? Why is time-window logic useful? What other fields would improve confidence?
