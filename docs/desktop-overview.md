# v0.9 Overview implementation

The Overview page displays only local, available information:
ClamAV executable presence, YARA rule-store configuration (not rule trust),
and the last five SQLite scan records, including detection count.
It explicitly says no real-time protection exists.

Run a safe smoke test on Kali:

```bash
git fetch origin
git switch feature/desktop-overview-v09
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Navigate Overview -> Scan -> Results -> Overview to check updated last scan.
Configure paths in Settings before testing if defaults are different.
The overview does not claim actual ClamAV database health; 'Executable found'
is only a PATH/file check. The result view is inherited unchanged from PR #12.
