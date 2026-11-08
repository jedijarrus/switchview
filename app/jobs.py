"""The scheduler of SwitchView and its jobs: poll, names, nightly backup, PacketFence sync, session pruning, the expiry of
four-eyes requests (Phase 4a, Task 6), the nightly purge of the history (Phase 4b, Task 2), the delivery of the alert queue every
30 seconds (Phase 4b, Task 6) and the watch over the changes waiting for their confirmation every 15 seconds, its first run right at
the start (Phase 4c, Task 5). One scheduler in the process (the single-worker invariant in main.py): main.lifespan schedules the
jobs and starts it, PUT /api/settings (api_settings.put_settings) schedules them anew with the poll interval it stored. Split from
main.py (Phase 3, Task 11), the code as it was."""
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler

import alerts
import approvals
import auth
import confirm
import history
import names as names_mod
import pf
import poller
import sshcli
from db import get_setting

scheduler = AsyncIOScheduler(timezone="Europe/Berlin")


async def _schedule():
    minutes = int(await get_setting("poll_minutes", "15") or 15)
    scheduler.add_job(poller.poll_all, "interval", minutes=max(5, minutes), id="poll", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(names_mod.refresh_names, "interval", minutes=15, id="names", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(sshcli.backup_all, "cron", hour=2, minute=30, id="backup", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(pf.expire_and_sync, "cron", hour=3, minute=15, id="pf_sync", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(auth.prune_sessions, "interval", minutes=60, id="sessions", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(approvals.expire_due, "interval", minutes=10, id="approvals", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(history.purge, "cron", hour=4, minute=0, id="history_purge", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(alerts.deliver_due, "interval", seconds=30, id="alerts", replace_existing=True, max_instances=1, coalesce=True)
    # The deadlines are in the database (changes.confirm_until): the first run right away takes back what ran out while SwitchView was down
    scheduler.add_job(confirm.watch, "interval", seconds=confirm.CHECK_S, id="confirm", replace_existing=True, max_instances=1, coalesce=True,
                      next_run_time=datetime.now(timezone.utc))
