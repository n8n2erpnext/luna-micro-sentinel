# Luna Micro Sentinel — Source publication and retirement

Status: SOURCE SNAPSHOT PREPARED; removal evidence to be appended after publication and n8n cleanup.

## Provenance

Original VPS-ARM source:
- /home/ubuntu/services/micro-sentinel
- /home/ubuntu/services/sentinel-site-guardian
- /home/ubuntu/services/sentinel-guardian-reports
- /home/ubuntu/services/sentinel-threat-intel
- /home/ubuntu/services/sentinel-competition-reviews
- /home/ubuntu/n8n2erpnext/light-sentinel-decision
- /home/ubuntu/n8n2erpnext/light-luna

Live state and historical backups are intentionally excluded. n8n templates cover:
- MSentinel20260905
- MSentinelAlerts20260905
- MSentinelBAlerts20260905
- MSentinelDailyReview20260906
- SGGuardianQueue20261008
- SGGuardianDaily20261008
- SGGuardianWeekly20261008

No other n8n workflows were authorized for removal.

## Retirement order

1. Freeze/disable the dedicated micro-sentinel.timer and service.
2. Publish and independently verify clean source files on GitHub.
3. Unpublish/remove the seven identified n8n workflows without changing other workflows, credentials or n8n service.
4. Remove only verified retired Sentinel/Luna source, runtime state and dedicated backups on VPS-ARM.
5. Verify GitHub commit, n8n workflow absence, timer state, unrelated services and disk recovery.

Workflow export templates are sanitized and inactive; they are not raw n8n backups.
