[Unit]
Description=SLMtune traffic usage and limits, every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target

