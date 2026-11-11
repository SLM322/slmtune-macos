[Unit]
Description=SLMtune traffic usage and limits

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'python3 /etc/sing-box/slm-usage.py'

