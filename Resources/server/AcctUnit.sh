[Unit]
Description=SLMtune traffic accounting (nftables)
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'nft -f /etc/sing-box/slm.nft && python3 /etc/sing-box/slm-usage.py reloaded'

[Install]
WantedBy=multi-user.target

