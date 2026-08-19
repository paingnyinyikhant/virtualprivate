#!/bin/bash
cd /data/data/com.termux/files/home/virtualprivate
python auto_v2ray.py
git add servers
git commit -m "Auto update: $(date)"
git push origin main
