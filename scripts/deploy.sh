#!/bin/bash
# scripts/deploy.sh
cd ../server || exit
npm install
pm2 stop cipherchat 2>/dev/null
pm2 start server.js --name cipherchat
echo "🚀 CipherChat relay started on port 8080"