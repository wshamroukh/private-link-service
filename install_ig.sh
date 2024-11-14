#!/bin/bash
sudo apt update && apt-get install -y dotnet-sdk-8.0 nginx git
sudo mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak
sudo cd /etc/nginx/sites-available/ && sudo curl -O https://raw.githubusercontent.com/wshamroukh/nginx-aspdotnet/refs/heads/main/default
sudo git clone https://github.com/jelledruyts/InspectorGadget /var/www/InspectorGadget
sudo mv /var/www/InspectorGadget/WebApp /var/www/ && sudo rm -rf /var/www/InspectorGadget
sudo cd /etc/systemd/system/ && sudo curl -O https://raw.githubusercontent.com/wshamroukh/nginx-aspdotnet/refs/heads/main/inspectorg.service
sudo systemctl enable inspectorg && systemctl start inspectorg
sudo nginx -t && sudo nginx -s reload
sudo reboot