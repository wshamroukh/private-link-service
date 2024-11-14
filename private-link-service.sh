rg=private-link-service
location=centralindia

pls_vnet_name=pls
pls_vnet_address=10.1.0.0/16
pls_vm_subnet_name=vm
pls_vm_subnet_address=10.1.0.0/24

pe_vnet_name=pe
pe_vnet_address=10.11.0.0/16
pe_vm_subnet_name=vm
pe_vm_subnet_address=10.11.0.0/24

admin_username=$(whoami)
admin_password=Test#123#123
vm_size=Standard_B2als_v2
myip=$(curl -s https://ifconfig.co)
vm_image=$(az vm image list -l $location -p Canonical -s 22_04-lts --all --query "[?offer=='0001-com-ubuntu-server-jammy'].urn" -o tsv | sort -u | tail -n 1) && echo $vm_image

win_vm_image=$(az vm image list -l $location -p MicrosoftWindowsDesktop --all -s "win10-22h2-ent" -f Windows-10 --query "[?imageDeprecationStatus.imageState=='Active' && sku=='win10-22h2-ent'].urn" -o tsv | sort -u | tail -n 1)

cloudinit_file=~/cloudinit.txt
cat <<EOF > $cloudinit_file
#cloud-config
runcmd:
  - apt update && apt-get install -y dotnet-sdk-8.0 nginx git
  - mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak
  - cd /etc/nginx/sites-available/ && curl -O https://raw.githubusercontent.com/wshamroukh/nginx-aspdotnet/refs/heads/main/default
  - git clone https://github.com/jelledruyts/InspectorGadget /var/www/InspectorGadget
  - mv /var/www/InspectorGadget/WebApp /var/www/ && rm -rf /var/www/InspectorGadget
  - cd /etc/systemd/system/ && curl -O https://raw.githubusercontent.com/wshamroukh/nginx-aspdotnet/refs/heads/main/inspectorg.service
  - systemctl enable inspectorg && systemctl start inspectorg
  - nginx -t && nginx -s reload
  - reboot
EOF

# Resource Groups
echo -e "\e[1;36mCreating $rg Resource Group...\e[0m"
az group create -l $location -n $rg -o none

# pls vnet
echo -e "\e[1;36mCreating $pls_vnet_name VNet...\e[0m"
az network vnet create -g $rg -n $pls_vnet_name -l $location --address-prefixes $pls_vnet_address --subnet-name $pls_vm_subnet_name --subnet-prefixes $pls_vm_subnet_address -o none

#Before a private link service can be created in the virtual network, the setting privateLinkServiceNetworkPolicies must be disabled.
echo -e "\e[1;36mDisabling network policy on $pe_vnet_name VNet for private link service to work...\e[0m"
az network vnet subnet update -g $rg -n $pls_vm_subnet_name --vnet-name $pls_vnet_name --private-link-service-network-policies Disabled -o none

# pe vnet
echo -e "\e[1;36mCreating $pe_vnet_name VNet...\e[0m"
az network vnet create -g $rg -n $pe_vnet_name -l $location --address-prefixes $pe_vnet_address --subnet-name $pe_vm_subnet_name --subnet-prefixes $pe_vm_subnet_address -o none

# ilb
echo -e "\e[1;36mCreating internal load balancer (ilb)...\e[0m"
az network lb create -g $rg -n ilb --sku Standard --vnet-name $pls_vnet_name --subnet $pls_vm_subnet_name --backend-pool-name vmss --frontend-ip-name fe -o none

# ilb health probe
echo -e "\e[1;36mCreating a health probe for ilb...\e[0m"
az network lb probe create -g $rg -n vmssprobe --lb-name ilb --protocol Http --port 80 --path / -o none

# ilb load balancer rule
echo -e "\e[1;36mCreating a load balancer rule for ilb...\e[0m"
az network lb rule create -g $rg -n httpRule --lb-name ilb --protocol Tcp --frontend-port 80 --backend-port 80 --frontend-ip-name fe --backend-pool-name vmss --probe-name vmssprobe --idle-timeout 15 --enable-tcp-reset -o none

# nsg
echo -e "\e[1;36mCreating a NSG and allowing HTTP and RDP...\e[0m"
az network nsg create -g $rg -n $pls_vnet_name -o none
az network nsg rule create -g $rg -n AllowHttp --nsg-name $pls_vnet_name --protocol '*' --direction Inbound --source-address-prefixes '*' --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges 80 --access Allow --priority 200 -o none
az network nsg rule create -g $rg -n AllowRdp --nsg-name $pls_vnet_name --protocol '*' --direction Inbound --source-address-prefixes $myip --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges 3389 --access Allow --priority 300 -o none

# nat gateway
echo -e "\e[1;36mCreating a NAT Gateway to allow the VMSS to download the custom script and install nginx and InspectorGadget...\e[0m"
az network public-ip create -g $rg -n natgw --sku Standard -o nome
az network nat gateway create -g $rg -n natgw --public-ip-addresses natgw --idle-timeout 10 -o nome
az network vnet subnet update -g $rg -n $pls_vm_subnet_name --vnet-name $pls_vnet_name --nat-gateway natgw --nsg $pls_vnet_name -o none

# vmss
echo -e "\e[1;36mCreating a Virtual Machine Scaleset and put it as a backend pool for the ilb...\e[0m"
az vmss create -g $rg -n vmss --image $vm_image --admin-username $admin_username --generate-ssh-keys --lb ilb --orchestration-mode Uniform --instance-count 2 --vnet-name $pls_vnet_name --subnet $pls_vm_subnet_name --nsg $pls_vnet_name --vm-sku $vm_size --custom-data $cloudinit_file --upgrade-policy-mode Automatic -o none

# private link service
echo -e "\e[1;36mCreating a Private Link Service to the ilb...\e[0m"
az network private-link-service create -g $rg -n pls --vnet-name $pls_vnet_name --subnet $pls_vm_subnet_name --lb-name ilb --lb-frontend-ip-configs fe --private-ip-address 10.1.0.250 --private-ip-allocation-method Static --private-ip-address-version IPv4 -o none
plsip=$(az network private-link-service show -g $rg -n pls --query ipConfigurations[0].privateIPAddress -o tsv)
plsid=$(az network private-link-service show -g $rg -n pls --query id -o tsv)

# private endpoint
echo -e "\e[1;36mCreating a Private Endpoint and connect it to the Private Link Service...\e[0m"
az network private-endpoint create -g $rg -n pe --connection-name pls-conn --private-connection-resource-id $plsid --subnet $pe_vm_subnet_name --vnet-name $pe_vnet_name --manual-request false
peip=$(az network nic list -g $rg --query "[?contains(name,'pe.nic')].ipConfigurations[0].privateIPAddress" -o tsv)

# pe test vm
echo -e "\e[1;36mCreating a VM in PE VNet to access the private endpoint...\e[0m"
az network public-ip create -g $rg -n $pe_vnet_name-jump --sku basic -o none
az network nic create -g $rg -n $pe_vnet_name-jump -l $location --public-ip-address $pe_vnet_name-jump --vnet-name $pe_vnet_name --subnet $pe_vm_subnet_name -o none
az vm create -g $rg -n $pe_vnet_name-jump -l $location --image $win_vm_image --nics $pe_vnet_name-jump --os-disk-name $pe_vnet_name-jump --size $vm_size --admin-username $admin_username --admin-password $admin_password --no-wait
pubip=$(az network public-ip show -g $rg -n $pe_vnet_name-jump --query ipAddress -o tsv)

echo RDP into this VM $pubip and try to to browse http://$peip which is a private endpoint connected to a private link service!!
