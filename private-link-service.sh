rg=private-link-service
location=centralindia

app_vnet_name=app
app_vnet_address=10.11.0.0/16
app_vm_subnet_name=vm
app_vm_subnet_address=10.11.0.0/24

hub1_vnet_name=hub1
hub1_vnet_address=10.1.0.0/16
hub1_gw_subnet_name=gw
hub1_gw_subnet_address=10.1.0.0/24
hub1_gw_asn=65501
hub1_gw_vti0=10.1.0.250
hub1_vm_subnet_name=vm
hub1_vm_subnet_address=10.1.1.0/24

onprem1_vnet_name=onprem1
onprem1_vnet_address=172.21.0.0/16
onprem1_gw_subnet_name=gw
onprem1_gw_subnet_address=172.21.0.0/24
onprem1_gw_asn=65502
onprem1_gw_vti0=172.21.0.250
onprem1_vm_subnet_name=vm
onprem1_vm_subnet_address=172.21.1.0/24

admin_username=$(whoami)
admin_password=Test#123#123
vm_size=Standard_B2als_v2
myip=$(curl -s https://ifconfig.co)
psk=secret12345

appinit_file=appinit.txt
cat <<EOF > $appinit_file
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

cloudinit_file=cloudinit.txt
cat <<EOF > $cloudinit_file
#cloud-config
runcmd:
  - curl -s https://deb.frrouting.org/frr/keys.gpg | sudo tee /usr/share/keyrings/frrouting.gpg > /dev/null
  - echo deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr \$(lsb_release -s -c) frr-stable | sudo tee -a /etc/apt/sources.list.d/frr.list
  - sudo apt update && sudo apt install -y frr frr-pythontools
  - sudo apt install -y strongswan inetutils-traceroute net-tools
  - sudo sed -i "/bgpd=no/ s//bgpd=yes/" /etc/frr/daemons
  - sudo service frr restart
  - sudo systemctl enable ipsec
  - cp /etc/ipsec.conf /etc/ipsec.conf.bak
  - cp /etc/ipsec.secrets /etc/ipsec.secrets.bak
  - echo "net.ipv4.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
  - echo "net.ipv4.conf.default.forwarding=1" | sudo tee -a /etc/sysctl.conf
  - sudo sysctl -p
EOF

function first_ip(){
    subnet=$1
    IP=$(echo $subnet | cut -d/ -f 1)
    IP_HEX=$(printf '%.2X%.2X%.2X%.2X\n' `echo $IP | sed -e 's/\./ /g'`)
    NEXT_IP_HEX=$(printf %.8X `echo $(( 0x$IP_HEX + 1 ))`)
    NEXT_IP=$(printf '%d.%d.%d.%d\n' `echo $NEXT_IP_HEX | sed -r 's/(..)/0x\1 /g'`)
    echo "$NEXT_IP"
}

# Resource Groups
echo -e "\e[1;36mCreating $rg Resource Group...\e[0m"
az group create -l $location -n $rg -o none

# hub1 vnet
echo -e "\e[1;36mCreating $hub1_vnet_name VNet...\e[0m"
az network vnet create -g $rg -n $hub1_vnet_name -l $location --address-prefixes $hub1_vnet_address --subnet-name $hub1_vm_subnet_name --subnet-prefixes $hub1_vm_subnet_address -o none
az network vnet subnet create -g $rg -n $hub1_gw_subnet_name --address-prefixes $hub1_gw_subnet_address --vnet-name $hub1_vnet_name -o none

# hub1 gw vm
echo -e "\e[1;36mDeploying $hub1_vnet_name-gw VM...\e[0m"
az network public-ip create -g $rg -n $hub1_vnet_name-gw -l $location --allocation-method Static --sku Basic -o none
az network nic create -g $rg -n $hub1_vnet_name-gw -l $location --vnet-name $hub1_vnet_name --subnet $hub1_gw_subnet_name --ip-forwarding true --public-ip-address $hub1_vnet_name-gw -o none
az vm create -g $rg -n $hub1_vnet_name-gw -l $location --image Ubuntu2404 --nics $hub1_vnet_name-gw --os-disk-name $hub1_vnet_name-gw --size $vm_size --admin-username $admin_username --generate-ssh-keys --custom-data $cloudinit_file --no-wait
# hub1 gw details
hub1_gw_pubip=$(az network public-ip show -g $rg -n $hub1_vnet_name-gw --query ipAddress -o tsv | tr -d '\r') && echo $hub1_vnet_name-gw public ip: $hub1_gw_pubip
hub1_gw_private_ip=$(az network nic show -g $rg -n $hub1_vnet_name-gw --query ipConfigurations[].privateIPAddress -o tsv | tr -d '\r')  && echo $hub1_vnet_name-gw private ip: $hub1_gw_private_ip
hub1_gw_nic_default_gw=$(first_ip $hub1_gw_subnet_address) && echo $hub1_vnet_name-gw default gateway ip: $hub1_gw_nic_default_gw

# onprem1 vnet
echo -e "\e[1;36mCreating $onprem1_vnet_name VNet...\e[0m"
az network vnet create -g $rg -n $onprem1_vnet_name -l $location --address-prefixes $onprem1_vnet_address --subnet-name $onprem1_vm_subnet_name --subnet-prefixes $onprem1_vm_subnet_address -o none
az network vnet subnet create -g $rg -n $onprem1_gw_subnet_name --address-prefixes $onprem1_gw_subnet_address --vnet-name $onprem1_vnet_name -o none

# onprem1 gw vm
echo -e "\e[1;36mDeploying $onprem1_vnet_name-gw VM...\e[0m"
az network public-ip create -g $rg -n $onprem1_vnet_name-gw -l $location --allocation-method Static --sku Basic -o none
az network nic create -g $rg -n $onprem1_vnet_name-gw -l $location --vnet-name $onprem1_vnet_name --subnet $onprem1_gw_subnet_name --ip-forwarding true --public-ip-address $onprem1_vnet_name-gw -o none
az vm create -g $rg -n $onprem1_vnet_name-gw -l $location --image Ubuntu2404 --nics $onprem1_vnet_name-gw --os-disk-name $onprem1_vnet_name-gw --size $vm_size --admin-username $admin_username --generate-ssh-keys --custom-data $cloudinit_file --no-wait
# onprem1 gw details
onprem1_gw_pubip=$(az network public-ip show -g $rg -n $onprem1_vnet_name-gw --query ipAddress -o tsv | tr -d '\r') && echo $onprem1_vnet_name-gw public ip: $onprem1_gw_pubip
onprem1_gw_private_ip=$(az network nic show -g $rg -n $onprem1_vnet_name-gw --query ipConfigurations[].privateIPAddress -o tsv | tr -d '\r')  && echo $onprem1_vnet_name-gw private ip: $onprem1_gw_private_ip
onprem1_gw_nic_default_gw=$(first_ip $onprem1_gw_subnet_address) && echo $onprem1_vnet_name-gw default gateway ip: $onprem1_gw_nic_default_gw

# app vnet
echo -e "\e[1;36mCreating $app_vnet_name VNet...\e[0m"
az network vnet create -g $rg -n $app_vnet_name -l $location --address-prefixes $app_vnet_address --subnet-name $app_vm_subnet_name --subnet-prefixes $app_vm_subnet_address -o none

# Before a private link service can be created in the virtual network, the setting privateLinkServiceNetworkPolicies must be disabled.
echo -e "\e[1;36mDisabling network policy on $app_vnet_name VNet for private link service to work...\e[0m"
az network vnet subnet update -g $rg -n $app_vm_subnet_name --vnet-name $app_vnet_name --private-link-service-network-policies Disabled -o none

# ilb
echo -e "\e[1;36mCreating internal load balancer (ilb)...\e[0m"
az network lb create -g $rg -n ilb --sku Standard --vnet-name $app_vnet_name --subnet $app_vm_subnet_name --backend-pool-name vmss --frontend-ip-name fe -o none

# ilb health probe
echo -e "\e[1;36mCreating a health probe for ilb...\e[0m"
az network lb probe create -g $rg -n vmssprobe --lb-name ilb --protocol Http --port 80 --path / -o none

# ilb load balancer rule
echo -e "\e[1;36mCreating a load balancer rule for ilb...\e[0m"
az network lb rule create -g $rg -n httpRule --lb-name ilb --protocol Tcp --frontend-port 80 --backend-port 80 --frontend-ip-name fe --backend-pool-name vmss --probe-name vmssprobe --idle-timeout 15 --enable-tcp-reset -o none

# nsg
echo -e "\e[1;36mCreating a NSG and allowing HTTP and RDP...\e[0m"
az network nsg create -g $rg -n $app_vnet_name -o none
az network nsg rule create -g $rg -n AllowHttp --nsg-name $app_vnet_name --protocol '*' --direction Inbound --source-address-prefixes '*' --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges 80 --access Allow --priority 200 -o none
az network nsg rule create -g $rg -n AllowRdp --nsg-name $app_vnet_name --protocol '*' --direction Inbound --source-address-prefixes $myip --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges 3389 --access Allow --priority 300 -o none

# nat gateway
echo -e "\e[1;36mCreating a NAT Gateway to allow the VMSS to download the custom script and install nginx and InspectorGadget...\e[0m"
az network public-ip create -g $rg -n natgw --sku Standard -o none
az network nat gateway create -g $rg -n natgw --public-ip-addresses natgw --idle-timeout 10 -o none
az network vnet subnet update -g $rg -n $app_vm_subnet_name --vnet-name $app_vnet_name --nat-gateway natgw --nsg $app_vnet_name -o none

# vmss
echo -e "\e[1;36mCreating a Virtual Machine Scaleset and put it as a backend pool for the ilb...\e[0m"
az vmss create -g $rg -n vmss --image Ubuntu2404 --admin-username $admin_username --generate-ssh-keys --lb ilb --orchestration-mode Uniform --instance-count 2 --vnet-name $app_vnet_name --subnet $app_vm_subnet_name --nsg $app_vnet_name --vm-sku $vm_size --custom-data $appinit_file --upgrade-policy-mode Automatic --no-wait

# private link service
echo -e "\e[1;36mCreating a Private Link Service to the ilb...\e[0m"
az network private-link-service create -g $rg -n app --vnet-name $app_vnet_name --subnet $app_vm_subnet_name --lb-name ilb --lb-frontend-ip-configs fe --private-ip-address 10.11.0.250 --private-ip-allocation-method Static --private-ip-address-version IPv4 -o none
appid=$(az network private-link-service show -g $rg -n app --query id -o tsv | tr -d '\r')

# private endpoint
echo -e "\e[1;36mCreating a Private Endpoint and connect it to the Private Link Service...\e[0m"
az network private-endpoint create -g $rg -n pe --connection-name app-conn --private-connection-resource-id $appid --subnet $hub1_vm_subnet_name --vnet-name $hub1_vnet_name --manual-request false -o none
peip=$(az network nic list -g $rg --query "[?contains(name,'pe.nic')].ipConfigurations[0].privateIPAddress" -o tsv | tr -d '\r')

# hub1 vm subnet route table
echo -e "\e[1;36mDeploying $hub1_vnet_name route table and attaching it to $hub1_vm_subnet_name subnet...\e[0m"
az network route-table create -n $hub1_vnet_name -g $rg -l $location -o none
az network route-table route create --address-prefix $onprem1_vnet_address -n to-$onprem1_vnet_name -g $rg --next-hop-type VirtualAppliance --route-table-name $hub1_vnet_name --next-hop-ip-address $hub1_gw_private_ip -o none
az network vnet subnet update --vnet-name $hub1_vnet_name -n $hub1_vm_subnet_name --route-table $hub1_vnet_name -g $rg -o none

# onprem1 route table
echo -e "\e[1;36mDeploying $onprem1_vnet_name route table and attaching it to $onprem1_vm_subnet_name subnet...\e[0m"
az network route-table create -n $onprem1_vnet_name -g $rg -l $location -o none
az network route-table route create --address-prefix $hub1_vnet_address -n to-$hub1_vnet_name -g $rg --next-hop-type VirtualAppliance --route-table-name $onprem1_vnet_name --next-hop-ip-address $onprem1_gw_private_ip -o none
az network vnet subnet update --vnet-name $onprem1_vnet_name -n $onprem1_vm_subnet_name --route-table $onprem1_vnet_name -g $rg -o none

# hub1 test vm
echo -e "\e[1;36mCreating a VM in PE VNet to access the private endpoint...\e[0m"
az network public-ip create -g $rg -n $hub1_vnet_name --sku basic -o none
az network nic create -g $rg -n $hub1_vnet_name -l $location --public-ip-address $hub1_vnet_name --vnet-name $hub1_vnet_name --subnet $hub1_vm_subnet_name -o none
az vm create -g $rg -n $hub1_vnet_name -l $location --image  Win2022Datacenter --nics $hub1_vnet_name --os-disk-name $hub1_vnet_name --size Standard_B2als_v2 --admin-username $admin_username --admin-password $admin_password --no-wait
hub1_pubip=$(az network public-ip show -g $rg -n $hub1_vnet_name --query ipAddress -o tsv | tr -d '\r') && echo $hub1_vnet_name public ip: $hub1_pubip

# onprem1 test vm
echo -e "\e[1;36mCreating a VM in PE VNet to access the private endpoint...\e[0m"
az network public-ip create -g $rg -n $onprem1_vnet_name --sku basic -o none
az network nic create -g $rg -n $onprem1_vnet_name -l $location --public-ip-address $onprem1_vnet_name --vnet-name $onprem1_vnet_name --subnet $onprem1_vm_subnet_name -o none
az vm create -g $rg -n $onprem1_vnet_name -l $location --image  Win2022Datacenter --nics $onprem1_vnet_name --os-disk-name $onprem1_vnet_name --size Standard_B2als_v2 --admin-username $admin_username --admin-password $admin_password --no-wait
onprem1_pubip=$(az network public-ip show -g $rg -n $onprem1_vnet_name --query ipAddress -o tsv | tr -d '\r') && echo $onprem1_vnet_name public ip: $onprem1_pubip

# clean up cloud init script
rm -rf $cloudinit_file $appinit_file

#######################
# hub1 VPN Config  #
#######################
echo -e "\e[1;36mCreating S2S/BGP VPN Config files for $hub1_vnet_name-gw gateway VM...\e[0m"
# ipsec.secrets
psk_file=~/ipsec.secrets
cat <<EOF > $psk_file
$hub1_gw_pubip $onprem1_gw_pubip : PSK $psk
EOF

# ipsec.conf
ipsec_file=~/ipsec.conf
cat <<EOF > $ipsec_file
conn %default
         # Authentication Method : Pre-Shared Key
         leftauth=psk
         rightauth=psk
         ike=aes256-sha1-modp1024!
         ikelifetime=28800s
         # Phase 1 Negotiation Mode : main
         aggressive=no
         esp=aes256-sha1!
         lifetime=3600s
         keylife=3600s
         type=tunnel
         dpddelay=10s
         dpdtimeout=30s
         keyexchange=ikev2
         rekey=yes
         reauth=no
         dpdaction=restart
         closeaction=restart
         leftsubnet=0.0.0.0/0,::/0
         rightsubnet=0.0.0.0/0,::/0
         leftupdown=/etc/strongswan.d/ipsec-vti.sh
         installpolicy=yes
         compress=no
         mobike=no
conn $onprem1_vnet_name-gw
         # OnPrem Gateway Private IP Address :
         left=$hub1_gw_private_ip
         # OnPrem Gateway Public IP Address :
         leftid=$hub1_gw_pubip
         # Azure VPN Gateway Public IP address :
         right=$onprem1_gw_pubip
         rightid=$onprem1_gw_pubip
         auto=start
         # unique number per IPSEC Tunnel eg. 100, 101 etc
         mark=101
EOF


# ipsec-vti.sh
ipsec_vti_file=~/ipsec-vti.sh
tee $ipsec_vti_file > /dev/null <<'EOT'
#!/bin/bash
#
# /etc/strongswan.d/ipsec-vti.sh
#

IP=$(which ip)
IPTABLES=$(which iptables)
PLUTO_MARK_OUT_ARR=(${PLUTO_MARK_OUT//// })
PLUTO_MARK_IN_ARR=(${PLUTO_MARK_IN//// })
PLUTO_CONNECTION=$onprem1_vnet_name-gw
VTI_INTERFACE=vti0
VTI_LOCALADDR=$hub1_gw_vti0/32
VTI_REMOTEADDR=$onprem1_gw_vti0/32
echo "`date` ${PLUTO_VERB} $VTI_INTERFACE" >> /tmp/vtitrace.log
case "${PLUTO_VERB}" in
    up-client)
        $IP link add ${VTI_INTERFACE} type vti local ${PLUTO_ME} remote ${PLUTO_PEER} okey ${PLUTO_MARK_OUT_ARR[0]} ikey ${PLUTO_MARK_IN_ARR[0]}
        sysctl -w net.ipv4.conf.${VTI_INTERFACE}.disable_policy=1
        sysctl -w net.ipv4.conf.${VTI_INTERFACE}.rp_filter=2 || sysctl -w net.ipv4.conf.${VTI_INTERFACE}.rp_filter=0
        $IP addr add ${VTI_LOCALADDR} remote ${VTI_REMOTEADDR} dev ${VTI_INTERFACE}
        $IP link set ${VTI_INTERFACE} up mtu 1350
        $IPTABLES -t mangle -I FORWARD -o ${VTI_INTERFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        $IPTABLES -t mangle -I INPUT -p esp -s ${PLUTO_PEER} -d ${PLUTO_ME} -j MARK --set-xmark ${PLUTO_MARK_IN}
        $IP route flush table 220
        /etc/init.d/frr force-reload bgpd
        ;;
    down-client)
        $IP link del ${VTI_INTERFACE}
        $IPTABLES -t mangle -D FORWARD -o ${VTI_INTERFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        $IPTABLES -t mangle -D INPUT -p esp -s ${PLUTO_PEER} -d ${PLUTO_ME} -j MARK --set-xmark ${PLUTO_MARK_IN}
        ;;
esac

# Enable IPv4 forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.eth0.disable_xfrm=1
sysctl -w net.ipv4.conf.eth0.disable_policy=1
EOT

sed -i "/\$onprem1_vnet_name-gw/ s//$onprem1_vnet_name-gw/" $ipsec_vti_file
sed -i "/\$hub1_gw_vti0/ s//$hub1_gw_vti0/" $ipsec_vti_file
sed -i "/\$onprem1_gw_vti0/ s//$onprem1_gw_vti0/" $ipsec_vti_file


# frr.conf
frr_conf_file=~/frr.conf
cat <<EOF > $frr_conf_file
frr version 10.3
frr defaults traditional
hostname $hub1_vnet_name-gw
log syslog informational
no ipv6 forwarding
service integrated-vtysh-config
!
ip route $hub1_vnet_address $hub1_gw_nic_default_gw
!
router bgp $hub1_gw_asn
 bgp router-id $hub1_gw_vti0
 no bgp ebgp-requires-policy
 neighbor $onprem1_gw_vti0 remote-as $onprem1_gw_asn
 neighbor $onprem1_gw_vti0 description $onprem1_vnet_name-gw
 neighbor $onprem1_gw_vti0 ebgp-multihop 2
 !
 address-family ipv4 unicast
  network $hub1_vnet_address
  neighbor $onprem1_gw_vti0 soft-reconfiguration inbound
 exit-address-family
exit
!
EOF

##### copy files to hub1 gw
echo -e "\e[1;36mCopying and applying S2S/BGP VPN Config files to $hub1_vnet_name-gw gateway VM...\e[0m"
scp -o StrictHostKeyChecking=no $psk_file $ipsec_file $ipsec_vti_file $frr_conf_file $hub1_gw_pubip:/home/$admin_username
scp -o StrictHostKeyChecking=no ~/.ssh/id_rsa $hub1_gw_pubip:/home/$admin_username/.ssh/
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $hub1_gw_pubip "sudo mv /home/$admin_username/frr.conf /etc/frr/frr.conf"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $hub1_gw_pubip "sudo mv /home/$admin_username/ipsec.* /etc/"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $hub1_gw_pubip "sudo mv /home/$admin_username/ipsec-vti.sh /etc/strongswan.d/"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $hub1_gw_pubip "sudo chmod +x /etc/strongswan.d/ipsec-vti.sh"

# clean up config files
rm $psk_file $ipsec_file $ipsec_vti_file $frr_conf_file

#######################
# onprem1 VPN Config  #
#######################
echo -e "\e[1;36mCreating S2S/BGP VPN Config files for $onprem1_vnet_name-gw gateway VM...\e[0m"
# ipsec.secrets
psk_file=~/ipsec.secrets
cat <<EOF > $psk_file
$onprem1_gw_pubip $hub1_gw_pubip : PSK $psk
EOF

# ipsec.conf
ipsec_file=~/ipsec.conf
cat <<EOF > $ipsec_file
conn %default
         # Authentication Method : Pre-Shared Key
         leftauth=psk
         rightauth=psk
         ike=aes256-sha1-modp1024!
         ikelifetime=28800s
         # Phase 1 Negotiation Mode : main
         aggressive=no
         esp=aes256-sha1!
         lifetime=3600s
         keylife=3600s
         type=tunnel
         dpddelay=10s
         dpdtimeout=30s
         keyexchange=ikev2
         rekey=yes
         reauth=no
         dpdaction=restart
         closeaction=restart
         leftsubnet=0.0.0.0/0,::/0
         rightsubnet=0.0.0.0/0,::/0
         leftupdown=/etc/strongswan.d/ipsec-vti.sh
         installpolicy=yes
         compress=no
         mobike=no
conn $hub1_vnet_name-gw
         # OnPrem Gateway Private IP Address :
         left=$onprem1_gw_private_ip
         # OnPrem Gateway Public IP Address :
         leftid=$onprem1_gw_pubip
         # Azure VPN Gateway Public IP address :
         right=$hub1_gw_pubip
         rightid=$hub1_gw_pubip
         auto=start
         # unique number per IPSEC Tunnel eg. 100, 101 etc
         mark=101
EOF


# ipsec-vti.sh
ipsec_vti_file=~/ipsec-vti.sh
tee $ipsec_vti_file > /dev/null <<'EOT'
#!/bin/bash
#
# /etc/strongswan.d/ipsec-vti.sh
#

IP=$(which ip)
IPTABLES=$(which iptables)
PLUTO_MARK_OUT_ARR=(${PLUTO_MARK_OUT//// })
PLUTO_MARK_IN_ARR=(${PLUTO_MARK_IN//// })
PLUTO_CONNECTION=$hub1_vnet_name-gw
VTI_INTERFACE=vti0
VTI_LOCALADDR=$onprem1_gw_vti0/32
VTI_REMOTEADDR=$hub1_gw_vti0/32
echo "`date` ${PLUTO_VERB} $VTI_INTERFACE" >> /tmp/vtitrace.log
case "${PLUTO_VERB}" in
    up-client)
        $IP link add ${VTI_INTERFACE} type vti local ${PLUTO_ME} remote ${PLUTO_PEER} okey ${PLUTO_MARK_OUT_ARR[0]} ikey ${PLUTO_MARK_IN_ARR[0]}
        sysctl -w net.ipv4.conf.${VTI_INTERFACE}.disable_policy=1
        sysctl -w net.ipv4.conf.${VTI_INTERFACE}.rp_filter=2 || sysctl -w net.ipv4.conf.${VTI_INTERFACE}.rp_filter=0
        $IP addr add ${VTI_LOCALADDR} remote ${VTI_REMOTEADDR} dev ${VTI_INTERFACE}
        $IP link set ${VTI_INTERFACE} up mtu 1350
        $IPTABLES -t mangle -I FORWARD -o ${VTI_INTERFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        $IPTABLES -t mangle -I INPUT -p esp -s ${PLUTO_PEER} -d ${PLUTO_ME} -j MARK --set-xmark ${PLUTO_MARK_IN}
        $IP route flush table 220
        /etc/init.d/frr force-reload bgpd
        ;;
    down-client)
        $IP link del ${VTI_INTERFACE}
        $IPTABLES -t mangle -D FORWARD -o ${VTI_INTERFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        $IPTABLES -t mangle -D INPUT -p esp -s ${PLUTO_PEER} -d ${PLUTO_ME} -j MARK --set-xmark ${PLUTO_MARK_IN}
        ;;
esac

# Enable IPv4 forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.eth0.disable_xfrm=1
sysctl -w net.ipv4.conf.eth0.disable_policy=1
EOT

sed -i "/\$hub1_vnet_name-gw/ s//$hub1_vnet_name-gw/" $ipsec_vti_file
sed -i "/\$onprem1_gw_vti0/ s//$onprem1_gw_vti0/" $ipsec_vti_file
sed -i "/\$hub1_gw_vti0/ s//$hub1_gw_vti0/" $ipsec_vti_file


# frr.conf
frr_conf_file=~/frr.conf
cat <<EOF > $frr_conf_file
frr version 10.3
frr defaults traditional
hostname $hub1_vnet_name-gw
log syslog informational
no ipv6 forwarding
service integrated-vtysh-config
!
ip route $onprem1_vnet_address $onprem1_gw_nic_default_gw
!
router bgp $onprem1_gw_asn
 bgp router-id $onprem1_gw_vti0
 no bgp ebgp-requires-policy
 neighbor $hub1_gw_vti0 remote-as $hub1_gw_asn
 neighbor $hub1_gw_vti0 description $hub1_vnet_name-gw
 neighbor $hub1_gw_vti0 ebgp-multihop 2
 !
 address-family ipv4 unicast
  network $onprem1_vnet_address
  neighbor $hub1_gw_vti0 soft-reconfiguration inbound
 exit-address-family
exit
!
EOF

##### copy files to onprem gw
echo -e "\e[1;36mCopying and applying S2S/BGP VPN Config files to $onprem1_vnet_name-gw gateway VM...\e[0m"
scp -o StrictHostKeyChecking=no $psk_file $ipsec_file $ipsec_vti_file $frr_conf_file $onprem1_gw_pubip:/home/$admin_username
scp -o StrictHostKeyChecking=no ~/.ssh/id_rsa $onprem1_gw_pubip:/home/$admin_username/.ssh/
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $onprem1_gw_pubip "sudo mv /home/$admin_username/frr.conf /etc/frr/frr.conf"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $onprem1_gw_pubip "sudo mv /home/$admin_username/ipsec.* /etc/"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $onprem1_gw_pubip "sudo mv /home/$admin_username/ipsec-vti.sh /etc/strongswan.d/"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $onprem1_gw_pubip "sudo chmod +x /etc/strongswan.d/ipsec-vti.sh"


# clean up config files
rm $psk_file $ipsec_file $ipsec_vti_file $frr_conf_file

ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $hub1_gw_pubip "sudo ipsec restart"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $onprem1_gw_pubip "sudo ipsec restart"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $hub1_gw_pubip "sudo ipsec status"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $onprem1_gw_pubip "sudo ipsec status"

echo -e "\e[1;36mChecking BGP routing on $hub1_vnet_name-gw gateway vm...\e[0m"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $hub1_gw_pubip "sudo vtysh -c 'show bgp summary' && sudo vtysh -c 'show bgp all' && sudo vtysh -c 'show int brief' && sudo vtysh -c 'show ip route'"

echo -e "\e[1;36mChecking BGP routing on $onprem1_vnet_name-gw gateway vm...\e[0m"
ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no $onprem1_gw_pubip "sudo vtysh -c 'show bgp summary' && sudo vtysh -c 'show bgp all' && sudo vtysh -c 'show int brief' && sudo vtysh -c 'show ip route'"

echo -e "\e[1;32mRDP into $hub1_vnet_name IP VM $hub1_pubip and to $onprem1_vnet_name VM IP $onprem1_pubip and try to to browse http://$peip which is a private endpoint connected to a private link service...\e[0m"
echo -e "\e[1;32mWhen the pages loads, notice the X-Forwarded-For under HTTP Headers is the IP address of the private link service 10.11.0.250\e[0m"

# rg cleanup
# az group delete -n $rg --yes --no-wait
