OPNsense PIA Wireguard Script
===
This script automates the process of getting Wireguard set up on OPNsense to connect to PIA's NextGen Wireguard servers.
It will create Wireguard Instance(Local) and Peer(Endpoint) on your OPNsense set up automaticly, it'll then maintain the tunnel to keep it up and connected.

Warning: Advanced Users Recommended

**What does it do**
 1. Creates WireGuard Interface in OPNsense
 2. Maintains connection to a PIA server (encase PIA server goes down) default check is every 5 minutes
 3. Allows rotation of PIA server on a user defined schedule, create a cron job and add "changeserver" to the parameters

**Prerequisites**
 1. OPNsense 20.7 onwards (prior versions not tested)
 2. WireGuard Plugin Installed
 3. Enable Secure Shell, Permit root user login and Permit password login (System: Settings: Administration -> Secure Shell) this can be reverted once the tunnel is working.
 4. HTTPS WebUI enabled (System: Settings: Administration -> Protocol: HTTPS)

**Setup**
 1. Create new user called something on the lines of "WireguardAPI",
     1. Go to  System: Access: Users
     2. Click Add on the top right
     3. Username: WireguardAPI
     4. Password leave empty and tick "Generate a scrambled password to prevent local database logins for this user."
     5. Scroll right to the bottom and click "Save"
     6. Now the user is created we can give its permissions and generate an API key pair
     7. Scroll down to you see "Effective Privileges", you want to give it the following permissions
         - Firewall: Alias: Edit
         - Firewall: Aliases
         - VPN: Wireguard
     8. Click Plus sign on API Keys, it'll download you the keys in a txt file. We'll want this later
     9. Click Save
 2. Edit "PIAWireguard.py" and edit the user variables in the script with the api key from OPNsense, your PIA credentials and region id. Use Notepad++ or your favourite IDE.
     - You can get your PIA region id by running ListRegions.py on your local device. If you don't have Python installed on your local device you can use this [Online Python Tool](https://www.programiz.com/python-programming/online-compiler/) copy the contents of the file and then click "Run". This will list the name and region id of each PIA region, for you choose from.
     - It is also possible to get PIA region ids running the main script using the argument listregions
     - Following User variables need filling in. (Between lines 34-45)
         - `opnsenseKey` WireguardAPI key you generated on step 1
         - `opnsenseSecret` WireguardAPI secret you generated on step 1
         - `piaUsername` Your PIA username
         - `piaPassword` Your PIA password
         - `piaRegionId` Change to your PIA region id
 3. Copying the following files to OPNsense using SCP or Filezilla etc, make sure you using the root user of OPNsense when you connect, otherwise you'll get access denied messages.
     - "PIAWireguard.py" and "ca.rsa.4096.crt" to "/conf/"
     - "actions_piawireguard.conf" to "/usr/local/opnsense/service/conf/actions.d/"
 4. SSH to OPNsense and drop in to a terminal "option 8". You can use Putty on Windows to SSH
 5. Run the following commands
     - chmod +x /conf/PIAWireguard.py
     - service configd restart
     - /conf/PIAWireguard.py debug
 6. Go to Interfaces: Assignments in OPNsense, so we can assign the new interface
     1. At the bottom of the interfaces you'll see "New interface", on the drop down select wg0, unless you already had one set up then select wg1 etc...
     2. Give it a description like WAN_PIAWG
     3. Once selected click the + button
     4. A new WAN_PIAWG interface will show on the list, which will be the new wg interface, click on it to edit.
     5. Tick "Enable Interface", click save and Apply Changes. nothing else
 7. Go to System: Gateways: Single, so we can set up the PIA gateway
     1. Top right Click Add
     2. Enter the name "WAN_PIAWG_IPv4"
     3. Interface select "WAN_PIAWG"
     4. Tick "Far Gateway"
     5. Untick "Disable Gateway Monitoring"
     6. Click Save and Apply Changes
 8. Go back to the SSH terminal, run the following command
     - /conf/PIAWireguard.py debug changeserver
 9. Now OPNsense should be se tup to be able to use PIA as an internet gateway, if you go back in to System: Gateways: Single, you should see WAN_PIAWG_IPv4 now has a gateway IP and its pinging
 10. Now we need to set up a cron to make sure the tunnel says up and change server when necessary. Go to System: Settings: Cron
     1. Click the plus button at the bottom right of the table
     2. Enter "*/5" in the minute box
     3. Enter "*" in the hours box
     4. Select "PIA WireGuard" on the command dropdown
     5. Give it a Description of your choice.
     6. Click Save
 11. Last thing we need to set up is maximum MSS for TCP packets, which is 40 bytes smaller than the MTU of WireGuard, by default Wireguard uses 1420 bytes MTU. So we need to set an MSS maximum of 1380. (Without this you may have issues loading websites or slow speeds).
 Goto Firewall: Settings: Normalization
     1. Click Add
     2. Interface select "WAN_PIAWG"
     3. Enter Description of "Maximum MSS for PIA WireGuard Tunnel"
     4. Max MSS to "1380"
     5. Click Save (you will notice it'll now list this as OPT rather than the interface name, don't worry it's still correct, just edit it to verify you made the right selection)
     6. Click Apply Changes
 12. OPNsense should now look after the tunnel itself encase the tunnel disconnects, every 5 minutes it'll check the status and change server if the server has gone down.
 13. You'll need to create your own NAT and Firewall rules to use this tunnel, an advanced user should be able to do this.

 Note: If your having speed issues, you may need to change PIA server region or lower the default MTU from 1420, advanced users should understand how to do this. 

***Port Forwarding***

To use port forwarding Enable "piaPortForward" variable in the python script. This will create an alias in your system called PIA_Port, which you can then use in your Port Forwarding rule. This variable will self update when required.
If you need a way to found out this port for an internal application, you can go to the following URL of your OPNsense to get the port, as its published publicly to devices that can reach the HTTPS port of OPNsense
https://opnsense.lan/wg0_port.txt

"WireGuard" is a registered trademarks of Jason A. Donenfeld.
"Private Internet Access" is owned by Private Internet Access, Inc. All Rights Reserved
