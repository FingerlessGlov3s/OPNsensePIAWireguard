OPNsense PIA Wireguard Script
===
This script automates the process of getting Wireguard setup on OPNsense to connect to PIA's NextGen Wireguard servers.
It will create Wireguard Instance(local) and Client(peer) on your OPNsense setup.

Warning: Advanced Users Recommended

**What does it do**
 1. Creates WireGuard Interface in OPNsense
 2. Maintains connection to a PIA server (encase PIA server goes down) default check is every 5 minutes
 3. Allows rotation of PIA server on a user defined schedule

**Prerequisites**
 1. OPNsense 20.7 onwards (prior versions not tested)
 2. WireGuard Plugin Installed
 3. SSH access enabled
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
 2. Edit "PIAWireguard.py" and edit the user variables in the script with the api key from OPNsense, your PIA credentials and region id.
 3. Copying the following files to OPNsense using SCP or Filezilla etc 
    - "PIAWireguard.py" and "ca.rsa.4096.crt" to "/conf/"
    - "actions_piawireguard.conf" to "/usr/local/opnsense/service/conf/actions.d"
 4. SSH to OPNsense and drop in to a terminal "option 8"
 5. Run the following commands
    - chmod +x /conf/PIAWireguard.py
    - service configd restart
    - /conf/PIAWireguard.py debug
 6. Go to Interfaces: Assignments in OPNsense, so we can assign the new interface
    1. At the bottom of the interfaces you'll see "New interface", on the drop down select wg0, unless you already had one setup then select wg1 etc...
    2. Give it a desciption like WAN_PIAWG
    3. Once selected click the + button
    4. A new WAN_PIAWG interface will show on the list, which will be the new wg interface, click on it to edit.
    5. Tick "Enable Interface" and press save. nothing else
 7. Go to  # System: Gateways: Single, so we can setup the PIA gateway
    1. Top right Click Add
    2. Enter the name "WAN_PIAWG_IPv4"
    3. Interface select "WAN_PIAWG"
    4. Tick "Far Gateway"
    5. Untick "Disable Gateway Monitoring"
    6. Click Save
 8. Go back to the SSH terminal, run the following command
    - /conf/PIAWireguard.py debug changeserver
 9. Now OPNsense should be setup to be able to use PIA as a internet gateway, if you go back in to System: Gateways: Single, you should see WAN_PIAWG_IPv4 now has a gateway
 10. Now we need to setup a cron to make sure the tunnel says up and change server when necessary. Go to System: Settings: Cron
     - Click the plus button at the bottom right of the table
     - Enter "*/5" in the minute box
     - Enter "*" in the hours box
     - Select "PIA WireGuard" on the command dropdown
     - Give it a Description of your choice.
     - Click Save
 11. OPNsense should now look after the tunnel itself encase the tunnel disconnects every 5 minutes it'll check the status and change server if the server has gone down.
 12. You'll need to create your own NAT and Firewall rules to use this tunnel, an advanced user should be able to do this.

***Port Forwarding***

To use port forwarding Enable "piaPortForward" variable in the python script. This will create an alias in your system called PIA_Port, which you can then use in your Port Forwarding rule. This variable will self update when required.
If you need a way to found out this port for an internal application, you can go to the following URL of your OPNsense to get the port, as its published publicly to devices that can reach the HTTPS port of OPNsense
https://opnsense.lan/wg0_port.txt

"WireGuard" is a registered trademarks of Jason A. Donenfeld.
"Private Internet Access" is owned by Private Internet Access, Inc. All Rights Reserved
