OPNsense PIA Wireguard Script
===
This script automates the process of getting Wireguard set up on OPNsense to connect to PIA's NextGen Wireguard servers.
It will create Wireguard Instance and Peer on your OPNsense set up automaticly, it'll then maintain the tunnel to keep it up and connected.

Warning: Advanced Users Recommended

**What does it do**
 1. Creates WireGuard Interface in OPNsense
 2. Maintains connection to a PIA server (encase PIA server goes down) default check is every 5 minutes
 3. Allows rotation of PIA server on a user defined schedule, create a cron job and add "changeserver" to the parameters

**Prerequisites**
 1. OPNsense 23.7.10 onwards
 2. WireGuard Plugin Installed
 3. Enable Secure Shell, Permit root user login and Permit password login (System: Settings: Administration -> Secure Shell) this can be reverted once the tunnel is working.
 4. HTTPS WebUI enabled (System: Settings: Administration -> Protocol: HTTPS)

**Setup**
 1. Create new user called something on the lines of `WireguardAPI`,
     1. Go to  System: Access: Users
     2. Click Add on the top right
     3. Username: WireguardAPI
     4. Password leave empty and tick `Generate a scrambled password to prevent local database logins for this user.`
     5. Scroll right to the bottom and click `Save`
     6. Now the user is created we can give its permissions and generate an API key pair
     7. Scroll down to you see `Effective Privileges`, you want to give it the following permissions
         - Firewall: Alias: Edit
         - Firewall: Aliases
         - System: Static Routes
         - VPN: Wireguard
     8. Click Plus sign on API Keys, it'll download you the keys in a txt file. We'll want this later
     9. Click Save
 1. SSH to OPNsense and drop in to a terminal `option 8`.
 1. as `root`. Run the below commands.
     - `fetch -o /conf https://raw.githubusercontent.com/FingerlessGlov3s/OPNsensePIAWireguard/main/PIAWireguard.py`
     - `fetch -o /conf https://raw.githubusercontent.com/FingerlessGlov3s/OPNsensePIAWireguard/main/ca.rsa.4096.crt`
     - `fetch -o /usr/local/opnsense/service/conf/actions.d https://raw.githubusercontent.com/FingerlessGlov3s/OPNsensePIAWireguard/main/actions_piawireguard.conf`
 1. Edit `PIAWireguard.json` and edit the variables with the api keys from OPNsense, your PIA credentials and region id. Use Notepad++ or your favourite IDE.
     - You can get your PIA region id by running `ListRegions.py` on your local device. If you don't have Python installed on your local device you can use this [Online Python Tool](https://paiza.io/en/projects/new?language=python3) copy the contents of the file and then click `Run`. This will list the name and region id of each PIA region, for you choose from.
     - It is also possible to get PIA region ids running the main script using the argument `--listregions`
     - Following variables need filling in.
         - `opnsenseKey` WireguardAPI key you downloaded from step 1 `apikeys.txt`
         - `opnsenseSecret` WireguardAPI secret you downloaded from step 1  `apikeys.txt`
         - `piaUsername` Your PIA username
         - `piaPassword` Your PIA password
         - `instances` As we support creation of multiple tunnels, Example config has one instance but you can have as many as you like. The `instances` are key value pairs. Change `instancename` to something like `london` if you using the `uk` region since but the instance name can be what you'd like it to be.
            - `regionId` Change to your PIA region id
            - `portForward` Enable port forwarding (note region support required)
            - `opnsenseWGPort` outgoing port for OPNsense, this needs to be different for each tunnel and not already be in use for something else on OPNsense
 1. Copy the json file to OPNsense using SCP or Filezilla etc, make sure you using the root user of OPNsense when you connect, otherwise you'll get access denied messages.
     - `PIAWireguard.json` to `/conf/`
 1. SSH to OPNsense and drop in to a terminal `option 8`. If you've closed the previous SSH connection.
 1. Run the following commands
     - `chmod +x /conf/PIAWireguard.py`
     - `service configd restart`
     - `/conf/PIAWireguard.py --debug`
 1. Go to Interfaces: Assignments in OPNsense, so we can assign the new interface for the tunnel/tunnels
     1. At the bottom of the interfaces you'll see `New interface`, on the drop down select `wg0`, unless you already had one set up then select `wg1` etc...
     2. Give it a description like `WAN_PIAWG`
     3. Once selected click the + button
     4. A new `WAN_PIAWG_INSTANCENAME` interface will show on the list, which will be the new wg interface, click on it to edit.
     5. Tick `Enable Interface`, click save and Apply Changes. nothing else
 1. Go to System: Gateways: Single, so we can set up the PIA gateway for the tunnel/tunnels
     1. Top right Click Add
     2. Make sure Disabled is unchecked
     3. Enter the name `WAN_PIA_INSTANCENAME_IPv4`
     4. Interface select `WAN_PIAWG_INSTANCENAME`
     5. Tick `Far Gateway`
     6. Untick `Disable Gateway Monitoring`
     7. Click Save and Apply Changes
 1. Also reccomended you set your Main gateway to have a lower Priority number than the created ones for the PIA tunnel
 1. Go back to the SSH terminal, run the following command
     - `/conf/PIAWireguard.py --debug --changeserver instancename`
 1. Now OPNsense should be setup to be able to use PIA as an internet gateway, if you go back in to System: Gateways: Single, you should see `WAN_PIA_INSTANCENAME_IPv4` now has a gateway IP and its pinging
 1. Now we need to set up a cron to make sure the tunnel says up and changes server when necessary. Go to System: Settings: Cron
     1. Click the plus button at the bottom right of the table
     2. Enter `*/5` in the minute box
     3. Enter `*` in the hours box
     4. Select `PIA WireGuard Monitor Tunnels` on the command dropdown
     5. Give it a Description of your choice.
     6. Click Save
 1. Last thing we need to set up is maximum MSS for TCP packets, which is 40 bytes smaller than the MTU of WireGuard, by default Wireguard uses 1420 bytes MTU. So we need to set an MSS maximum of 1380. (Without this you may have issues loading websites or slow speeds).
 Goto Firewall: Settings: Normalization
     1. Click Add
     2. Interface select `WAN_PIA_INSTANCENAME_IPv4`
     3. Enter Description of `Maximum MSS for PIA WireGuard Tunnel`
     4. Max MSS to `1380`
     5. Click Save (you will notice it'll now list this as OPT rather than the interface name, don't worry it's still correct, just edit it to verify you made the right selection)
     6. Click Apply Changes
 1. OPNsense should now look after the tunnel itself encase the tunnel disconnects, every 5 minutes it'll check the status and change server if the server has gone down.
 1. You'll need to create your own NAT and Firewall rules to use this tunnel, an advanced user should be able to do this.
     - There is now a [guide on OPNsense Docs](https://docs.opnsense.org/manual/how-tos/wireguard-selective-routing.html#step-7-create-an-alias-for-the-relevant-local-hosts-that-will-access-the-tunnel), which will help you here. Step 7 onwards.

Note: If your having speed issues, you may need to change PIA server region or lower the default MTU from 1420, advanced users should understand how to do this.

**Updating**

Since 2024/01/05 the script has gone a complete overhaul, upgrade steps are
1. Delete the cron entry.
1. Populate the new `PIAWireguard.json` based on your old config file and the information above
1. Upload new `PIAWireguard.py` and `PIAWireguard.json` file to `/conf/`
1. There's a few bits in the WireGuard section in OPNsense you need to rename
    1. Rename current WG instance name to `pia-{instancename}` from `PIA`
    1. Rename current WG peer to `pia-{instancename}-server` from `PIA-Server`
1. If your using port forwarding rename the alias to `pia_{instancename}_port` from `PIA_Port` 
1. Ensure you applied all changes
1. Run the new script via SSH in debug mode and ensure it's working `python3 PIAWireguard.py --debug`, should return `instancename tunnel up - last handshake x seconds ago` as the last log entry
1. Then run again but this time forcing a it to change server `python3 PIAWireguard.py --debug --changeserver instancename`
1. If all is working correctly, then re-create the cron entry, see above for example as command name changed
1. Now double check all your configured routes and rules, ensure IP leaking isn't happening etc

See releases, starting from the version you have installed, to see if there's anything you need to do, usually it's just upgrade the py script itself.

***Port Forwarding***

To use port forwarding Enable `portForward` variable in the json file for the intance from `false` to `true`. This will create an alias in your system called `pia_instancename_port`, which you can then use in your Port Forwarding rule. This alias will self update when required.
If you need a way to find out this port for an internal application, you can go to the following URL of your OPNsense to get the port, as its published publicly to devices that can reach the HTTPS port of OPNsense
https://opnsense.lan/wg0_port.txt

Note: Not all server locations support port forwarding.

***Dedicated IP***

If you have purchased a Dedicated IP from PIA. Add your DIP token to `dipToken` in the json file for the instance, then to enable the usage simply set `dip` to `true`. Remember PIA only give you the DIP token once, so make sure you have backed up the token somewhere.

I have developed this functionality by reserve engineering the PIA client, at this moment in time manual connections for DIP is not offically supported by PIA.

Note: I have not tested DIP in a while, so if this works for you let me know, if not create a GitHub issue.

***Set outgoing tunnel gateway (outgoing interface)***

In some deployments, people may be running dual or even triple WAN configurations, in this case due to how WireGuard is configured in FreeBSD (OPNsense), it'll route the PIA tunnel over the default WAN interface. Some people will want to change this to use another WAN interface as the gateway to route the PIA tunnel over.

To accommodate this functionality, this is built in to the script. You will need to get the name of your wanted gateway, for example `WAN2_DHCP`, then set this as the `tunnelGateway` variable value in the json file (value needs to be in double quotes). When the script then runs it'll add/change a static route to enforce the PIA tunnel to use that gateway (interface).

You'll find your gateway names in `System: Gateways: Single`, making sure its the IPv4 one.

---
`WireGuard` is a registered trademarks of Jason A. Donenfeld.

`Private Internet Access` is owned by Private Internet Access, Inc. All Rights Reserved
