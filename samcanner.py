#!/usr/bin/env python
# -*- coding: utf-8 -*-
#autor samir sanchez garnica @sasaga92
import argparse
import socket
import sys
import platform
import os
from time import time
from multiprocessing.pool import Pool
from commands import getoutput


common_ports = {
	5: 'Remote Job Entry',
	7: 'Echo',
	9: 'Discard',
	11: 'Active Users',
	13: 'DAYTIME – (RFC 867)',
	17: 'Quote of the Day',
	18: 'Message Send Protocol',
	19: 'Character Generator',
	20: 'FTP – data',
	21: 'FTP—control (command)',
	22: 'Secure Shell (SSH)—used for secure logins, file transfers (scp, sftp) and port forwarding',
	23: 'Telnet protocol—unencrypted text communications',
	25: 'Simple Mail Transfer Protocol (SMTP)—used for e-mail routing between mail servers',
	35: 'Any private printer server protocol',
	35: 'QMS Magicolor 2 printer server protocol',
	37: 'TIME protocol',
	39: 'Resource Location Protocol[2] (RLP)—used for determining the location of higher level services from hosts on a network',
	41: 'Graphics',
	42: 'nameserver, ARPA Host Name Server Protocol',
	42: 'WINS',
	43: 'WHOIS protocol',
	49: 'TACACS Login Host protocol',
	52: 'XNS (Xerox Network Services) Time Protocol',
	53: 'Domain Name System (DNS)',
	54: 'XNS (Xerox Network Services) Clearinghouse',
	56: 'XNS (Xerox Network Services) Authentication',
	56: 'RAP (Route Access Protocol)[3]',
	57: 'MTP, Mail Transfer Protocol',
	58: 'XNS (Xerox Network Services) Mail',
	67: 'Bootstrap Protocol (BOOTP) Server; also used by Dynamic Host Configuration Protocol (DHCP)',
	68: 'Bootstrap Protocol (BOOTP) Client; also used by Dynamic Host Configuration Protocol (DHCP)',
	69: 'Trivial File Transfer Protocol (TFTP)',
	70: 'Gopher protocol',
	79: 'Finger protocol',
	80: 'Hypertext Transfer Protocol (HTTP)',
	81: 'Torpark—Onion routing',
	82: 'Torpark—Control',
	83: 'MIT ML Device',
	88: 'Kerberos—authentication system',
	90: 'dnsix (DoD Network Security for Information Exchange) Securit Attribute Token Map',
	90: 'Pointcast',
	101: 'NIC host name',
	102: 'ISO–TSAP (Transport Service Access Point) Class 0 protocol[4]',
	104: 'ACR/NEMA Digital Imaging and Communications in Medicine',
	107: 'Remote TELNET Service[5] protocol',
	109: 'Post Office Protocol 2 (POP2)',
	110: 'Post Office Protocol 3 (POP3)',
	111: 'Sun Remote Procedure Call',
	113: 'ident—user identification system, used by IRCservers to identify users',
	113: 'Authentication Service (auth)',
	115: 'Simple File Transfer Protocol (SFTP)',
	117: 'UUCP Path Service',
	118: 'SQL (Structured Query Language) Services',
	119: 'Network News Transfer Protocol (NNTP)—used for retrieving newsgroup messages',
	123: 'Network Time Protocol (NTP)—used for time synchronization',
	135: 'DCE endpoint resolution',
	135: 'Microsoft EPMAP (End Point Mapper), also known as DCE/RPC Locator service[6]',
	137: 'NetBIOS NetBIOS Name Service',
	138: 'NetBIOS NetBIOS Datagram Service',
	139: 'NetBIOS NetBIOS Session Service',
	143: 'Internet Message Access Protocol (IMAP)—used for retrieving, organizing, and synchronizing e-mail messages',
	152: 'Background File Transfer Program (BFTP)[7]',
	153: 'SGMP, Simple Gateway Monitoring Protocol',
	156: 'SQL Service',
	158: 'DMSP, Distributed Mail Service Protocol',
	161: 'Simple Network Management Protocol (SNMP)',
	162: 'Simple Network Management Protocol Trap (SNMPTRAP)[8]',
	170: 'Print-srv, Network PostScript',
	177: 'X Display Manager Control Protocol (XDMCP)',
	179: 'BGP (Border Gateway Protocol)',
	194: 'IRC (Internet Relay Chat)',
	199: 'smux',
	201: 'AppleTalk Routing Maintenance',
	209: 'The Quick Mail Transfer Protocol',
	213: 'IPX',
	218: 'MPP, Message Posting Protocol',
	220: 'IMAP, Interactive Mail Access Protocol, version 3',
	259: 'ESRO, Efficient Short Remote Operations',
	264: 'BGMP, Border Gateway Multicast Protocol',
	311: 'Mac OS X Server Admin (officially AppleShare IP Web administration)',
	308: 'Novastor Online Backup',
	318: 'PKIX TSP, Time Stamp Protocol',
	323: 'IMMP, Internet Message Mapping Protocol',
	350: 'MATIP-Type A, Mapping of Airline Traffic over Internet Protocol',
	351: 'MATIP-Type B, Mapping of Airline Traffic over Internet Protocol',
	366: 'ODMR, On-Demand Mail Relay',
	369: 'Rpc2portmap',
	371: 'ClearCase albd',
	383: 'HP data alarm manager',
	384: 'A Remote Network Server System',
	387: 'AURP, AppleTalk Update-based Routing Protocol',
	389: 'Lightweight Directory Access Protocol (LDAP)',
	401: 'UPS Uninterruptible Power Supply',
	402: 'Altiris, Altiris Deployment Client',
	411: 'Direct Connect Hub',
	412: 'Direct Connect Client-to-Client',
	427: 'Service Location Protocol (SLP)',
	443: 'Hypertext Transfer Protocol over TLS/SSL (HTTPS)',
	444: 'SNPP, Simple Network Paging Protocol (RFC 1568)',
	445: 'Microsoft-DS Active Directory, Windows shares',
	445: 'Microsoft-DS SMB file sharing',
	464: 'Kerberos Change/Set password',
	465: 'Cisco protocol',
	465: 'SMTP over SSL',
	475: 'tcpnethaspsrv (Hasp services, TCP/IP version)',
	497: 'Dantz Retrospect',
	500: 'Internet Security Association and Key Management Protocol (ISAKMP)',
	502: 'Modbus, Protocol',
	504: 'Citadel – multiservice protocol for dedicated clients for the Citadel groupware system',
	510: 'First Class Protocol',
	512: 'Rexec, Remote Process Execution',
	512: 'comsat, together with biff',
	513: 'Login',
	513: 'Who',
	514: 'Shell—used to execute non-interactive commands on a remote system',
	514: 'Syslog—used for system logging',
	515: 'Line Printer Daemon—print service',
	517: 'Talk',
	518: 'NTalk',
	520: 'efs, extended file name server',
	520: 'Routing—RIP',
	524: 'NCP (NetWare Core Protocol) is used for a variety things such as access to primary NetWare server resources, Time Synchronization, etc.',
	525: 'Timed, Timeserver',
	530: 'RPC',
	531: 'AOL Instant Messenger, IRC',
	532: 'netnews',
	533: 'netwall, For Emergency Broadcasts',
	540: 'UUCP (Unix-to-Unix Copy Protocol)',
	542: 'commerce (Commerce Applications)',
	543: 'klogin, Kerberos login',
	544: 'kshell, Kerberos Remote shell',
	546: 'DHCPv6 client',
	547: 'DHCPv6 server',
	548: 'Apple Filing Protocol (AFP) over TCP',
	550: 'new-rwho, new-who',
	554: 'Real Time Streaming Protocol (RTSP)',
	556: 'Remotefs, RFS, rfs_server',
	560: 'rmonitor, Remote Monitor',
	561: 'monitor',
	563: 'NNTP protocol over TLS/SSL (NNTPS)',
	587: 'e-mail message submission[9] (SMTP)',
	591: 'FileMaker 6.0 (and later) Web Sharing (HTTP Alternate, also see port 80)',
	593: 'HTTP RPC Ep Map, Remote procedure call over Hypertext Transfer Protocol, often used by Distributed Component Object Model services and Microsoft Exchange Server',
	604: 'TUNNEL profile[10], a protocol for BEEP peers to form an application layer tunnel',
	623: 'ASF Remote Management and Control Protocol</ref> (ASF-RMCP)',
	631: 'Internet Printing Protocol (IPP)',
	636: 'Lightweight Directory Access Protocol over TLS/SSL(LDAPS)',
	639: 'MSDP, Multicast Source Discovery Protocol',
	646: 'LDP, Label Distribution Protocol, a routing protocol used in MPLS networks',
	647: 'DHCP Failover protocol[11]',
	648: 'RRP (Registry Registrar Protocol)[12]',
	652: 'DTCP, Dynamic Tunnel Configuration Protocol',
	654: 'AODV (Ad-hoc On-demand Distance Vector)',
	655: 'IEEE MMS (IEEE Media Management System)[13][14]',
	657: 'IBM RMC (Remote monitoring and Control) protocol, used by System p5 AIX Integrated Virtualization Manager (IBM)',
	660: 'Mac OS X Server administration',
	665: 'sun-dr, Remote Dynamic Reconfiguration',
	666: 'Doom, first online first-person shooter',
	674: 'ACAP (Application Configuration Access Protocol)',
	691: 'MS Exchange Routing',
	692: 'Hyperwave-ISP',
	694: 'Linux-HA High availability Heartbeat',
	695: 'IEEE-MMS-SSL (IEEE Media Management System over SSL)[16]',
	698: 'OLSR (Optimized Link State Routing)',
	699: 'Access Network',
	700: 'EPP (Extensible Provisioning Protocol), a protocol for communication between domain name registries and registrars (RFC 4934)',
	701: 'LMP (Link Management Protocol (Internet))[17], a protocol that runs between a pair of nodes and is used to manage traffic engineering (TE) links',
	702: 'IRIS[18][19] (Internet Registry Information Service) over BEEP (Blocks Extensible Exchange Protocol)[20](RFC 3983)',
	706: 'SILC, Secure Internet Live Conferencing',
	711: 'Cisco TDP, Tag Distribution Protocol[21][22][23]—being replaced by the MPLS Label Distribution Protocol[24]',
	712: 'TBRPF, Topology Broadcast based on Reverse-Path Forwarding routing protocol (RFC 3684)',
	712: 'Promise RAID Controller',
	720: 'SMQP, Simple Message Queue Protocol',
	749: 'Kerberos administration',
	750: 'rfile',
	750: 'loadav',
	750: 'kerberos-iv, Kerberos version IV',
	751: 'pump',
	751: 'kerberos_master, Kerberos authentication',
	752: 'qrh',
	752: 'qrh',
	752: 'userreg_server, Kerberos Password (kpasswd) server',
	753: 'Reverse Routing Header (rrh)[25]',
	753: 'Reverse Routing Header (rrh)',
	753: 'passwd_server, Kerberos userreg server',
	754: 'tell send',
	754: 'krb5_prop, Kerberos v5 slave propagation',
	754: 'tell send',
	760: 'ns',
	760: 'krbupdate [kreg], Kerberos registration',
	782: 'Conserver serial-console management server',
	783: 'SpamAssassin spamd daemon',
	829: 'CMP (Certificate Management Protocol)',
	843: 'Adobe Flash socket policy server',
	860: 'iSCSI (RFC 3720)',
	873: 'rsync file synchronisation protocol',
	888: 'cddbp, CD DataBase (CDDB) protocol (CDDBP)—unassigned but widespread use',
	901: 'Samba Web Administration Tool (SWAT)',
	901: 'VMware Virtual Infrastructure Client (UDP from server being managed to management console)',
	902: 'VMware Server Console (TCP from management console to server being Managed)',
	902: 'VMware Server Console (UDP from server being managed to management console)',
	904: 'VMware Server Alternate (if 902 is in use, i.e. SUSE linux)',
	911: 'Network Console on Acid (NCA)—local tty redirection over OpenSSH',
	912: 'apex-mesh',
	953: 'Domain Name System (DNS) RDNC Service',
	981: 'SofaWare Technologies Remote HTTPS management for firewall devices running embedded Check PointFireWall-1 software',
	989: 'FTPS Protocol (data): FTP over TLS/SSL',
	990: 'FTPS Protocol (control): FTP over TLS/SSL',
	991: 'NAS (Netnews Administration System)',
	992: 'TELNET protocol over TLS/SSL',
	993: 'Internet Message Access Protocol over SSL (IMAPS)',
	995: 'Post Office Protocol 3 over TLS/SSL (POP3S)',
	999: 'ScimoreDB Database System',
	1023: 'Reserved[1]',
	1024: 'Reserved[1]',
	1025: 'NFS-or-IIS',
	1026: 'Often utilized by Microsoft DCOM services',
	1029: 'Often utilized by Microsoft DCOM services',
	1058: 'nim, IBM AIX Network Installation Manager (NIM)',
	1059: 'nimreg, IBM AIX Network Installation Manager(NIM)',
	1072: 'cardax',
	1077: 'imgames',
	1078: 'avocent-proxy',
	1080: 'SOCKS proxy',
	1085: 'WebObjects',
	1098: 'rmiactivation, RMI Activation',
	1099: 'rmiregistry, RMI Registry',
	1109: 'Reserved[1]',
	1109: 'Kerberos Post Office Protocol (KPOP)',
	1111: 'EasyBits School network discovery protocol (for Intel’s CMPC platform)',
	1140: 'AutoNOC protocol',
	1167: 'phone, conference calling',
	1169: 'Tripwire',
	1176: 'Perceptive Automation Indigo Home automationserver',
	1182: 'AcceleNet Intelligent Transfer Protocol',
	1194: 'OpenVPN',
	1198: 'The cajo project Free dynamic transparent distributed computing in Java',
	1200: 'scol, protocol used by SCOL 3D virtual worlds server to answer world name resolution client request[26]',
	1200: 'scol, protocol used by SCOL 3D virtual worlds server to answer world name resolution client request',
	1200: 'Steam Friends Applet',
	1214: 'Kazaa',
	1220: 'QuickTime Streaming Server administration',
	1223: 'TGP, TrulyGlobal Protocol, also known as “The Gur Protocol” (named for Gur Kimchi of TrulyGlobal)',
	1234: 'VLC media player Default port for UDP/RTP stream',
	1236: 'Symantec BindView Control UNIX Default port for TCP management server connections',
	1241: 'Nessus Security Scanner',
	1248: 'NSClient/NSClient++/NC_Net (Nagios)',
	1270: 'Microsoft System Center Operations Manager(SCOM) (formerly Microsoft Operations Manager (MOM)) agent',
	1293: 'IPSec (Internet Protocol Security)',
	1311: 'Dell Open Manage HTTPS',
	1313: 'Xbiim (Canvii server)',
	1334: 'writesrv',
	1337: 'PowerFolder P2P Encrypted File Synchronization Program',
	1337: 'WASTE Encrypted File Sharing Program',
	1352: 'IBM Lotus Notes/Domino Remote Procedure Call(RPC) protocol',
	1387: 'cadsi-lm, LMS International (formerly Computer Aided Design Software, Inc. (CADSI)) LM',
	1414: 'IBM WebSphere MQ (formerly known as MQSeries)',
	1417: 'Timbuktu Service 1 Port',
	1418: 'Timbuktu Service 2 Port',
	1419: 'Timbuktu Service 3 Port',
	1420: 'Timbuktu Service 4 Port',
	1431: 'Reverse Gossip Transport Protocol (RGTP), used to access a General-purpose Reverse-Ordered Gossip Gathering System (GROGGS) bulletin board, such as that implemented on the Cambridge University‘s Phoenix system',
	1433: 'Microsoft SQL Server database management systemServer',
	1434: 'Microsoft SQL Server database management systemMonitor',
	1494: 'Citrix XenApp Independent Computing Architecture(ICA) thin client protocol',
	1500: 'NetGuard GuardianPro firewall (NT4-based) Remote Management',
	1501: 'NetGuard GuardianPro firewall (NT4-based) Authentication Client',
	1503: 'Windows Live Messenger (Whiteboard and Application Sharing)',
	1512: 'Microsoft Windows Internet Name Service (WINS)',
	1521: 'nCube License Manager',
	1521: 'Oracle database default listener, in future releases official port 2483',
	1524: 'ingreslock, ingres',
	1526: 'Oracle database common alternative for listener',
	1533: 'IBM Sametime IM—Virtual Places Chat Microsoft SQL Server',
	1542: 'gridgen-elmd',
	1547: 'Laplink',
	1550: 'Gadu-Gadu (direct client-to-client)',
	1581: 'MIL STD 2045-47001 VMF',
	1589: 'Cisco VQP (VLAN Query Protocol) / VMPS',
	1645: 'radius, RADIUS authentication protocol (default for Cisco and Juniper Networks RADIUS servers)',
	1646: 'radacct, RADIUS accounting protocol (default for Cisco and Juniper Networks RADIUS servers)',
	1627: 'iSketch',
	1677: 'Novell GroupWise clients in client/server access mode',
	1701: 'Layer 2 Forwarding Protocol (L2F) & Layer 2 Tunneling Protocol (L2TP)',
	1716: 'America’s Army Massively multiplayer online role-playing game (MMORPG)',
	1720: 'h323hostcall',
	1723: 'Microsoft Point-to-Point Tunneling Protocol (PPTP)',
	1725: 'Valve Steam Client',
	1755: 'Microsoft Media Services (MMS, ms-streaming)',
	1761: 'cft-0',
	1761: 'Novell Zenworks Remote Control utility',
	1762: 'cft-1 to cft-7',
	1801: 'msmq',
	1812: 'radius, RADIUS authentication protocol',
	1813: 'radacct, RADIUS accounting protocol',
	1863: 'MSNP (Microsoft Notification Protocol), used by the .NET Messenger Service and a number of Instant Messaging clients',
	1900: 'Microsoft SSDP Enables discovery of UPnP devices',
	1920: 'IBM Tivoli Monitoring Console (https)',
	1935: 'Adobe Systems Macromedia Flash Real Time Messaging Protocol (RTMP) “plain” protocol',
	1970: 'Danware NetOp Remote Control',
	1971: 'Danware NetOp School',
	1972: 'InterSystems Caché',
	1975: 'Cisco TCO (Documentation)',
	1984: 'Big Brother—network monitoring tool',
	1985: 'Cisco HSRP',
	1994: 'Cisco STUN-SDLC (Serial Tunneling—Synchronous Data Link Control) protocol',
	1998: 'Cisco X.25 over TCP (XOT) service',
	2000: 'Cisco SCCP (Skinny)',
	2001: 'CAPTAN Test Stand System',
	2002: 'Secure Access Control Server (ACS) for Windows',
	2030: 'Oracle Services for Microsoft Transaction Server',
	2031: 'mobrien-chat—obsolete (ex-http://www.mobrien.com)',
	2041: 'Mail.Ru Agent communication protocol',
	2049: 'Network File System',
	2049: 'shilp',
	2053: 'lot105-ds-upd Lot105 DSuper Updates',
	2053: 'lot105-ds-upd Lot105 DSuper Updates',
	2053: 'knetd Kerberos de-multiplexor',
	2056: 'Civilization 4 multiplayer',
	2073: 'DataReel Database',
	2074: 'Vertel VMF SA (i.e. App.. SpeakFreely)',
	2082: 'Infowave Mobility Server',
	2082: 'CPanel default',
	2083: 'Secure Radius Service (radsec)',
	2083: 'CPanel default SSL',
	2086: 'GNUnet',
	2086: 'WebHost Manager default',
	2087: 'WebHost Manager default SSL',
	2095: 'CPanel default Web mail',
	2096: 'CPanel default SSL Web mail',
	2102: 'zephyr-srv Project Athena Zephyr Notification Service server',
	2103: 'zephyr-clt Project Athena Zephyr Notification Service serv-hm connection',
	2104: 'zephyr-hm Project Athena Zephyr Notification Service hostmanager',
	2105: 'IBM MiniPay',
	2105: 'eklogin Kerberos encrypted remote login (rlogin)',
	2105: 'zephyr-hm-srv Project Athena Zephyr Notification Service hm-serv connection (should use port 2102)',
	2107: 'msmq-mgmt',
	2144: 'Iron Mountain LiveVault Agent',
	2145: 'Iron Mountain LiveVault Agent',
	2161: 'APC Agent',
	2181: 'EForward-document transport system',
	2190: 'TiVoConnect Beacon',
	2200: 'Tuxanci game server[27]',
	2210: 'NOAAPORT Broadcast Network',
	2210: 'MikroTik Remote management for “The Dude”',
	2211: 'EMWIN',
	2211: 'MikroTik Secure management for “The Dude”',
	2212: 'LeeCO POS Server Service',
	2212: 'Port-A-Pour Remote WinBatch',
	2219: 'NetIQ NCAP Protocol',
	2220: 'NetIQ End2End',
	2222: 'DirectAdmin default',
	2222: 'Microsoft Office OS X antipiracy network monitor [1]',
	2301: 'HP System Management Redirect to port 2381',
	2302: 'ArmA multiplayer (default for game)',
	2302: 'Halo: Combat Evolved multiplayer',
	2303: 'ArmA multiplayer (default for server reporting) (default port for game +1)',
	2305: 'ArmA multiplayer (default for VoN) (default port for game +3)',
	2369: 'Default for BMC Software CONTROL-M/Server—Configuration Agent, though often changed during installation',
	2370: 'Default for BMC Software CONTROL-M/Server—to allow the CONTROL-M/Enterprise Manager to connect to the CONTROL-M/Server, though often changed during installation',
	2381: 'HP Insight Manager default for Web server',
	2401: 'CVS version control system',
	2404: 'IEC 60870-5-104, used to send electric powertelecontrol messages between two systems via directly connected data circuits',
	2420: 'Westell Remote Access',
	2427: 'Cisco MGCP',
	2447: 'ovwdb—OpenView Network Node Manager (NNM) daemon',
	2483: 'Oracle database listening for unsecure client connections to the listener, replaces port 1521',
	2484: 'Oracle database listening for SSL client connections to the listener',
	2546: 'EVault—Data Protection Services',
	2593: 'RunUO—Ultima Online server',
	2598: 'new ICA—when Session Reliability is enabled, TCP port 2598 replaces port 1494',
	2612: 'QPasa from MQSoftware',
	2700: 'KnowShowGo P2P',
	2710: 'XBT Bittorrent Tracker',
	2710: 'XBT Bittorrent Tracker experimental UDP tracker extension',
	2710: 'Knuddels.de',
	2735: 'NetIQ Monitor Console',
	2809: 'corbaloc:iiop URL, per the CORBA 3.0.3 specification',
	2809: 'IBM WebSphere Application Server (WAS) Bootstrap/rmi default',
	2809: 'corbaloc:iiop URL, per the CORBA 3.0.3 specification.',
	2944: 'Megaco Text H.248',
	2945: 'Megaco Binary (ASN.1) H.248',
	2948: 'WAP-push Multimedia Messaging Service (MMS)',
	2949: 'WAP-pushsecure Multimedia Messaging Service(MMS)',
	2967: 'Symantec AntiVirus Corporate Edition',
	3000: 'Miralix License server',
	3000: 'Distributed Interactive Simulation (DIS), modifiable default',
	3001: 'Miralix Phone Monitor',
	3002: 'Miralix CSTA',
	3003: 'Miralix GreenBox API',
	3004: 'Miralix InfoLink',
	3006: 'Miralix SMS Client Connector',
	3007: 'Miralix OM Server',
	3025: 'netpd.org',
	3030: 'NetPanzer',
	3050: 'gds_db (Interbase/Firebird)',
	3051: 'AMS (Agency Management System)',
	3074: 'Xbox LIVE and/or Games for Windows – LIVE',
	3128: 'HTTP used by Web caches and the default for the Squid cache',
	3225: 'FCIP (Fiber Channel over Internet Protocol)',
	3233: 'WhiskerControl research control protocol',
	3260: 'iSCSI target',
	3268: 'msft-gc, Microsoft Global Catalog (LDAP service which contains data from Active Directory forests)',
	3269: 'msft-gc-ssl, Microsoft Global Catalog over SSL(similar to port 3268, LDAP over SSL)',
	3283: 'Apple Remote Desktop reporting (officially Net Assistant, referring to an earlier product)',
	3300: 'TripleA game server',
	3305: 'odette-ftp, Odette File Transfer Protocol (OFTP)',
	3306: 'MySQL database system',
	3333: 'Network Caller ID server',
	3386: 'GTP’ 3GPP GSM/UMTS CDR logging protocol',
	3389: 'Microsoft Terminal Server (RDP) officially registered as Windows Based Terminal (WBT)',
	3396: 'Novell NDPS Printer Agent',
	3455: '[RSVP] Reservation Protocol',
	3423: 'Xware xTrm Communication Protocol',
	3424: 'Xware xTrm Communication Protocol over SSL',
	3483: 'Slim Devices discovery protocol',
	3483: 'Slim Devices SlimProto protocol',
	3544: 'Teredo tunneling',
	3632: 'distributed compiler',
	3689: 'Digital Audio Access Protocol (DAAP)—used by Apple’s iTunes and AirPort Express',
	3690: 'Subversion version control system',
	3702: 'Web Services Dynamic Discovery (WS-Discovery), used by various components of Windows Vista',
	3723: 'Used by many Battle.net Blizzard games (Diablo II, Warcraft II, Warcraft III, StarCraft)',
	3724: 'World of Warcraft Online gaming MMORPG',
	3724: 'Club Penguin Disney online game for kids',
	3784: 'Ventrilo VoIP program used by Ventrilo',
	3785: 'Ventrilo VoIP program used by Ventrilo',
	3868: 'Diameter base protocol (RFC 3588)',
	3872: 'Oracle Management Remote Agent',
	3899: 'Remote Administrator',
	3900: 'udt_os, IBM UniData UDT OS[28]',
	3945: 'EMCADS service, a Giritech product used by G/On',
	3978: 'OpenTTD game serverlist masterserver',
	3979: 'OpenTTD game',
	4000: 'Diablo II game',
	4007: 'PrintBuzzer printer monitoring socket server',
	4018: 'protocol information and warnings',
	4069: 'Minger Email Address Verification Protocol[29]',
	4089: 'OpenCORE Remote Control Service',
	4093: 'PxPlus Client server interface ProvideX',
	4096: 'Bridge-Relay Element ASCOM',
	4100: 'WatchGuard Authentication Applet—default',
	4111: 'Xgrid',
	4125: 'Microsoft Remote Web Workplace administration',
	4226: 'Aleph One (game)',
	4224: 'Cisco CDP Cisco discovery Protocol',
	4353: 'f5-iquery',
	4500: 'IPSec NAT Traversal (RFC 3947)',
	4534: 'Armagetron Advanced default server port',
	4569: 'Inter-Asterisk eXchange',
	4610: 'QualiSystems TestShell Suite Services',
	4662: 'OrbitNet Message Service',
	4662: 'often used by eMule',
	4664: 'Google Desktop Search',
	4664: 'Default for Unica’s Campaign Listener, though often changed during installation',
	4672: 'eMule—often used',
	4747: 'Apprentice',
	4750: 'BladeLogic Agent',
	4840: 'OPC UA TCP Protocol for OPC Unified Architecturefrom OPC Foundation',
	4843: 'OPC UA TCP Protocol over TLS/SSL for OPC Unified Architecture from OPC Foundation',
	4847: 'Web Fresh Communication, Quadrion Software & Odorless Entertainment',
	4993: 'Home FTP Server web Interface Default Port',
	4894: 'LysKOM Protocol A',
	4899: 'Radmin remote administration tool (program sometimes used by a Trojan horse)',
	5000: 'commplex-main',
	5000: 'UPnP—Windows network device interoperability',
	5000: 'VTun—VPN Software',
	5001: 'commplex-link',
	5001: 'Iperf (Tool for measuring TCP and UDP bandwidth performance)',
	5001: 'Slingbox and Slingplayer',
	5003: 'FileMaker',
	5004: 'RTP (Real-time Transport Protocol) media data (RFC 3551, RFC 4571)',
	5005: 'RTP (Real-time Transport Protocol) control protocol (RFC 3551, RFC 4571)',
	5031: 'AVM CAPI-over-TCP (ISDN over Ethernet tunneling)',
	5050: 'Yahoo! Messenger',
	5051: 'ita-agent Symantec Intruder Alert[30]',
	5060: 'Session Initiation Protocol (SIP)',
	5061: 'Session Initiation Protocol (SIP) over TLS',
	5093: 'SPSS (Statistical Package for the Social Sciences) License Administrator',
	5104: 'IBM Tivoli Framework NetCOOL/Impact[31] HTTPService',
	5106: 'A-Talk Common connection',
	5107: 'A-Talk Remote server connection',
	5110: 'ProRat Server',
	5121: 'Neverwinter Nights',
	5151: 'ESRI SDE Instance',
	5151: 'ESRI SDE Remote Start',
	5154: 'BZFlag',
	5176: 'ConsoleWorks default UI interface',
	5190: 'ICQ and AOL Instant Messenger',
	5222: 'Extensible Messaging and Presence Protocol (XMPP, Jabber) client connection (RFC 3920)',
	5223: 'Extensible Messaging and Presence Protocol (XMPP, Jabber) client connection over SSL',
	5269: 'Extensible Messaging and Presence Protocol (XMPP, Jabber) server connection (RFC 3920)',
	5298: 'Extensible Messaging and Presence Protocol (XMPP) link-local messaging',
	5351: 'NAT Port Mapping Protocol—client-requested configuration for inbound connections through network address translators',
	5353: 'Multicast DNS (MDNS)',
	5355: 'LLMNR—Link-Local Multicast Name Resolution, allows hosts to perform name resolution for hosts on the same local link (only provided by Windows Vistaand Server 2008)',
	5357: 'wsdapi',
	5402: 'mftp, Stratacache OmniCast content delivery system MFTP file sharing protocol',
	5405: 'NetSupport',
	5421: 'Net Support 2',
	5432: 'PostgreSQL database system',
	5445: 'Cisco Unified Video Advantage',
	5495: 'Applix TM1 Admin server',
	5498: 'Hotline tracker server connection',
	5499: 'Hotline tracker server discovery',
	5500: 'VNC remote desktop protocol—for incoming listening viewer, Hotline control connection',
	5501: 'Hotline file transfer connection',
	5504: 'fcp-cics-gw1',
	5517: 'Setiqueue Proxy server client for SETI@Homeproject',
	5555: 'Freeciv versions up to 2.0, Hewlett Packard Data Protector, SAP',
	5556: 'Freeciv',
	5560: 'isqlplus',
	5584: 'bis-web',
	5586: 'att-mt-sms',
	5631: 'pcANYWHEREdata, Symantec pcAnywhere (version 7.52 and later[32])[33] data',
	5632: 'pcANYWHEREstat, Symantec pcAnywhere (version 7.52 and later) status',
	5666: 'NRPE (Nagios)',
	5667: 'NSCA (Nagios)',
	5723: 'Operations Manager',
	5800: 'VNC remote desktop protocol—for use over HTTP',
	5814: 'Hewlett-Packard Support Automation (HP OpenView Self-Healing Services)',
	5850: 'COMIT SE (PCR)',
	5852: 'Adeona client: communications to OpenDHT',
	5900: 'Virtual Network Computing (VNC) remote desktop protocol (used by Apple Remote Desktop and others)',
	5938: 'TeamViewer[34] remote desktop protocol',
	5984: 'CouchDB database server',
	5985: 'wsman',
	5999: 'CVSup [35] file update tool',
	6000: 'X11—used between an X client and server over the network',
	6001: 'X11—used between an X client and server over the network',
	6005: 'Default for BMC Software CONTROL-M/Server—Socket used for communication between CONTROL-M processes—though often changed during installation',
	6005: 'Default for Camfrog Chat & Cam Client http://www.camfrog.com',
	6050: 'Brightstor Arcserve Backup',
	6050: 'Nortel Software',
	6051: 'Brightstor Arcserve Backup',
	6055: 'X11',
	6072: 'iOperator Protocol Signal Port',
	6086: 'PDTP—FTP like file server in a P2P network',
	6100: 'Vizrt System',
	6101: 'Backup Exec Agent Browser',
	6110: 'softcm, HP Softbench CM',
	6111: 'spc, HP Softbench Sub-Process Control',
	6112: '“dtspcd”—a network daemon that accepts requests from clients to execute commands and launch applications remotely',
	6112: 'Blizzard‘s Battle.net gaming service, ArenaNetgaming service',
	6112: 'Club Penguin Disney online game for kids',
	6113: 'Club Penguin Disney online game for kids',
	6129: 'DameWare Remote Control',
	6257: 'WinMX (see also 6699)',
	6346: 'gnutella-svc, Gnutella (FrostWire, Limewire, Shareaza, etc.)',
	6347: 'gnutella-rtr, Gnutella alternate',
	6389: 'EMC Clarrion',
	6444: 'Sun Grid Engine—Qmaster Service',
	6445: 'Sun Grid Engine—Execution Service',
	6502: 'Danware Data NetOp Remote Control',
	6522: 'Gobby (and other libobby-based software)',
	6543: 'Paradigm Research & Development Jetnet[36] default',
	6566: 'SANE (Scanner Access Now Easy)—SANE network scanner daemon',
	6571: 'Windows Live FolderShare client',
	6600: 'Music Playing Daemon (MPD)',
	6619: 'odette-ftps, Odette File Transfer Protocol (OFTP) over TLS/SSL',
	6646: 'McAfee Network Agent',
	6660: 'Internet Relay Chat',
	6665: 'Internet Relay Chat',
	6679: 'IRC SSL (Secure Internet Relay Chat)—often used',
	6697: 'IRC SSL (Secure Internet Relay Chat)—often used',
	6699: 'WinMX (see also 6257)',
	6771: 'Polycom server broadcast',
	6789: 'Datalogger Support Software Campbell Scientific Loggernet Software',
	6881: 'BitTorrent part of full range of ports used most often',
	6888: 'MUSE',
	6888: 'BitTorrent part of full range of ports used most often',
	6889: 'BitTorrent part of full range of ports used most often',
	6891: 'BitTorrent part of full range of ports used most often',
	6891: 'Windows Live Messenger (File transfer)',
	6901: 'Windows Live Messenger (Voice)',
	6901: 'BitTorrent part of full range of ports used most often',
	6902: 'BitTorrent part of full range of ports used most often',
	6969: 'acmsoda',
	6969: 'BitTorrent tracker',
	6970: 'BitTorrent part of full range of ports used most often',
	7000: 'Default for Vuze‘s built in HTTPS Bittorrent Tracker',
	7001: 'Default for BEA WebLogic Server‘s HTTP server, though often changed during installation',
	7002: 'Default for BEA WebLogic Server‘s HTTPS server, though often changed during installation',
	7005: 'Default for BMC Software CONTROL-M/Server and CONTROL-M/Agent for Agent-to-Server, though often changed during installation',
	7006: 'Default for BMC Software CONTROL-M/Server and CONTROL-M/Agent for Server-to-Agent, though often changed during installation',
	7009: 'afs3-rmtsys',
	7010: 'Default for Cisco AON AMC (AON Management Console) [2]',
	7025: 'Zimbra LMTP [mailbox]—local mail delivery',
	7047: 'Zimbra conversion server',
	7133: 'Enemy Territory: Quake Wars',
	7171: 'Tibia',
	7306: 'Zimbra mysql [mailbox]',
	7307: 'Zimbra mysql [logger]',
	7312: 'Sibelius License Server',
	7400: 'RTPS (Real Time Publish Subscribe) DDS Discovery',
	7401: 'RTPS (Real Time Publish Subscribe) DDS User-Traffic',
	7402: 'RTPS (Real Time Publish Subscribe) DDS Meta-Traffic',
	7670: 'BrettspielWelt BSW Boardgame Portal',
	7777: 'iChat server file transfer proxy',
	7777: 'Default used by Windows backdoor program tini.exe',
	7680: 'pando-pub',
	7831: 'Default used by Smartlaunch Internet Cafe Administration[37] software',
	7915: 'Default for YSFlight server [3]',
	7937: 'nsrexecd',
	7938: 'lgtomapper',
	8000: 'iRDMI (Intel Remote Desktop Management Interface)[38]—sometimes erroneously used instead of port 8080',
	8000: 'Commonly used for internet radio streams such as those using SHOUTcast',
	8002: 'Cisco Systems Unified Call Manager Intercluster',
	8008: 'HTTP Alternate',
	8008: 'IBM HTTP Server administration default',
	8010: 'XMPP/Jabber File transfers',
	8074: 'Gadu-Gadu',
	8080: 'HTTP alternate (http_alt)—commonly used for Web proxy and caching server, or for running a Web server as a non-root user',
	8080: 'Apache Tomcat',
	8080: 'FilePhile Master/Relay',
	8081: 'HTTP alternate, e.g. McAfee ePolicy Orchestrator (ePO)',
	8086: 'HELM Web Host Automation Windows Control Panel',
	8086: 'Kaspersky AV Control Center',
	8087: 'Hosting Accelerator Control Panel',
	8087: 'Kaspersky AV Control Center',
	8087: 'Parallels Plesk Control Panel',
	8090: 'HTTP Alternate (http_alt_alt)—used as an alternative to port 8080',
	8116: 'Check Point Cluster Control Protocol',
	8118: 'Privoxy—advertisement-filtering Web proxy',
	8123: 'Polipo Web proxy',
	8192: 'Sophos Remote Management System',
	8193: 'Sophos Remote Management System',
	8194: 'Sophos Remote Management System',
	8200: 'GoToMyPC',
	8220: 'Bloomberg',
	8222: 'VMware Server Management User Interface (insecure Web interface)[39]. See also port 8333',
	8243: 'HTTPS listener for Apache Synapse [40]',
	8280: 'HTTP listener for Apache Synapse [40]',
	8291: 'Winbox—Default on a MikroTik RouterOS for a Windows application used to administer MikroTik RouterOS',
	8294: 'Bloomberg',
	8333: 'VMware Server Management User Interface (secure Web interface)[39]. See also port 8222',
	8400: 'cvp, Commvault Unified Data Management',
	8443: 'SW Soft Plesk Control Panel, Apache Tomcat SSL',
	8484: 'MapleStory',
	8500: 'ColdFusion Macromedia/Adobe ColdFusion default and Duke Nukem 3D—default',
	8501: '[4] DukesterX —default',
	8701: 'SoftPerfect Bandwidth Manager',
	8702: 'SoftPerfect Bandwidth Manager',
	8767: 'TeamSpeak—default',
	8834: 'nessus-xmlrpc',
	8880: 'cddbp-alt, CD DataBase (CDDB) protocol (CDDBP) alternate',
	8880: 'cddbp-alt, CD DataBase (CDDB) protocol (CDDBP) alternate',
	8880: 'WebSphere Application Server SOAP connector default',
	8881: 'Atlasz Informatics Research Ltd Secure Application Server',
	8882: 'Atlasz Informatics Research Ltd Secure Application Server',
	8888: 'NewsEDGE server',
	8888: 'Sun Answerbook dwhttpd server (deprecated by docs.sun.com)',
	8888: 'GNUmp3d HTTP music streaming and Web interface',
	8888: 'LoLo Catcher HTTP Web interface (www.optiform.com)',
	8888: 'D2GS Admin Console Telnet administration console for D2GS servers (Diablo 2)',
	9000: 'Buffalo LinkSystem Web access',
	9000: 'DBGp',
	9000: 'SqueezeCenter web server & streaming',
	9000: 'UDPCast',
	9001: 'Microsoft Sharepoint Authoring Environment',
	9001: 'cisco-xremote router configuration',
	9001: 'Tor network default',
	9001: 'DBGp Proxy',
	9002: 'dynamid',
	9009: 'Pichat Server—Peer to peer chat software',
	9030: 'Tor often used',
	9043: 'WebSphere Application Server Administration Console secure',
	9050: 'Tor',
	9051: 'Tor',
	9060: 'WebSphere Application Server Administration Console',
	9080: 'glrpc, Groove Collaboration software GLRPC',
	9080: 'glrpc, Groove Collaboration software GLRPC',
	9080: 'WebSphere Application Server HTTP Transport (port 1) default',
	9090: 'Openfire Administration Console',
	9090: 'SqueezeCenter control (CLI)',
	9091: 'Openfire Administration Console (SSL Secured)',
	9100: 'PDL Data Stream',
	9101: 'Bacula Director',
	9102: 'Bacula File Daemon',
	9103: 'Bacula Storage Daemon',
	9110: 'SSMP Message protocol',
	9119: 'MXit Instant Messenger',
	9300: 'IBM Cognos 8 SOAP Business Intelligence and Performance Management',
	9418: 'git, Git pack transfer service',
	9443: 'WSO2 Web Services Application Server HTTPStransport (officially WSO2 Tungsten HTTPS',
	9443: 'WebSphere Application Server HTTP Transport (port 2) default',
	9535: 'mngsuite, LANDesk Management Suite Remote Control',
	9535: 'BBOS001, IBM Websphere Application Server (WAS) High Avail Mgr Com',
	9535: 'mngsuite, LANDesk Management Suite Remote Control',
	9800: 'WebDAV Source',
	9800: 'WebCT e-learning portal',
	9875: 'Club Penguin Disney online game for kids',
	9898: 'MonkeyCom',
	9898: 'Tripwire – File Integrity Monitoring Software',
	9999: 'Hydranode—edonkey2000 TELNET control',
	9999: 'Lantronix UDS-10/UDS100[41] RS-485 to Ethernet Converter TELNET control',
	9999: 'Urchin Web Analytics',
	10000: 'Webmin—Web-based Linux admin tool',
	10000: 'BackupExec',
	10000: 'Ericsson Account Manager (avim)',
	10001: 'Lantronix UDS-10/UDS100[42] RS-485 to Ethernet Converter default',
	10008: 'Octopus Multiplexer, primary port for the CROMP protocol, which provides a platform-independentmeans for communication of objects across a network',
	10017: 'AIX,NeXT, HPUX—rexd daemon control',
	10024: 'Zimbra smtp [mta]—to amavis from postfix',
	10025: 'Ximbra smtp [mta]—back to postfix from amavis',
	10050: 'Zabbix-Agent',
	10051: 'Zabbix-Trapper',
	10113: 'NetIQ Endpoint',
	10114: 'NetIQ Qcheck',
	10115: 'NetIQEndpoint',
	10116: 'NetIQ VoIP Assessor',
	10200: 'FRISK Software International‘s fpscand virus scanning daemon for Unix platforms [5]',
	10200: 'FRISK Software International‘s f-protd virus scanning daemon for Unix platforms [6]',
	10308: 'Lock-on: Modern Air Combat',
	10480: 'SWAT 4 Dedicated Server',
	11211: 'memcached',
	11235: 'Savage:Battle for Newerth Server Hosting',
	11294: 'Blood Quest Online Server',
	11371: 'OpenPGP HTTP key server',
	11576: 'IPStor Server management communication',
	12012: 'Audition Online Dance Battle, Korea Server – Status/Version Check',
	12013: 'Audition Online Dance Battle, Korea Server',
	12035: 'Linden Lab viewer to sim',
	12345: 'NetBus—remote administration tool (often Trojan horse). Also used by NetBuster. Little Fighter 2 (TCP).',
	12975: 'LogMeIn Hamachi (VPN tunnel software; also port 32976)—used to connect to Mediation Server (bibi.hamachi.cc); will attempt to use SSL (TCP port 443) if both 12975 & 32976 fail to connect',
	12998: 'Takenaka RDI Mirror World on SL',
	13000: 'Linden Lab viewer to sim',
	13076: 'Default for BMC Software CONTROL-M/Enterprise Manager Corba communication, though often changed during installation',
	13720: 'Symantec NetBackup—bprd (formerly VERITAS)',
	13721: 'Symantec NetBackup—bpdbm (formerly VERITAS)',
	13724: 'Symantec Network Utility—vnetd (formerly VERITAS)',
	13782: 'Symantec NetBackup—bpcd (formerly VERITAS)',
	13783: 'Symantec VOPIED protocol (formerly VERITAS)',
	13785: 'Symantec NetBackup Database—nbdb (formerly VERITAS)',
	13786: 'Symantec nomdb (formerly VERITAS)',
	14552: 'Lasso (programming language) application service',
	14567: 'Battlefield 1942 and mods',
	15000: 'psyBNC',
	15000: 'Wesnoth',
	15000: 'Kaspersky Network Agent',
	15000: 'hydap, Hypack Hydrographic Software Packages Data Acquisition',
	15000: 'hydap, Hypack Hydrographic Software Packages Data Acquisition',
	15567: 'Battlefield Vietnam and mods',
	15345: 'XPilot Contact',
	16000: 'shroudBNC',
	16080: 'Mac OS X Server Web (HTTP) service with performance cache[43]',
	16384: 'Iron Mountain Digital online backup',
	16567: 'Battlefield 2 and mods',
	18180: 'DART Reporting server',
	18200: 'Audition Online Dance Battle, AsiaSoft Thailand Server – Status/Version Check',
	18201: 'Audition Online Dance Battle, AsiaSoft Thailand Server',
	18206: 'Audition Online Dance Battle, AsiaSoft Thailand Server – FAM Database',
	18300: 'Audition Online Dance Battle, AsiaSoft SEA Server – Status/Version Check',
	18301: 'Audition Online Dance Battle, AsiaSoft SEA Server',
	18306: 'Audition Online Dance Battle, AsiaSoft SEA Server – FAM Database',
	18400: 'Audition Online Dance Battle, KAIZEN Brazil Server – Status/Version Check',
	18401: 'Audition Online Dance Battle, KAIZEN Brazil Server',
	18505: 'Audition Online Dance Battle, Nexon Server – Status/Version Check',
	18506: 'Audition Online Dance Battle, Nexon Server',
	18605: 'X-BEAT – Status/Version Check',
	18606: 'X-BEAT',
	19000: 'Audition Online Dance Battle, G10/alaplaya Server – Status/Version Check',
	19001: 'Audition Online Dance Battle, G10/alaplaya Server',
	19226: 'Panda Software AdminSecure Communication Agent',
	19638: 'Ensim Control Panel',
	19771: 'Softros LAN Messenger',
	19813: '4D database Client Server Communication',
	19880: 'Softros LAN Messenger',
	20000: 'DNP (Distributed Network Protocol), a protocol used in SCADA systems between communicating RTU‘s and IED‘s',
	20000: 'Usermin, Web-based user tool',
	20014: 'DART Reporting server',
	20720: 'Symantec i3 Web GUI server',
	22347: 'WibuKey, WIBU-SYSTEMS AG Software protectionsystem',
	22350: 'CodeMeter, WIBU-SYSTEMS AG Software protectionsystem',
	23073: 'Soldat Dedicated Server',
	23513: '[7] Duke Nukem Ports',
	24444: 'NetBeans integrated development environment',
	24465: 'Tonido Directory Server for Tonido which is a Personal Web app and peer-to-peer platform',
	24554: 'BINKP, Fidonet mail transfers over TCP/IP',
	24800: 'Synergy: keyboard/mouse sharing software',
	24842: 'StepMania: Online: Dance Dance RevolutionSimulator',
	25999: 'Xfire',
	26000: 'id Software‘s Quake server',
	26000: 'CCP‘s EVE Online Online gaming MMORPG',
	26900: 'CCP‘s EVE Online Online gaming MMORPG',
	26901: 'CCP‘s EVE Online Online gaming MMORPG',
	27000: '(through 27006) id Software‘s QuakeWorld master server',
	27000: 'VMWare‘s Licence server (from server being managed to management console))',
	27010: 'Half-Life and its mods, such as Counter-Strike',
	27010: 'VMWare‘s Licence server (from server being managed to management console))',
	27015: 'Half-Life and its mods, such as Counter-Strike',
	27374: 'Sub7 default. Most script kiddies do not change from this.',
	27500: '(through 27900) id Software‘s QuakeWorld',
	27888: 'Kaillera server',
	27900: '(through 27901) Nintendo Wi-Fi Connection',
	27901: '(through 27910) id Software‘s Quake II master server',
	27960: '(through 27969) Activision‘s Enemy Territory and id Software‘s Quake III Arena and Quake III and some ioquake3 derived games',
	28001: 'Starsiege: Tribes Common/default Tribes v.1 Server',
	28395: 'www.SmartSystemsLLC.com Used by Smart Sale® 5.0',
	28910: 'Nintendo Wi-Fi Connection',
	28960: 'Call of Duty 2 Common Call of Duty 2 (PC Version)',
	28961: 'Call of Duty 4: Modern Warfare Common Call of Duty 4 (PC Version)',
	29900: '(through 29901) Nintendo Wi-Fi Connection',
	29920: 'Nintendo Wi-Fi Connection',
	30000: 'Pokemon Netbattle',
	30301: 'BitTorrent',
	30564: 'Multiplicity: keyboard/mouse/clipboard sharing software',
	31337: 'Back Orifice—remote administration tool (often Trojan horse)',
	31415: 'ThoughtSignal—Server Communication Service (often Informational)',
	31456: 'TetriNET IRC gateway on some servers',
	31457: 'TetriNET',
	31458: 'TetriNET Used for game spectators',
	32245: 'MMTSG-mutualed over MMT (encrypted transmission)',
	32976: 'LogMeIn Hamachi (VPN tunnel software; also port 12975)—used to connect to Mediation Server (bibi.hamachi.cc); will attempt to use SSL (TCP port 443) if both 12975 & 32976 fail to connect',
	33434: 'traceroute',
	34443: 'Linksys PSUS4 print server',
	37777: 'Digital Video Recorder hardware',
	36963: 'Counter Strike 2D multiplayer (2D clone of popular CounterStrike computer game)',
	40000: 'SafetyNET p Real-time Industrial Ethernet protocol',
	43594: 'RuneScape',
	47808: 'BACnet Building Automation and Control Networks',
	49151: 'Reserved[1]'
}

service = ""

def enum_os(target):
	global dominio
	global sistema_operativo
	global servidor
	#Uses null session as opposed to username and password
	cmd = "smbclient //%s/IPC$ -U %s%%%s -t 1 -c exit" % (target, '', '')
	for line in getoutput(cmd).splitlines():
		if "Domain=" in line:
			result = line.split('] ')
			dominio = script_colors("c",result[0] +"]")
			sistema_operativo = script_colors("c",result[1] +"]")
			servidor = script_colors("c",result[2])
		elif "NT_STATUS_LOGON_FAILURE" in line:
			print script_colors("red","Authentication Failed")
		else:
			dominio = script_colors("c","Not found")
			sistema_operativo = script_colors("c","Not found")
			servidor = script_colors("c","Not found")



def check_host_online(direccion):
    if (platform.system()=="Windows"):
        ping = "ping -n 1"
    else :
        ping = "ping -c 1"

        response = os.popen(ping+" "+direccion)

        for line in response.readlines():
            if ("ttl" in line.lower()):
                return True


def script_colors(color_type, text):
    color_end = '\033[0m'

    if color_type.lower() == "r" or color_type.lower() == "red":
        red = '\033[91m'
        text = red + text + color_end
    elif color_type.lower() == "lgray":
        gray = '\033[2m'
        text = gray + text + color_end
    elif color_type.lower() == "gray":
        gray = '\033[90m'
        text = gray + text + color_end
    elif color_type.lower() == "strike":
        strike = '\033[9m'
        text = strike + text + color_end
    elif color_type.lower() == "underline":
        underline = '\033[4m'
        text = underline + text + color_end
    elif color_type.lower() == "b" or color_type.lower() == "blue":
        blue = '\033[94m'
        text = blue + text + color_end
    elif color_type.lower() == "g" or color_type.lower() == "green":
        green = '\033[92m'
        text = green + text + color_end
    elif color_type.lower() == "y" or color_type.lower() == "yellow":
        yellow = '\033[93m'
        text = yellow + text + color_end
    elif color_type.lower() == "c" or color_type.lower() == "cyan":
        cyan = '\033[96m'
        text = cyan + text + color_end
    elif color_type.lower() == "cf" or color_type.lower() == "cafe":
        cafe = '\033[52m'
        text = cafe + text + color_end
    else:
        return text
    return  text


def banner_welcome():
    banner = '''
		███████╗ █████╗ ███╗   ███╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
		██╔════╝██╔══██╗████╗ ████║██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
		███████╗███████║██╔████╔██║██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
		╚════██║██╔══██║██║╚██╔╝██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
		███████║██║  ██║██║ ╚═╝ ██║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
		╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
		                                                                version: 1.5
		                                                Autor: Samir Sanchez Garnica
		                                                                   @sasaga92
                                                                     
    '''
    return script_colors('lgray',banner)





def escanear_banner(direccion, puertos):
    from socket import *
    tiempo_inicial = time()
    informacion = []
    service =""
    try:
        host = gethostbyname(direccion)
    except:
        print script_colors("red","[-] ") + script_colors("c", "no se reconoce el host")
        exit(1)
    if not check_host_online(host):
        print script_colors("red","[-] ") + script_colors("c", "este host no esta en linea :(")
        exit(1)
    print script_colors("g", "[+] ") + script_colors("c", "Iniciando escaner para: ") + script_colors("red",host) + script_colors("red"," domain: ") + dominio + script_colors("red"," OS: ") + sistema_operativo + script_colors("red"," server: ") + servidor
    print script_colors("yellow", "PUERTO.                 ESTADO.                         SERVICIO")

    for puerto in puertos:

        try:
            conexion  = socket(AF_INET, SOCK_STREAM)
            try:
                p = int(puerto)
            except:
                print script_colors("red","[-] ") + script_colors("c", "algo salio mal con algun puerto")
                return
            conexion.connect((host,p))
            service = conexion.recv(1024)

            conexion.close()
            informacion.append([puerto, "abierto",str(service).rstrip('\n')])
        except:
        	conexion.close()
        	informacion.append([puerto, "cerrado",service])

    for i in informacion:
        if i[2] == "":
            i[2] = script_colors("red","no encontrado")
        x=int((30-len(i[0]))/8)
        print script_colors("blue","%s"%i[0]),
        for y in range(x):
            print "\t",
        if i[1] == "cerrado":
            i[1] = script_colors("red","cerrado")
            i[2] = script_colors("red","no existe")
        else:
            i[1] = script_colors("g","abierto")
        print i[1],
        for y in range(x):
            print "\t",
        print i[2]

    tiempo_final = time()
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    print script_colors("lgray","Escaneo realizado en: ") + script_colors("c", str(int(tiempo_ejecucion))) + script_colors("lgray"," Segundos")




def escanear(direccion, puertos):
    from socket import *
    tiempo_inicial = time()
    informacion = []
    service =""
    try:
        host = gethostbyname(direccion)
    except:
        print script_colors("red","[-] ") + script_colors("c", "no se reconoce el host")
        exit(1)
    if not check_host_online(host):
        print script_colors("red","[-] ") + script_colors("c", "este host no esta en linea :(")
        exit(1)
    print script_colors("g", "[+] ") + script_colors("c", "Iniciando escaner para: ") + script_colors("red",host) + script_colors("red"," domain: ") + dominio + script_colors("red"," OS: ") + sistema_operativo + script_colors("red"," server: ") + servidor
    print script_colors("yellow", "PUERTO.                 ESTADO.                         SERVICIO")

    for puerto in puertos:

        try:
            conexion  = socket(AF_INET, SOCK_STREAM)
            try:
                p = int(puerto)
            except:
                print script_colors("red","[-] ") + script_colors("c", "algo salio mal con algun puerto")
                return
            conexion.connect((host,p))
            #service = conexion.recv(1024)

            if int(puerto) in common_ports:
            	service = common_ports[int(puerto)]
            else:
            	service = ""

            conexion.close()
            informacion.append([puerto, "abierto",service])
        except:
        	conexion.close()
        	informacion.append([puerto, "cerrado",service])

    for i in informacion:
        if i[2] == "":
            i[2] = script_colors("red","no encontrado")
        x=int((30-len(i[0]))/8)
        print script_colors("blue","%s"%i[0]),
        for y in range(x):
            print "\t",
        if i[1] == "cerrado":
            i[1] = script_colors("red","cerrado")
            i[2] = script_colors("red","no existe")
        else:
            i[1] = script_colors("g","abierto")
        print i[1],
        for y in range(x):
            print "\t",
        print i[2]

    tiempo_final = time()
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    print script_colors("lgray","Escaneo realizado en: ") + script_colors("c", str(int(tiempo_ejecucion))) + script_colors("lgray"," Segundos")



def scan_range_banner(port):

    try:
    	ip = ip_host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((ip, port))
        service = sock.recv(1024)

        if len(service) > 0:
        	
        	x=int((30-len(str(port)))/8)
        	print script_colors("lgray", str(port)),

        	for y in range(x):
        		print "\t",
        	print script_colors("g","abierto"),
        	for y in range(x):
        		print "\t",
        	print script_colors("lgray",str(service).rstrip('\n'))
        sock.close()

    except socket.gaierror:
        print script_colors("red","host imposible de resolver")
        sys.exit()

    except socket.error:
        pass


def scan_range(port):

    try:
    	ip = ip_host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
        	if int(port) in common_ports:
        		service = common_ports[int(port)]
        	else:
        		service = script_colors("red","desconocido")
        	
        	x=int((30-len(str(port)))/8)
        	print script_colors("lgray", str(port)),

        	for y in range(x):
        		print "\t",
        	print script_colors("g","abierto"),
        	for y in range(x):
        		print "\t",
        	print script_colors("lgray",service)
        sock.close()

    except socket.gaierror:
        print script_colors("red","host imposible de resolver")
        sys.exit()

    except socket.error:
        print script_colors("red","imposible conectar al host remoto")
        sys.exit()

def main():
    print banner_welcome()
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", dest="host", help="Introducir host a escanear", required=True)
    parser.add_argument("--port", dest="puertos", help="puerto o lista de puertos separada por ,", required=False)
    parser.add_argument("--range", dest="range_ports", help="rango de puertos separados por - ,", required=False)
    parser.add_argument('--banner', dest='banner', action='store_true',help='Extrae el banner grabbing de un puerto')

    args = parser.parse_args()
    host = args.host
    listaPuertos = str(args.puertos).split(",")
    range_port = str(args.range_ports).split("-")

    enum_os(host)
    global ip_host 	
    ip_host = host

    if args.host and args.puertos and args.banner:
    	escanear_banner(host,listaPuertos)
    elif args.host and args.puertos:
    	escanear(host,listaPuertos)
    elif args.host and args.range_ports and args.banner:
    	if not check_host_online(host):
    		print script_colors("red","[-] ") + script_colors("c", "este host no esta en linea :(")
    		exit(1)   
    	ip_host = host
    	print script_colors("g", "[+] ") + script_colors("c", "Iniciando escaner para: ") + script_colors("red",host) + script_colors("red"," domain: ") + dominio + script_colors("red"," OS: ") + sistema_operativo + script_colors("red"," server: ") + servidor
    	print script_colors("yellow", "PUERTO.                 ESTADO.                         SERVICIO")
    	p = Pool(50)
    	tiempo_inicial = time()
    	salida = p.map(scan_range_banner, range(int(range_port[0]), int(range_port[1])))
    	tiempo_final = time()
    	tiempo_ejecucion = tiempo_final - tiempo_inicial
    	print script_colors("lgray","Escaneo realizado en: ") + script_colors("c", str(int(tiempo_ejecucion))) + script_colors("lgray"," Segundos")
    elif args.host and args.range_ports:
    	if not check_host_online(host):
    		print script_colors("red","[-] ") + script_colors("c", "este host no esta en linea :(")
    		exit(1)   
    	print script_colors("g", "[+] ") + script_colors("c", "Iniciando escaner para: ") + script_colors("red",host) + script_colors("red"," domain: ") + dominio + script_colors("red"," OS: ") + sistema_operativo + script_colors("red"," server: ") + servidor
    	print script_colors("yellow", "PUERTO.                 ESTADO.                         SERVICIO")
    	p = Pool(50)
    	tiempo_inicial = time()
    	salida = p.map(scan_range, range(int(range_port[0]), int(range_port[1])))
    	tiempo_final = time()
    	tiempo_ejecucion = tiempo_final - tiempo_inicial
    	print script_colors("lgray","Escaneo realizado en: ") + script_colors("c", str(int(tiempo_ejecucion))) + script_colors("lgray"," Segundos")
    else:
        print script_colors("yellow","[-] ") + script_colors("c", "Requiere parametros --host host --port puerto/s o --range ")
        exit(0)

if __name__ == '__main__':
    main()  
