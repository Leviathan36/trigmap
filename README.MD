![Release](https://img.shields.io/badge/release-beta-yellow.svg)
![Language](https://img.shields.io/badge/made%20with-bash-brightgreen.svg)
![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
![LastUpdate](https://img.shields.io/badge/last%20update-2019%2F05-orange.svg)
![TestedOn](https://img.shields.io/badge/tested%20on-Kali%20Linux-red.svg)

<br>
<br>
<br>

<p align="center"><img src="https://github.com/Leviathan36/trigmap/blob/master/trigmap_images/trigmap_logo.png" width="90%" height="auto"></p>

## About
Trigmap is a wrapper for Nmap.
You can use it to easily start Nmap scan and especially to collect informations into a well
organized directory hierarchy.
The use of Nmap makes the script **portable** (easy to run not only on Kali Linux)
and very **efficient** thanks to the optimized Nmap algorithms.

## Details
Trigmap can performs several tasks using Nmap scripting engine (NSE):

   * **_Port Scan_**
   * **_Service and Version Detection_**
   * **_Web Resources Enumeration_**
   * **_Vulnerability Assessment_**
   * **_Common Vulnerabilities Test_**
   * **_Common Exploits Test_**
   * **_Dictionary Attacks Against Active Services_**
   * **_Default Credentials Test_**

## Usage
Trigmap can be used in two ways:

   * Interactive mode:

   `trigmap [ENTER], and the script does the rest`

<p align="center"><img src="https://github.com/Leviathan36/trigmap/blob/master/trigmap_images/screenshots/interactive_mode.png" width="80%" height="auto"></p>

   * NON-interactive mode:

   `trigmap -h|--host <target/s> [-tp|--tcp TCP ports] [-up|--udp UDP ports] [-f|--file file path] [-s|--speed time profile] [-n|--nic NIC] [-p|--phase phases]`

<br>

**If you want to see the help:**
<br>

   `trigmap --help to print this helper`

<br>

_**For more screenshots see the relative [directory](https://github.com/Leviathan36/trigmap/tree/master/trigmap_images/screenshots) of the repository.**_

## Dir Hierarchy
<p align="center"><img src="https://github.com/Leviathan36/trigmap/blob/master/trigmap_images/dir_hierarchy.PNG" width="80%" height="auto"></p>

## Customization
It's possible to customize the script by changing the value of variables at the beginning of the file.
In particularly you can choose the wordlists used by the Nmap scripts and the most important Nmap scan parameters (ping, scan, timing and script).

```bash
##############################################
###				PARAMETERS				   ###
##############################################
GENERAL_USER_LIST='general_user_wordlist_short.txt'
WIN_USER_LIST='win_user_wordlist_short.txt'
UNIX_USER_LIST='unix_user_wordlist_short.txt'
SHORT_PASS_LIST='fasttrack.txt'
LONG_PASS_LIST='rockyou.txt'

##############################################
###				NMAP SETTING			   ###
##############################################

# PE (echo req), PP (timestamp-request)
# you can add a port on every ping scan
NMAP_PING='-PE -PS80,443,22,25,110,445 -PU -PP -PA80,443,22,25,110,445'

NMAP_OTHER='-sV --allports -O --fuzzy --min-hostgroup 256'

SCRIPT_VA='(auth or vuln or exploit or http-* and not dos)'

SCRIPT_BRUTE='(auth or vuln or exploit or http-* or brute and not dos)'

SCRIPT_ARGS="userdb=$GENERAL_USER_LIST,passdb=$SHORT_PASS_LIST"

CUSTOM_SCAN='--max-retries 3 --min-rate 250'	# LIKE UNICORNSCAN
```

## Twin Brother
This project is very similar to [Kaboom](https://github.com/Leviathan36/kaboom), but it has a different philosophy; infact, it uses only Nmap, while Kaboom uses different tools, one for each task.
The peculiarity of Trigmap is the **portability** and the **efficient**, but it's recommended to use both the tools to
scan the targets in a such way to gather more evidence with different tools (_redundancy_ and _reliability_).

<br>
<br>

-------------------------------------
## Disclaimer:
Author assume no liability and are not responsible for any misuse or damage caused by this program.

Trigmap is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

## License:
Trigmap is released under GPLv3 license. See [LICENSE](LICENSE) for more details.
