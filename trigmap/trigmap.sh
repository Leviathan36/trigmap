#!/bin/bash



# trigmap    -    a wrapper for Nmap
# Copyright © 2019 Leviathan36 

# trigmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# trigmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with trigmap.  If not, see <http://www.gnu.org/licenses/>.




##############################################
###             PARAMETERS                 ###  
##############################################
GENERAL_USER_LIST='general_user_wordlist_short.txt'         #   <<
WIN_USER_LIST='win_user_wordlist_short.txt'                 #  <<<
UNIX_USER_LIST='unix_user_wordlist_short.txt'               # <=============
SHORT_PASS_LIST='fasttrack.txt'                             #<======= CHANGE THESE TO CUSTOMIZE YOUR SCRIPT
LONG_PASS_LIST='passwords.lst'                              # <=============
                                                            #  <<<
##############################################              #   <<
###             NMAP SETTING               ###  
##############################################

# PE (echo req), PP (timestamp-request) 
# you can add a port on every ping scan
NMAP_PING='-PE -PS80,443,22,25,110,445 -PU -PP -PA80,443,22,25,110,445' #   <<
                                                                        #  <<<
NMAP_OTHER='-sV --allports -O --fuzzy --min-hostgroup 256'              # <=============
                                                                        #<======= CHANGE THESE TO CUSTOMIZE YOUR SCRIPT
SCRIPT_VA='(auth or vuln or exploit or http-* and not dos)'             # <=============
                                                                        #  <<<
SCRIPT_BRUTE='(auth or vuln or exploit or http-* or brute and not dos)' #   <<

SCRIPT_ARGS="userdb=$GENERAL_USER_LIST,passdb=$SHORT_PASS_LIST"

CUSTOM_SCAN='--max-retries 3 --min-rate 250'    # LIKE UNICORNSCAN


##############################################
###             FUNCTIONS                  ###  
##############################################

# print functions
print_start_end () {
    printf "\033[36;1m[*******************************************************]\033[0m\n"
    printf "\033[36;1m[ $1  ]\033[0m\n"
    printf "\033[36;1m[*******************************************************]\033[0m\n"
}

print_std () {
    printf "\033[34;1m[*]$1\033[0m\n"
}

print_failure () {
    printf "\033[35;1m[-]$1\033[0m\n"
}

print_succ () {
    printf "\033[32;1m[+]$1\033[0m\n"
}

print_progress () {
    TIME='0'
    while true; do
        printf "\rWORKING TIME: $TIME minutes  ["
        for ((i=0;i<10;i++)); do
            printf "="
            sleep 6
        done
        ((TIME++))
    done
}
    
    

# print help
print_help () {
    echo 'Usage:'
    echo '  Interactive mode:'
    echo '      trigmap [ENTER]  ...and the script does the rest'
    echo
    echo '  NON-interactive mode:'
    echo '      trigmap -h|--host <target/s> [-tp|--tcp TCP ports] [-up|--udp UDP ports] [-f|--file file path] [-s|--speed time profile] [-n|--nic NIC] [-p|--phase phases]'
    echo 
    echo '      phases:'
    echo '          - i == information gathering'
    echo '          - v == vulnerability assessment'
    echo '          - d == dictionary attack against open services'
    echo
    echo '      example: iv == information gathering + vulnerability assessment'
    echo '      dafult: ALL (ivb)'
    echo
    echo '      trigmap --help to print this helper'
    echo
}

# sanitize input parameters
sanitize_input () {
        
    # interactive mode
    if [[ "$#" == 0 ]]; then    
        printf "insert host (nmap syntax):\n>> "
        read HOST
        
        printf "insert the range of TCP ports to scan (default top 1000):\n>> "
        read TCP_PORTS
        
        printf "insert the range of UDP ports to scan (default top 200):\n>> "
        read UDP_PORTS
        
        
        echo 'choose the time profile:'
        echo '  0. paranoid (-T 0)'
        echo '  1. sneaky (-T 1)'
        echo '  2. polite (-T 2)'
        echo '  3. normal (-T 3)'
        echo '  4. aggressive (-T 4)'
        echo '  5. insane (-T 5)'
        echo '  6. custom scan (CUSTOM_SCAN)'
        read -p '>> ' TIME_PROFILE_CHOICE
        
        printf "insert NIC:\n>> "
        read NIC

        printf "insert path where to save results (without final /):\n>> "
        read FILE_PATH
        
        echo 'choose the phases to perform (default ivd):'
        echo '  - Information Gathering (i)'
        echo '  - Vulnerability Assessment (v)'
        echo '  - Dictionary Attack (d)' 
        read -p '>> ' PHASE
        while [[ ! "$PHASE" == '' && ! "$PHASE" =~ ['ivd'] ]]; do
            printf "INVALID PARAMETER\nchoose the phases to perform:\n>> "
            read PHASE
        done
        
        printf "shutdown pc at the end of script [YES/NO] (default NO):\n>> "
        read SHUTDOWN
        
    else
        
        while [[ ! "$#" == 0 ]]; do
          case "$1" in
            --help ) print_help; exit 0;;
            -h | --host ) HOST="$2"; shift 2;;
            -tp | --tcp )    TCP_PORTS="$2"; shift 2;;
            -up | --udp ) UDP_PORTS="$2"; shift 2;;
            -f | --file ) FILE_PATH="$2"; shift 2;;
            -s | --speed ) TIME_PROFILE_CHOICE="$2"; shift 2;;
            -n | --nic )    NIC="$2"; shift 2;;
            -p | --phase ) PHASE="$2"; shift 2;;
            * ) print_failure "INVALID PARAMETERS!"; print_help; exit 0;;
          esac
        done
     
    fi
    
    
    # check input
    if [[ ! "$HOST" =~ ['1234567890./,'] && ! "$HOST" == 'localhost' ]]; then 
        echo "$HOST : THE TARGET IP CONTAINS INVALID CHARACTERS"
        exit 1
    fi
    
    if [[ ! "$TCP_PORTS" == '' && ! "$TCP_PORTS" == '-' && ! "$TCP_PORTS" =~ ['1234567890,'] ]]; then 
        echo "$TCP_PORTS : THE TCP PORTS PARAMETER CONTAINS INVALID CHARACTERS"
        exit 2
    fi
    
    if [[ ! "$UDP_PORTS" == '' && ! "$UDP_PORTS" == '-' && ! "$UDP_PORTS" =~ ['1234567890,'] ]]; then 
        echo "$UDP_PORTS : THE UDP PORTS PARAMETER CONTAINS INVALID CHARACTERS"
        exit 3
    fi
    
    if [[ ! "$TIME_PROFILE_CHOICE" =~ ['123456'] && ! "$TIME_PROFILE_CHOICE" == '' ]]; then 
        echo "$TIME_PROFILE_CHOICE : THE TIME PROFILE PARAMETER CONTAINS INVALID CHARACTERS"
        exit 4
    fi
    
    if [[ ! "$NIC" == '' ]]; then
        ifconfig "$NIC" &> /dev/null || { echo "$NIC : DEVICE NOT FOUND"; exit 5; }
    fi
    
    if [[ "$FILE_PATH" == '' ]]; then
        FILE_PATH="$(pwd)"
    elif [[ ! -d "$FILE_PATH" ]]; then 
        echo "$FILE_PATH : DIRECTORY NOT FOUND"
        exit 6
    fi
    
    if [[ "$PHASE" == '' ]]; then
        PHASE='ivd'
    fi

fi
    
}

# build nmap parameters
make_nmap_parameters () {
    
    # HOST
    NMAP_HOST="$HOST"
    
    # TCP
    if [[ "$TCP_PORTS" == '' ]]; then
        NMAP_TCP_PORTS='--top-ports 1000'
    elif [[ $(cut -d' ' -f1 <<< $TCP_PORTS) == '--top-ports' ]]; then
        NMAP_TCP_PORTS="$TCP_PORTS"
    else
        NMAP_TCP_PORTS="-p $TCP_PORTS"
    fi
    
    # UDP
    if [[ "$UDP_PORTS" == '' ]]; then
        NMAP_UDP_PORTS='--top-ports 200'
    elif [[ $(cut -d' ' -f1 <<< $UDP_PORTS) == '--top-ports' ]]; then
        NMAP_UDP_PORTS="$UDP_PORTS"
    else
        NMAP_UDP_PORTS="-p $UDP_PORTS"
    fi
    
    # TIME
    if [[ "$TIME_PROFILE_CHOICE" == '' ]]; then
        NMAP_TIME_PROFILE=''
    elif [[ "$TIME_PROFILE_CHOICE" == '6' ]]; then
        NMAP_TIME_PROFILE="$CUSTOM_SCAN"
    else
        NMAP_TIME_PROFILE="-T$TIME_PROFILE_CHOICE"
    fi
    
    # NIC
    if [[ "$NIC" == '' ]]; then
        NMAP_NIC=''
    else 
        NMAP_NIC="-e $NIC"
    fi
    
    # PATH
    mkdir -p "$FILE_PATH/$HOST"
    FILE_PATH="$FILE_PATH/$HOST"
    
    # FILES 
    SYN_FILE_NAME='script-syn'
    UDP_FILE_NAME='script-udp'
    NMAP_SYN_FILE_PATH="-oA $FILE_PATH/$SYN_FILE_NAME"
    NMAP_UDP_FILE_PATH="-oA $FILE_PATH/$UDP_FILE_NAME"
    
    # PHASE
    case "$PHASE" in
        'i')
            NMAP_SCRIPT=''
            ;;
        'v')
            NMAP_SCRIPT="$SCRIPT_VA"
            ;;
        *)
            NMAP_SCRIPT="$SCRIPT_BRUTE"
            ;;
    esac
    
    # SCRIPT ARGS
    NMAP_SCRIPT_ARGS="$SCRIPT_ARGS"

}
    

# the function which calls nmap script
#
#$1 == ping scan
#$2 == scan
#$3 == ports
#$4 == other
#$5 == path
#$6 == script
#$7 == script_args
#$8 == interface
#$9 == time profile
#$10 == hosts
#
nmap_cmd () {
    print_progress &
    PRINT_PROGRESS_PID="$!"
    PARAMETERS="$1 $2 $3 $4 $5 $8 $9"   # EXCEPT $6, $7, $10 : script (string), script-args (string), host (last)
    read -a array <<< "$PARAMETERS"
    #echo "${array[@]}" --script "$6" --script-args "$7" "${10}"    #debug
    nmap "${array[@]}" --script "$6" --script-args "$7" "${10}" &> /dev/null || { print_failure "NMAP: exit with error code $?"; kill "$PRINT_PROGRESS_PID" &> /dev/null; exit 99; }
    kill "$PRINT_PROGRESS_PID" &> /dev/null
    echo
}

# parser for syn-scan
#
# $1 == FILE_TCP
# $2 == PATH
#
parser_tcp () {
    NEW_FILE='/dev/null'
    while read line; do
        if grep -q 'Nmap scan report' <<< "$line"; then
            # parsing old files
            if [[ ! "$NEW_FILE" == '/dev/null' ]]; then
                grep -v '|' "$NEW_FILE-script" > "$NEW_FILE-syn"
            fi
            # creating new dir and files
            NEW_HOST="$(cut -f5 -d' ' <<< "$line")"
            mkdir -p "$2/$NEW_HOST"
            NEW_FILE="$2/$NEW_HOST/$NEW_HOST"
            print_std "new directory:   $2/$NEW_HOST/"
            # filling the first line of new file
            echo "$line" > "$NEW_FILE-script"
        else
            # filling the others lines of new file
            echo "$line" >> "$NEW_FILE-script"
            # password found!
            grep -q -e '- Valid credentials' <<< "$line" && { print_succ "PASSWORD FOUND    $line"; echo "$line" >> "$NEW_FILE-passwords"; }
        fi
    done < "$2/$1.nmap"
    # parsing the last file
    grep -v '|' "$NEW_FILE-script" > "$NEW_FILE-syn"
}


# parser for udp-scan
#
# $1 == FILE_UDP
# $2 == PATH
#
parser_udp () {
    NEW_FILE='/dev/null'
    while read line; do
        if grep -q 'Nmap scan report' <<< "$line"; then
            # creating new dir and files
            NEW_HOST="$(cut -f5 -d' ' <<< "$line")"
            mkdir -p "$2/$NEW_HOST"
            NEW_FILE="$2/$NEW_HOST/$NEW_HOST"
            #print_std "new directory: $2/$NEW_HOST/"
            # filling the first line of new file
            echo "$line" > "$NEW_FILE-udp"
        else
            # filling the others lines of new file
            echo "$line" >> "$NEW_FILE-udp"
        fi
    done < "$2/$1.nmap"
}



##############################################
###             MAIN                       ###  
##############################################

# take the parameters
sanitize_input "$@"

# make nmap parameters
make_nmap_parameters

# start script
print_start_end "START SCRIPT AT `date`"

# syn-scan
print_std 'start syn-scan...'
nmap_cmd "$NMAP_PING" '-sS' "$NMAP_TCP_PORTS" "$NMAP_OTHER" "$NMAP_SYN_FILE_PATH" "$NMAP_SCRIPT" "$NMAP_SCRIPT_ARGS" "$NMAP_NIC" "$NMAP_TIME_PROFILE" "$NMAP_HOST"

# udp-scan
print_std 'start udp-scan...';
nmap_cmd "$NMAP_PING" '-sU' "$NMAP_UDP_PORTS" "$NMAP_OTHER" "$NMAP_UDP_FILE_PATH" "$NMAP_SCRIPT" "$NMAP_SCRIPT_ARGS" "$NMAP_NIC" "$NMAP_TIME_PROFILE" "$NMAP_HOST"

# parsing
parser_tcp "$SYN_FILE_NAME" "$FILE_PATH"
parser_udp "$UDP_FILE_NAME" "$FILE_PATH"

# end of script
print_start_end "END SCRIPT AT `date`"

# shutdown
if [[ "$shutdown" == 'YES' || "$shutdown" == 'yes'  ]]; then 
    print_std 'shutdown system...'
    sleep 2
    shutdown now
fi



###########     END OF SCRIPT   ##############
##############################################
