# enumHostLinux
#
# script to run a serie of active enumeration probes on a linux host to spot potential security weaknesses
# designed to require no user interaction, to have as few binary dependencies as possible and to be legacy-tolerant
#
# output format is flat json to allow for easy parsing by vulnerability management tools and CTF scripts
# although web browsers are quite decent at presenting json content, additional html output can be requested by the command-line argument "-e"
#
# largely inspired by Rebootuser's "LinEnum" (https://github.com/rebootuser/LinEnum)
#
# do not actively enumerate systems without obtaining previous, written and adequate permission from their legitimate owners (https://www.sans.org/reading-room/whitepapers/testing/paper/259)

#!/bin/bash
set -u

# constants
SCRIPT_VERSION='0.1.0'

# variables setable via command-line arguments
enum_probes_cat=1               # category of the probes to be run (0: no probes, 1: fast probes, 2: medium probes, 3: slow probes)
enum_sudo_pwd='12345678'        # user password to allow sudo scripts (security warning: password will most probably persist in the shell history)
enum_dir_tmp='/tmp'             # directory to store the probe's temporary results (default: '/tmp')
enum_dir_out='.'                # directory to store the enumeration output (default: '.')
enum_prefix_out='enumHostLinux' # prefix of the final report's file name (timestamp and extension are added automatically)
enum_export_fmt=''              # format of requested additional output (only 'html' is currently available)
enum_tags_custom='null'         # string of arbitrary tags for identification and automated parsing (default: json 'null' value)

# internal variables
enum_tmp=''    # generic temporary storage (e.g. to hide the sudo password)
enum_stdout='' # temporary storage of the probe's stdout
enum_stderr='' # temporary storage of the probe's stderr
enum_report='' # full path of the final report file: $enum_dir_out/$enum_prefix_out.$(date +%s).json

# - - - helper functions - - -

# function to set variables according to the provided command-line arguments
# expected arguments: $1 as array of command-line arguments provided to the script
function initialise() {
	while [ $# -gt 0 ]
	do
		case "$1" in
			-c|--category) enum_probes_cat="${2-}"; shift ;;
			-s|--sudo) enum_sudo_pwd="${2-}"; shift ;;
			-t|--temporary) enum_dir_tmp="${2-}"; shift ;;
			-d|--directory) enum_dir_out="${2-}"; shift ;;
			-p|--prefix) enum_prefix_out="${2-}"; shift ;;
			-e|--export) enum_export_fmt="${2-}"; shift ;;
			-t|--tags) enum_tags_custom="${2-}"; shift ;;
			-v|--version) echo "$SCRIPT_VERSION" 2>/dev/null; exit 0 ;;
			-h|--help)
				echo 'script: enumHostLinux'
				echo 'usage:' 2>/dev/null
				echo '    -c|--category <n>: category of probes to be run' 2>/dev/null
				echo '        0: no probes (dry-run), 1: fast probes (default), 2: medium probes, 3: slow probes' 2>/dev/null
				echo '    -s|--sudo <xxx>: user password to allow sudo scripts (security warning: password will most probably persist in the shell history)' 2>/dev/null
				echo "    -t|--temporary <xxx>: directory to store the probe's temporary results (default: '/tmp')" 2>/dev/null
				echo '    -d|--directory <xxx>: directory to store the enumeration output (default: '.')' 2>/dev/null
				echo "    -p|--prefix <xxx>: prefix of the final report's file name (timestamp and extension are added automatically)" 2>/dev/null
				echo "    -e|--export <xxx>: format of requested additional output (only 'html' is currently available)" 2>/dev/null
				echo "    -t|--tags <xxx>: csv of arbitrary tags for identification and automated parsing (default: json 'null' value)" 2>/dev/null
				echo "    -v|--version: print the script's version (current: $SCRIPT_VERSION)" 2>/dev/null
				echo '    -h|--help: this help message' 2>/dev/null
				exit 0 ;;
			*) echo "invalid argument: \"$1\" (try -h|--help)" 2>/dev/null; exit 1 ;;
		esac
		shift
	done

	# initial set up
	tmp_date="$(date +%s 2>/dev/null)" # timestamp files to avoid conflicts on concurred CTF machines
	enum_tmp="$enum_dir_tmp/$enum_prefix_out.${tmp_date:-0}.tmp"
	enum_stdout="$enum_dir_tmp/$enum_prefix_out.${tmp_date:-0}.stdout"
	enum_stderr="$enum_dir_tmp/$enum_prefix_out.${tmp_date:-0}.stderr"
	enum_report="$enum_dir_out/$enum_prefix_out.${tmp_date:-0}.json"
	echo -n '' 1>"$enum_report" 2>/dev/null # initialise report file
}

# function to format the output of the different enumeration probes to json structure
# required argument: $1 as json record separator (curly or squared, with or without comma)
# optional arguments: $2 as key and $3 as value
function json() {
	if [ $# -lt 1 ]; then return; fi
	output=''
	if [ -n "$1" ]; then output+="$1"; fi
	if [ -n "${2-}" ]; then output+="\"$2\":"; fi
	if [ -n "${3-}" ]
	then
		value="$3" # escape all json reserved characters
		value="${value//\\/\\\\}"
		value="${value//\"/\\\"}"
		value="${value//$'\x09'/\\t}"
		value="${value//$'\x0a'/\\n}"
		value="${value//$'\x08'/\\b}"
		value="${value//$'\x0c'/\\f}"
		value="${value//$'\x0d'/\\r}"
		if [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" == 'null' ] || [ "$value" == 'true' ] || [ "$value" == 'false' ]
		then output+="$value"
		else output+="\"$value\""
		fi
	fi
	if [ -n "$enum_report" ]; then echo -n "$output" 1>> "$enum_report" 2>/dev/null; else echo -n "$output" 2>/dev/null; fi
}

# function to run enumeration probes and pass their output to the json formating function
# required argument: $1 as array of commands to run
# security warning: commands will be trusted and run as-is, potential impact on the system should be considered beforehand
function enumerate() {
	for probe in "$@"
	do
		if [ -n "${tmp_comma-}" ]; then json ','; else tmp_comma='true'; fi # do not prepend a comma on the first loop
		tmp_start="$(date +%s 2>/dev/null)"
		json '{' 'command' "$probe"
		eval "$probe" 1>"$enum_stdout" 2>"$enum_stderr"
		json ',' 'retcode' "$?"
		stdout="$(cat "$enum_stdout" 2>/dev/null)"
		json ',' 'stdout' "${stdout:-null}" # default to json 'null' value
		stderr="$(cat "$enum_stderr" 2>/dev/null)"
		json ',' 'stderr' "${stderr:-null}" # default to json 'null' value
		tmp_stop="$(date +%s 2>/dev/null)"
		json ',' 'duration' "$(( $tmp_stop-$tmp_start ))" # in seconds
		json '}'
	done
}

# function to convert the json output to another format (only "html" is currently available)
# required arguments: $1 as json source file and $2 as requested destination format
function convert() {
	if [ $# -lt 2 ]; then return; fi
	if [ ! -f "$1" ]; then return; fi
	cp "$1" "$1.$2" 2>/dev/null
	if [ "$2" == 'html' ]
	then
		# conversion of reserved characters
		sed -i -E 's|'$'\x26''|\&amp\;|g; s|<|\&lt\;|g; s|>|\&gt\;|g' "$1.$2" 2>/dev/null          # html reserved
		sed -i -E 's|'$'\x27''|\&apos\;|g; s|\\\"|\&quot\;|g' "$1.$2" 2>/dev/null                  # html reserved
		sed -i -E 's|\\r|\'$'\x0d''|g; s|\\f|\'$'\x0c''|g; s|\\b|\'$'\x08''|g' "$1.$2" 2>/dev/null # json reserved
		sed -i -E 's|\\t|\'$'\x09''|g; s|\\\\|\'$'\x5c''|g' "$1.$2" 2>/dev/null                    # json reserved
		# generic regex (pure json)
		sed -i -E 's|"([^"]+)":"([^"]+)",?|<li><span class="key">\1: </span><pre>\2</pre></li>|g' "$1.$2" 2>/dev/null
		sed -i -E 's|"([^"]+)":([^][}{",]+),?|<li><span class="key">\1: </span><span class="value">\2</span></li>|g' "$1.$2" 2>/dev/null
		sed -i -E 's|"([^"]+)":|<details open><summary>\1</summary>|g' "$1.$2" 2>/dev/null
		# custom regex (generated html mixed with remaining json)
		sed -i -E 's|[][],?||g' "$1.$2" # todo: add a collapsible <details></details> tag for each <ul></ul> pair
		sed -i -E 's|^\{||; s|}$||; s|\{|<ul>|g; s|},?|</ul>|g' "$1.$2" 2>/dev/null
		sed -i -E 's|</ul><([^u])|</ul></details><\1|g' "$1.$2" 2>/dev/null
		# html format-specific
		sed -i -E 's|^|<!doctype html><html><head><title>enumHostLinux</title><style>*{font-family:monospace} summary{color:blue} ul{list-style-type:none} span.key{vertical-align:top;color:blue} span.value{color:green} pre{display:inline-block;margin:0;color:red}</style></head><body>|' "$1.$2" 2>/dev/null
		sed -i -E 's|$|</details></body></html>|' "$1.$2" 2>/dev/null
		# unescape the latest to avoid confusing the previous sed operations
		sed -i -E 's|\\n|\'$'\x0a''|g' "$1.$2" 2>/dev/null
	fi
}

# - - - main - - -

# initialise variables according to command-line arguments
initialise "$@"

# set array of probes to run
probes=()
# --- dry-run
if [ "$enum_probes_cat" -eq 0 ]; then probes+=('echo "--- dry-run ---" 2>/dev/null; date'); fi # example to append titles/comments to the commands output
# --- kernel, os and cpu
if [ "$enum_probes_cat" -gt 0 ]; then probes+=('uname -a' 'cat /proc/version' 'cat /etc/*-release' 'df -a' 'cat /proc/cpuinfo'); fi
# --- system and environment
if [ "$enum_probes_cat" -gt 0 ]; then probes+=('env' 'cat /etc/profile' 'cat /etc/shells' 'mount' 'cat /etc/fstab' 'lpstat -a' 'ls -la /var/' 'ls -la /var/log/'); fi
# --- service information
if [ "$enum_probes_cat" -gt 0 ]; then probes+=('ps -e -o cmd | grep -E "^/"' 'cat /etc/*inetd.conf' 'ls -la /etc/cron*'); fi
# --- network
if [ "$enum_probes_cat" -gt 0 ]; then probes+=('ifconfig -a' 'arp -e' 'route' 'cat /etc/resolv.conf' "cat \"$enum_tmp\" 2>/dev/null | sudo -n -S iptables -L" "cat \"$enum_tmp\" 2>/dev/null | sudo -n -S netstat -antup"); fi
# --- users and groups
if [ "$enum_probes_cat" -gt 0 ]; then probes+=('getent aliases' 'grep -Ev "nologin|false" /etc/passwd' 'cat /etc/group' "cat \"$enum_tmp\" 2>/dev/null | sudo -n -S grep -v \":[\*\!]:\" /etc/shadow" 'for i in $(cat /etc/passwd 2>/dev/null | cut -d: -f1 2>/dev/null); do id $i 2>/dev/null; done' 'w' 'last' 'lastlog 2>/dev/null | grep -v "Never"' "cat \"$enum_tmp\" 2>/dev/null | sudo -n -S grep -Ev \"^$|^#\" /etc/sudoers" 'ls -ahl /home/*'); fi
if [ "$enum_probes_cat" -gt 1 ]; then probes+=("cat \"$enum_tmp\" 2>/dev/null | sudo -n -S find / -name \"id_dsa*\" -o -name \"id_rsa*\" -o -name \"known_hosts\" -o -name \"authorized_*\""); fi
# --- priviledged user
if [ "$enum_probes_cat" -gt 0 ]; then probes+=("cat \"$enum_tmp\" 2>/dev/null | sudo -n -S ls -ahlR /root/" "cat \"$enum_tmp\" 2>/dev/null | sudo -n -S head /var/mail/root" "cat \"$enum_tmp\" 2>/dev/null | sudo -n -S ps -U root -u root u"); fi
if [ "$enum_probes_cat" -gt 1 ]; then probes+=("cat \"$enum_tmp\" 2>/dev/null | sudo -n -S find / -type f -perm -u=s -o -perm -g=s ! -path \"/proc/*\" ! -path \"/var/*\""); fi
# --- current user
if [ "$enum_probes_cat" -gt 0 ]; then probes+=('id' 'whoami' 'groups' 'crontab -l 2>/dev/null | grep -v "^#"'  'ps -x' "echo \"$enum_tmp\" 2>/dev/null | sudo -S -l -k" 'ls -al ~' 'ls -la ~/.ssh/' 'history 2>/dev/null | tail -100' 'history 2>/dev/null | grep -A5 "sudo" 2>/dev/null | tail -50'); fi
# --- interesting binaries (https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
if [ "$enum_probes_cat" -gt 0 ]; then probes+=('gcc -v' 'for i in ed ne nano pico vim vi more less man pinfo links lynx elinks mutt nmap awk expect irb perl python php nc netcat wget curl; do ls -la $(which $i || echo -) 2>/dev/null; done'); fi
# --- interesting files
if [ "$enum_probes_cat" -gt 0 ]; then probes+=("cat \"$enum_tmp\" 2>/dev/null | sudo -n -S find /home/ –name \"*.rhosts\" -type f" 'ls -la /usr/sbin/in.*'); fi
if [ "$enum_probes_cat" -gt 1 ]; then probes+=("cat \"$enum_tmp\" 2>/dev/null | sudo -n -S find / -mmin -10 ! -path \"/proc/*\" ! -path \"/var/*\" ! -path \"/sys/*\"" 'grep -l -i "pass" /var/log/*.log' "cat \"$enum_tmp\" 2>/dev/null | sudo -n -S find / -name \".*\" ! -path \"/proc/*\" ! -path \"/sys/*\""); fi

# workaround to avoid leaking the sudo password in the enumeration report
echo "$enum_sudo_pwd" > "$enum_tmp" 2>/dev/null

# open json output
json '{' 'script'
json '{' 'name' 'enumHostLinux'
json ',' 'version' "$SCRIPT_VERSION"
json '},' 'context'
json '{' 'epoch' "$(date +%s 2>/dev/null || echo null 2>/dev/null)"
json ',' 'host' "$(uname -n 2>/dev/null || echo null 2>/dev/null)"
json ',' 'user' "$(whoami 2>/dev/null || echo null 2>/dev/null)"
json ',' 'terminal' "$(tty 2>/dev/null || echo null 2>/dev/null)"
json ',' 'ipaddr' "$(who -u 2>/dev/null | grep $(whoami 2>/dev/null) 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' 2>/dev/null || echo null 2>/dev/null)"
json ',' 'call' "$0 $*"
json ',' 'tags' "$enum_tags_custom"
json '},' 'probes'
json '['
# run probes
enumerate "${probes[@]}"
# close json output
json ']'
json '}'

if [ -n "$enum_export_fmt" ]; then convert "$enum_report" "$enum_export_fmt"; fi

# clean temporary files
echo '' > "$enum_tmp" 2>/dev/null
rm "$enum_tmp" 2>/dev/null
echo '' > "$enum_stdout" 2>/dev/null
rm "$enum_stdout" 2>/dev/null
echo '' > "$enum_stderr" 2>/dev/null
rm "$enum_stderr" 2>/dev/null
