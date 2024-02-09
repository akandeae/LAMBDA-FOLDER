#!/usr/bin/env bash

interactive=${1}
lynis_tarball=${2}
linux_repo="Sikich_linux_commands"
lynis_repo="lynis"
base_path="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
linux_output_path="${base_path}/${linux_repo}"
linux_teminal_log="${linux_output_path}/${HOSTNAME}_log.txt"
soft_dir="${linux_output_path}/software"
net_dir="${linux_output_path}/networking"
rsyslog_dir="${linux_output_path}/rsyslog"
usr_dir="${linux_output_path}/users"
misc_dir="${linux_output_path}/miscellaneous"
pam_dir="${usr_dir}/pam_authentication"
accts_dir="${usr_dir}/accounts"
mkdir -p "${soft_dir}" "${net_dir}" "${rsyslog_dir}" "${pam_dir}" "${accts_dir}" "${misc_dir}"

exec > >( tee "${linux_teminal_log}" )
printf "\nOS baseline tests\n\n"

prompt() {
  if [[ $interactive ]]; then
    printf "\n[Press [ENTER] to continue, or [CTRL]+C to stop]\n\n"
    read input
  else
    printf "\n\n"
  fi
}

print_section_break() {
  printf "%.0s-" {1..80}
  printf "\n"
}

if [[ -f /etc/system-release ]]; then
  os_vers="$(cat /etc/system-release)"
else
  os_vers="$(lsb_release -sd)"
fi

if [[ -e /etc/redhat-release ]]; then
  is_fedora=true
elif [[ -n $(grep -i "ID_LIKE=rhel fedora" /etc/os-release 2>/dev/null) ]]; then
  is_fedora=true
elif [[ -n $(grep -i "ID_LIKE=debian" /etc/os-release 2>/dev/null) ]]; then
  is_debian=true
else
  is_debian=true
fi

if [[ -x /usr/bin/systemctl || -x /bin/systemctl ]]; then
 uses_systemd=true
fi

print_section_break
printf "%-23s %-56s\n" "Date:" "$(date -u +%T\ %Z\ %F)"
printf "%-23s %-56s\n" "Hostname:" "$(hostname)"
printf "%-23s %-56s\n" "OS version:" "${os_vers}"
printf "%-23s %-56s\n" "Kernel version:" "$(uname -r | cut -f2)"
printf "%-23s %-56s\n" "Details:" "$(uname -srv)"
print_section_break

prompt

## Package manager config, installed software, software update history, etc.
if [[ $is_fedora == true ]]; then
  rpm_gpg_query="\"%{name}\t%{version}-%{release}\t%{summary}\n\""
  rpm_pkg_query="\"%{name} %{version} %{release} %{vendor}\n\""
  rpm_legacy="telnet telnet-server rsh rsh-server ypbind ypserv tftp tftp-server talk talk-server xinetd sendmail"
  rpm_specialty="dhcp openldap-servers openldap-clients bind vsftpd httpd dovecot samba squid net-snmp mcstrans setroubleshoot xorg-x11-server-common"
  pkg_mgmt=(
    "grep gpgcheck /etc/yum.conf # Require verification for updates?"
    "rpm -qa --qf ${rpm_pkg_query} | column -t | sort > ${soft_dir}/${HOSTNAME}_installed_software.txt"
    "rpm -q ${rpm_legacy}        # Look for these legacy packages explicitly"
    "rpm -q ${rpm_specialty}     # Look for these specialty packages explicitly"
    "yum history list            # Software update history"
    "rpm -qa --last | column -t  > ${soft_dir}/${HOSTNAME}_software_update_history.txt"
    "yum check-update            # Any updates not installed?"
  )

elif [[ $is_debian == true ]]; then
  legacy="prelink nis rsh-client rsh-redone-client talk slapd biosdevname"
  pkg_mgmt=(
    "dpkg -l > ${soft_dir}/${HOSTNAME}_installed_software--all.txt"
    "dpkg -s ${legacy} 2>&1 | egrep -v '^$' > ${soft_dir}/${HOSTNAME}_installed_software--insecure.txt"
    "egrep -i '^(Start|End)-Date:' /var/log/apt/history.log | column -t  > ${soft_dir}/${HOSTNAME}_patch_history--1.txt"
    "grep [[:space:]]install[[:space:]] /var/log/dpkg.log | column -t > ${soft_dir}/${HOSTNAME}_patch_history--2.txt"
    "apt-get -qq update && apt-get --just-print upgrade 2>&1 | perl -ne 'if (/Inst\s([\w,\-,\d,\.,~,:,\+]+)\s\[([\w,\-,\d,\.,~,:,\+]+)\]\s\(([\w,\-,\d,\.,~,‌​:,\+]+)\)? /i) {print \"PROGRAM: \$1 INSTALLED: \$2 AVAILABLE: \$3\n\"}' | column -s ' ' -t  > ${soft_dir}/${HOSTNAME}_installed_software__uninstalled_updates.txt"
    "/usr/lib/update-notifier/apt-check --human-readable > ${soft_dir}/${HOSTNAME}_installed_software__uninstalled_update_totals.txt"
  )
fi

## System processes and services, enabled functionality, etc.
if [[ $is_fedora == true && $uses_systemd == true ]]; then
  services=(
    "systemctl get-default   # Default run-level for servers should not be graphical"
    "systemctl list-units --type service       # List running services"
    "systemctl list-unit-files --type service  # List available services"
    "chkconfig --list | egrep '(chargen|daytime|echo|tcpmux)-'  # Specifically check for legacy software"
    "systemctl list-units --type device        # List kernel-managed devices"
    "systemctl list-units --type mount         # List mount points"
    "systemctl list-units --type socket        # List kernel-managed sockets"
    "systemctl list-sockets                    # List kernel-managed sockets"
  )
elif [[ $is_fedora == true ]]; then
  chkcfg_legacy="'rlogin|rsh|rexec|telnet|chargen|daytime|echo|tcpmux'"
  chkcfg_specialty="'avahi-daemon|cups|nfslock|rpc(gssd|bind|idmapd|svcgssd)|netconsole|rdisc|ntpdate|oddjobd|abrtd|atd|qpidd|bluetooth'"
  services=(
    "grep initdefault /etc/inittab | grep -v ^#    # System run-level at boot"
    "service --status-all | egrep -i running       # List running system services"
    "service --status-all > ${misc_dir}/${HOSTNAME}_all_services_status.txt"
    "chkconfig --list | column -t                  # List run-levels for each service"
    "chkconfig --list | egrep ${chkcfg_legacy}     # Check the status of legacy services explicitly"
    "chkconfig --list | egrep ${chkcfg_specialty}  # Check the status of specialty software explicitly"
  )
elif [[ $is_debian == true && $uses_systemd == true ]]; then
  services=(
    "systemctl get-default                     # System run-level at boot"
    "systemctl list-units --type service       # List running services"
    "systemctl list-unit-files --type service  # List installed services that might not be running"
    "systemctl list-units --type device        # List kernel-managed devices"
    "systemctl list-units --type mount         # List mount points"
    "systemctl list-units --type socket        # List kernel-managed sockets"
    "systemctl list-sockets                    # List kernel-managed sockets"
  )
elif [[ $is_debian == true ]]; then
  legacy_services="'xinetd|cups|isc-dhcp-server|rpcbind-boot|vsftpd|dovecot|smbd|squid3|avahi-daemon'"
  services=(
    "service --status-all 2>&1 | egrep -v '\[ (\?|\-) \]'     # List running services managed by sysvinit"
    "initctl list | egrep -v 'stop/waiting|^tty' | column -t  # List running services managed by upstart"
    "initctl list | egrep ${legacy_services} | column -t      # Legacy services should be disabled"
    "egrep '^shell|^login|^exec|^talk|^ntalk|^telnet|^tftp' /etc/inetd.conf  # Legacy services should be disabled"
    "egrep '^chargen|^daytime|^echo|^discard|^time' /etc/inetd.conf          # Legacy services should be disabled"
    "ls /etc/rc*.d/S*{bind9,apache2,snmpd}   # Check if DNS and Apache server, or SNMP agent are enabled"
    "grep ^RSYNC_ENABLE /etc/default/rsync   # Check if rsync is enabled"
  )
fi

## General system configs (mostly) common to all Linux distros.
sys_info=(
  "mount | column -t > ${misc_dir}/${HOSTNAME}_mounted_filesystems.txt"
  "pstree -A > ${misc_dir}/${HOSTNAME}_process_tree.txt                    # List system daemons/processes"
  "ps -ef | egrep -v 'bash -c' > ${misc_dir}/${HOSTNAME}_process_list.txt  # List system daemons/processes"
  "cat /sys/class/dmi/id/{sys_vendor,product*}                 # Check if this a virtual system"
  "dmidecode -t1 -t2 -t3 -t24 -t30 -t38 > ${misc_dir}/${HOSTNAME}_system_hardware.txt"
  "ifconfig -a                          # Show network interfaces"
  "iw list                              # Show wireless devices"
  "ss -l | column -t                    # List all open ports"
  "ss -tuanp | column -t                # List tcp and udp sockets"
  "netstat -nr                          # display the kernel routing table"
  "netstat -l                           # display listening connections"
  "netstat -an | grep ':25[[:space:]]'  # Set mail transfer agent to local only"
  "sysctl kernel.randomize_va_space     # Virtual memory layout randomization"
  "sysctl fs.suid_dumpable              # Restrictions on core dumps"
  "grep \"hard core\" /etc/security/limits.conf    # Restrictions on core dumps"
  "timedatectl status                              # List information about system time"
  "timedatectl --version                           # List information about system time"
  "systemctl status ntpd                           # NTP daemon status"
  "ntpq -p                                         # NTP daemon status"
  "ntpd --version                                  # NTP version"
  "cat /etc/sysconfig/ntpd                         # NTP daemon service account"
  "chronyc sources -v                              # Chrony time sources"
  "chronyc tracking                                # Time metrics reported by chrony"
  "sshd -T  > ${net_dir}/${HOSTNAME}_ssh_running_config.txt    # SSH server daemon running config"
  "auditctl -l                          # Kernel audit daemon running config"
)

## Critical config files
net_configs="/etc/{resolv.conf,hosts,hosts.{allow,deny},snmp/snmpd.conf}"
sys_configs="/etc/{fstab,securetty,ntp.conf,ssh/{ssh,sshd}_config}"
user_configs="/etc/{sudoers,login.defs,default/useradd}"
mon_configs="/etc/{audit/audit.rules,aide.conf}"
log_configs="/etc/{*syslog*.conf,rsyslog.d/*.conf}"
user_files="/etc/{passwd,shadow,gshadow,group}"
cron_files="/etc/{*cron*,cron.allow,at.{allow,deny}}"
syslogs=$(grep -v "^#" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null |grep -o "/var/log[^[:space:];]*" |cut -d: -f2 |tr "\n" " ")

if [[ ! -f "/etc/audit/auditd.conf" ]]; then
  printf "[-] auditd is not installed\n\n"
  auditd_log="/etc/audit/auditd.conf"
else
  auditd_log=$(grep -o "/var/log[^[:space:];]*" /etc/audit/auditd.conf)
fi

if [[ $is_fedora == true && $uses_systemd == true ]]; then
  pam_configs="/etc/pam.d/{su,sudo,sshd,system-auth*,password-auth*}"
  boot_files="/boot/grub2/grub.cfg"
elif [[ $is_fedora == true ]]; then
  pam_configs="/etc/pam.d/{su,sudo,sshd,system-auth*,password-auth*}"
  boot_files="/boot/grub/grub.conf"
elif [[ $is_debian == true ]]; then
  pam_configs="/etc/pam.d/{su,sudo,sshd,common-*,login}"
  boot_files="/boot/grub/grub.cfg"
else
  pam_configs="/etc/pam.d/{su,sudo,sshd,common-*,login,system-auth*,password-auth*}"
  boot_files="/boot/grub/grub.{cfg,conf}"
fi

cfg_files=(
  "cp ${net_configs} ${net_dir}      # Network configs"
  "cp ${sys_configs} ${net_dir}      # System configs"
  "cp ${mon_configs} ${misc_dir}     # Monitoring software configs"
  "cp ${log_configs} ${rsyslog_dir}  # Rsyslog configs"
  "cp ${pam_configs} ${pam_dir}      # Authentication configs"
  "cp ${user_configs} ${usr_dir}     # System configs"
  "cp ${boot_files} ${misc_dir}      # System boot config"
)

## Discretionary access controls
local_volumes=$(df -lP | sed "1d" | tr -s " " | cut -d " " -f6 | tr "\n" " ")
lib_dirs="/lib /lib64 /usr/lib /usr/lib64"
exe_dirs="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/libexec /usr/local/libexec"
users=$(getent passwd | cut -d: -f1 | tr "\n" " ")
dac=(
  "stat -c '%A %a %U %G %n' ${net_configs} | column -t  # Perms for system config files"
  "stat -c '%A %a %U %G %n' ${sys_configs} | column -t  # Perms for system config files"
  "stat -c '%A %a %U %G %n' ${mon_configs} | column -t  # Perms for monitoring config files"
  "stat -c '%A %a %U %G %n' ${log_configs} | column -t  # Perms for system config files"
  "stat -c '%A %a %U %G %n' ${pam_configs} | column -t  # Perms for PAM config files"
  "stat -c '%A %a %U %G %n' ${user_configs} | column -t # Perms for system config files"
  "stat -c '%A %a %U %G %n' ${boot_files} | column -t   # Perms for boot config file"
  "stat -c '%A %a %U %G %n' ${user_files} | column -t   # Perms for user acct files"
  "stat -c '%A %a %U %G %n' ${cron_files} | column -t   # Perms for cron and anacron"
  "stat -c '%A %a %U %G %n' /var/log/* | column -t      # Perms for log files in /var"
  "stat -c '%A %a %U %G %n' ${syslogs} | column -t      # Perms for rsyslog log files"
  "stat -c '%A %a %U %G %n' ${auditd_log} | column -t   # Perms for auditd log file"
)

## SELinux and AppArmor
if [[ $is_fedora == true ]]; then
  mac=(
    "egrep 'selinux=|enforcing=' ${boot_files}    # Whether SELinux is enabled/disabled at boot"
    "grep ^SELINUX /etc/selinux/config            # SElinux state and policy"
    "/usr/sbin/sestatus                           # SElinux state and policy"
    "ps -eZ | egrep unconfined | egrep -vw 'ps|egrep|bash' # Unconfined daemons"
    "grep ^umask /etc/bashrc /etc/profile.d/*     # Default perms for new user-created files/objects"
    "grep umask /etc/sysconfig/init  # Default perms for new daemon-created files/objects"
    "authconfig --test               # Current system auth config"
  )
elif [[ $is_debian == true ]]; then
  mac=(
    "apparmor_status   # AppArmor state, profiles, and unconfined processes."
    "grep ^umask /etc/login.defs  # Default perms for new user-created files/objects"
  )
fi

## User account and authentication management
users=(
  "getent passwd | column -ts: > ${accts_dir}/${HOSTNAME}_user_accounts.txt"
  "getent group | column -ts: > ${accts_dir}/${HOSTNAME}_user_groups.txt"
  "getent shadow | sed 's/\([^:]*[:]\)\([^:]*\)\(.*\)/\1*\3/' | column -ts: > ${accts_dir}/${HOSTNAME}_user_shadow.txt"
  "getent gshadow > ${accts_dir}/${HOSTNAME}_user_group_shadow.txt"
  "getent passwd | cut -d: -f1 | xargs -I {} bash -c 'sudo -l -U {}'                    # Check each user's sudo privileges"
  "getent passwd | cut -d: -f1 | xargs -I {} bash -c 'echo {}; chage -l {}'             # Check each user's password age"
  "printf '\n%-20s %-16s %-15s %-10s %-10s %-10s %-10s\n\n' 'User' 'Status (L,P,NP)' 'Last changed' 'Min age' 'Max age' 'Warn' 'Inacivity period'; getent passwd | cut -d: -f1 | xargs -I {} bash -c 'sudo passwd -S {}' |  awk -F' ' '{printf \"%-20s %-16s %-15s %-10s %-10s %-10s %-10s\n\", \$1, \$2, \$3, \$4, \$5, \$6, \$7}'  # Check each user's password status"
  "getent passwd | egrep -v '/sbin/nologin|/bin/false|/bin/sync|/var/lib/libuuid'       # List of users with a valid interactive login shell"
  "useradd -D | grep 'INACTIVE'                                                         # Days of inactivity before the system disables a user's account"
)

## Host-based firewall
if [[ $is_fedora == true && $uses_systemd == true ]]; then
  fw=(
    "systemctl is-enabled firewalld  # Status of the builtin firewall"
    "firewall-cmd --list-all-zones   # Everything active or enabled in all zones"
  )
elif [[ $is_fedora == true ]]; then
  fw=(
    "egrep ':FORWARD|:INPUT' /etc/sysconfig/iptables"
    "iptables -L -n -v --line-numbers > ${net_dir}/${HOSTNAME}_iptables_ipv4_rules.txt"
    "ip6tables -L -n -v --line-numbers > ${net_dir}/${HOSTNAME}_iptables_ipv6_rules.txt"
  )
elif [[ $is_debian == true ]]; then
  fw=(
    "ufw status          # Status of the builtin firewall"
    "ufw show listening  # Status of the builtin firewall"
    "iptables -L -n -v --line-numbers > ${net_dir}/${HOSTNAME}_iptables_ipv4_rules.txt"
    "ip6tables -L -n -v --line-numbers > ${net_dir}/${HOSTNAME}_iptables_ipv6_rules.txt"
  )
fi

do_cmd() {
  if [[ $2 ]]; then
    printf "\n"
    print_section_break
    printf "%s) %s\n" "${1}" "${2}"
    bash -c "${2}" 2>&1
    prompt
  fi
}

# Get to work.
command_list=( "${pkg_mgmt[@]}" "${services[@]}" "${sys_info[@]}" "${cfg_files[@]}" "${dac[@]}" "${mac[@]}" "${users[@]}" "${fw[@]}" )
for ((i = 0; i < ${#command_list[@]}; i++)); do
  do_cmd $(($i + 1)) "${command_list[$i]}";
done

printf "\nFinished with OS baseline test\n"
exec &>/dev/tty

printf "\nSetting up Lynis test\n"
if [[ -z $interactive ]]; then
  pause="-Q"
fi

lynis_code_path="${base_path}/Sikich_lynis"
lynis_output_path="${base_path}/${lynis_repo}"
lynis_cli_report="${lynis_output_path}/${HOSTNAME}_terminal_report.html"
lynis_data_path="${lynis_output_path}/data"
lynis_data="${lynis_data_path}/${HOSTNAME}_lynis_data.txt"
lynis_terminal_output="${lynis_data_path}/${HOSTNAME}_terminal_output.txt"
lynis_log="${lynis_data_path}/${HOSTNAME}_lynis_log.txt"
lynis_auditor="Sikich"

mkdir -p "${lynis_output_path}" "${lynis_data_path}"
cd "${base_path}"
tar xf "${lynis_tarball}"
mv "$(tar -tf ${lynis_tarball} | head -n 1)" "${lynis_code_path}"
cd "${lynis_code_path}"

exec > >( tee "${lynis_terminal_output}" )
bash ./lynis audit system -c ${pause} --verbose --auditor "${lynis_auditor}" --logfile "${lynis_log}" --report-file "${lynis_data}"
exec &>/dev/tty

printf "\nGenerating Lynis report...\n";
ansi_codes_to_html() {
    filename="${1}"

    printf "%s\n" "<html><head><title>Lynis Summary Report: $(hostname)</title></head><style>"
    printf "%s\n" "html { background-color: #eee8d5; margin: 1em; color: #839496 }"
    printf "%s\n" "body { background-color: #002b36; margin: 0 auto; max-width: 23cm; border: 1pt solid #93a1a1; padding: 1em; }"
    printf "%s\n" ".txt { font-weight: normal; }"
    printf "%s\n" ".txt.bold { font-weight: bold; }"
    printf "%s\n" ".txt.red      { color: #d30102; }"
    printf "%s\n" ".txt.yellow   { color: #b58900; }"
    printf "%s\n" ".txt.green    { color: #859900; }"
    printf "%s\n" ".txt.white    { color: #93a1a1; }"
    printf "%s\n" ".txt.magenta  { color: #d33682; }"
    printf "%s\n" ".txt.cyan     { color: #2aa198; }"
    printf "%s\n" ".txt.blue     { color: #268bd2; }"
    printf "%s\n" ".row_container { width: 100\%; height: 20px; border: 0px solid; margin: 0px 0px 0px 0px;}"
    printf "%s\n" ".left_indent  { margin: 0px 0px 0px 0px; width:auto; overflow:hidden; }"
    printf "%s\n" ".right_indent { margin: 0px 0px 0px 0px; width:auto; float:right; }"
    printf "%s\n" ".left_indent.single    { margin-left: 20px; }"
    printf "%s\n" ".left_indent.double    { margin-left: 40px; }"
    printf "%s\n" ".left_indent.triple    { margin-left: 60px; }"
    printf "%s\n" ".left_indent.quadruple { margin-left: 80px; }"
    printf "%s\n" ".left_indent.quintuple { margin-left: 100px; }"
    printf "%s\n" "</style><body><pre>"

    div_row="<div class='row_container'>"
    div_left0="<div class='left_indent'>\1<\/div>"
    div_left1="<div class='left_indent single'>\1<\/div>"
    div_left2="<div class='left_indent double'>\1<\/div>"
    div_left3="<div class='left_indent triple'>\1<\/div>"
    div_left4="<div class='left_indent quadruple'>\1<\/div>"
    div_left5="<div class='left_indent quintuple'>\1<\/div>"
    div_right="${div_row}<div class='right_indent'>\3<\/div>"
    pattern1="\(.*\)\(\[[0-9]*C\)\(.*\)"

    while IFS='' read -r line || [[ -n "$line" ]]; do
        [[ ${line:0:3} == '[+]' ]] && line="<p></p><br>${line}";

            line=$(echo $line | sed "s/\[0C${pattern1}/${div_right}${div_left0}<\/div>/")
            line=$(echo $line | sed "s/\[2C${pattern1}/${div_right}${div_left1}<\/div>/")
            line=$(echo $line | sed "s/\[4C${pattern1}/${div_right}${div_left2}<\/div>/")
            line=$(echo $line | sed "s/\[6C${pattern1}/${div_right}${div_left3}<\/div>/")
            line=$(echo $line | sed "s/\[8C${pattern1}/${div_right}${div_left4}<\/div>/")
            line=$(echo $line | sed "s/\[10C${pattern1}/${div_right}${div_left5}<\/div>/")

            line=$(echo $line | sed 's/\[0;44m\(.[^\[]*\)\[0m\(.*\)/<span class="bold blue txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[0;94m\(.[^\[]*\)\[0m\(.*\)/<span class="bold blue txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[0;31m\(.[^\[]*\)\[0m\(.*\)/<span class="red txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[0;32m\(.[^\[]*\)\[0m\(.*\)/<span class="green txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[0;33m\(.[^\[]*\)\[0m\(.*\)/<span class="yellow txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[0;34m\(.[^\[]*\)\[0m\(.*\)/<span class="blue txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[0;35m\(.[^\[]*\)\[0m\(.*\)/<span class="magenta txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[0;36m\(.[^\[]*\)\[0m\(.*\)/<span class="cyan txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[0;37m\(.[^\[]*\)\[0m\(.*\)/<span class="white txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[1;31m\(.[^\[]*\)\[0m\(.*\)/<span class="bold red txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[1;32m\(.[^\[]*\)\[0m\(.*\)/<span class="bold green txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[1;33m\(.[^\[]*\)\[0m\(.*\)/<span class="bold yellow txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[1;34m\(.[^\[]*\)\[0m\(.*\)/<span class="bold blue txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[1;35m\(.[^\[]*\)\[0m\(.*\)/<span class="bold magenta txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[1;36m\(.[^\[]*\)\[0m\(.*\)/<span class="bold cyan txt">\1<\/span>\2/g')
            line=$(echo $line | sed 's/\[1;37m\(.[^\[]*\)\[0m\(.*\)/<span class="bold white txt">\1<\/span>\2/g')

            printf "%s<br>" "${line}"
    done < ${filename}
    printf "</pre></body></html>"
}
ansi_codes_to_html "${lynis_terminal_output}" > "${lynis_cli_report}"

printf "\nRemoving temporary files...\n";
rm -rf "${lynis_code_path}"
rm -vf "${base_path}/${lynis_tarball}"
rm -vf "${base_path}/${0##*/}"

printf "\nSetting permissions on output files...\n";
chmod -Rfv 777 "${base_path}"
exit 0
