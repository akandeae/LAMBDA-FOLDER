#!/usr/bin/env bash

base_file="${0##*/}"
base_path="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

usage() {
  printf "%s\n" \
    "usage: bash ${base_file} [-i] [-f file] [-h] [-u user] [-l file] [host1 host2...]"
}

manual() {
  man_str="
  This script has two components that can be used to audit security
  configurations on a specified set of remote targets or a local system.

  1) Use Lynis to perform a security audit on the specified systems. Lynis
  supports any *NIX like system including UNIX, Linux, MacOS, AIX, Solaris, etc.

  2) Collect security configurations from hosts running Linux operating systems
  (Red Hat v5.x/v6.x/v7.x, CentOS v5.x/v6.x/v7.x, Ubuntu 14.04+, Debian 7.0+).

  optional arguments:
    -i  interactive
        Ask for confirmation before executing the next command.

    -l  lynis file
        Specify the file path of a local Lynis tarball to use for the system
        audit (see https://github.com/CISOfy/lynis/tarball/master)

    -t  targets
        Filename specifying remote audit targets. Recognizes comma, tab,
        whitespace, newline, and carriage return character target delimiters.

    -u  user
        Specify a username for SSH when connecting to the remote system(s).

    -h  help
        Display this help and exit

  examples:
    # Collect information on the local system. Run commands as a batch.
    > bash ${base_file}

    # Collect information on each system in the file. Use 'bob' as the login
    # for SSH on each host. Run the whole thing as a batch.
    > bash ${base_file} -f targets.txt -u bob

    # Collect information on the hostnames given on the command line. Pause
    # before executing each command. Connect by SSH without the optional user
    > bash ${base_file} -i 192.168.224.191 192.168.224.192 192.168.224.193

  other notes:

    Whether the script collects information from the local system, or collects
    information from remote systems, it will aggregate results from all targets
    locally on the system that executed the script in the current directory
    in a tarball with timestamps in the name using this format:

    ${PWD}/Sikich_Linux_OS_YYYY-MM-DD.H.M.S.tar.gz

    After completing, this tarball will contain a folder from each target
    system. If collecting from remote targets, the script will clean up
    after itself on each remote target before closing the connection."

  printf "%s\n" "${man_str}"
}

unset interactive
while getopts ":it:u:l:h" opt; do
  case "$opt" in
    i)  interactive=true;;
    t)  targets_file="${OPTARG}";;
    u)  user_acct="${OPTARG}";;
    l)  lynis_file="${OPTARG}";;
    h)  usage
        manual
        exit 0;;
    \?) printf "${base_file}: unknown option -%s\n%s" "$OPTARG">&2
        usage
        exit 1;;
    :)  printf "${base_file}: option requires an argument -%s\n%s" "$OPTARG">&2
        usage
        exit 1;;
  esac
done;
shift "$((OPTIND-1))"

linux_script="support_script_linux.sh"
local_repo="Sikich_Linux_OS"
l_path="${base_path}/${local_repo}"
mkdir -p "${l_path}"

if [[ -z ${lynis_file+x} ]] || [[ ! -f "${lynis_file}" ]]; then
  lynis_path="${base_path}"
  lynis_file="lynis.tar.gz"
#  printf "\nDownloading Lynis from Github...\n"
#  lynis_github="https://github.com/CISOfy/lynis/tarball/master"
#  wget -q --show-progress -O "${lynis_path}/${lynis_file}" "${lynis_github}"
else
  if [[ "${lynis_file}" = /* ]]; then
    lynis_path="$(dirname ${lynis_file})"
    lynis_file="$(basename ${lynis_file})"
  else
    lynis_path="${base_path}"
  fi
fi

host_args="$@"
host_file=()
IFS=$'\r\n\t, '
if [[ $targets_file ]]; then
  if [[ -f ${targets_file} ]]; then
    host_file=($(<${targets_file}))
  else
    printf "File not found: %s\n" "${targets_file}" && exit 1;
  fi
fi
targets=( ${host_args[@]} ${host_file[@]} )
sudo_prompt="This requires root privilege. Enter password for sudo:"
sudo_cmd="sudo -p \"${sudo_prompt}\""

printf "\nReviewing target hosts\n"

if [[ -z "${targets[@]}" ]]; then
  printf "%s\n" "No targets specified. Audit the local system instead?"
  printf "\n%s\n" 'Press [ENTER] to continue, or [CTRL]+C to quit' && read input
  printf "\nCopying test scripts...\n"
  output_path="$(pwd)/${local_repo}/Sikich_$(hostname)"
  mkdir -pv "${output_path}"
  cp "${base_path}/${linux_script}" "${output_path}"
  cp "${lynis_path}/${lynis_file}" "${output_path}"
  sudo -p "${sudo_prompt}" /usr/bin/env bash "${output_path}/${linux_script}" "${interactive}" "${lynis_file}"

else
  for target in "${targets[@]}"; do
    ssh_options="-o ControlMaster=auto -o ControlPersist=600 -o ControlPath=~/.ssh/control-%C"
    ssh_usr="${user_acct}@${target}"

    printf "\nConnecting to next target: %s@%s\n" "${user_acct}" "${target}"
    r_repo="Sikich_$(ssh ${ssh_options} ${ssh_usr} 'hostname' | sed 's/^M//g')"
    r_path="$(ssh ${ssh_options} ${ssh_usr} 'pwd' | sed 's/^M//g')/${r_repo}"

    printf "\nCopying test scripts to the remote host...\n"
    ssh ${ssh_options} "${ssh_usr}" "mkdir -p ${r_path}"
    scp -r ${ssh_options} "${base_path}/${linux_script}" "${ssh_usr}:${r_path}"
    scp -r ${ssh_options} "${lynis_path}/${lynis_file}" "${ssh_usr}:${r_path}"

    printf "\nBeginning the tests...\n"
    printf "The script needs to elevate privilege on the target host via sudo.\n"
    script_cmd="sudo /usr/bin/env bash ${r_path}/${linux_script}"
    ssh -t ${ssh_options} "${ssh_usr}" "${script_cmd} \"${interactive}\" \"${lynis_file}\""

    printf "\nRetrieving test results from %s...\n" "${target}"
    scp -r ${ssh_options} "${ssh_usr}:${r_path}" "${l_path}"

    printf "\nCleaning up test results on %s...\n" "${target}"
    ssh  ${ssh_options} "${ssh_usr}" "rm -vrf ${r_path}"

    printf "\nFinished with %s. Closing SSH session...\n" "${target}"
    ssh -O exit ${ssh_options} "${ssh_usr}"

    printf "\nCollecting SSH protocol negotiation output...\n" "${target}"
    ssh -vv "root@${target}" "logout" > "${l_path}/${r_repo}/${r_repo:4}_ssh_protocol_negotiation.txt" 2>&1
    printf "\nDone collecting SSH protocol negotiation output.\n" "${target}"
  done
fi

printf "\nCompleted all tests.\n";
printf "\nRemoving temporary files...\n";
printf "\nOutput saved here: %s\n" "${l_path}";

exit 0
