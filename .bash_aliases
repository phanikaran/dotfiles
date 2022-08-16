alias sai='sudo apt-get install -y'
alias sarp='sudo apt-get remove --purge'
alias ltt='ls -larth | tail'
alias ba='vim ~/.bash_aliases'
alias br='. ~/.bashrc'
alias zc='vim ~/.zshrc'
alias za='vim ~/.bash_aliases'
alias zr='. ~/.zshrc'
alias sau='sudo apt-get update'
alias hvpn='sudo openvpn /home/shanks/Code/HTB/lab_luffytaro.ovpn'
alias cdd='cd ../..'
alias ad='ip -c addr | grep -w inet'
alias bat='batcat'
alias pys='python3 -m http.server 13379'
alias nessus='sudo systemctl start nessusd.service'
alias js='sudo docker run --rm -p 3000:3000 bkimminich/juice-shop'
alias tf='tail -f'
alias shr='cd /media/shared; python3 -m http.server 13379'
alias sd='python3 /home/shanks/Code/SubDomainizer/SubDomainizer.py'
#alias bs='cd ~/Code/Burp_Suite_Pro/; /usr/lib/jvm/java-11-openjdk-amd64/bin/java --illegal-access=permit -Dfile.encoding=utf-8 -javaagent:BurpSuiteLoader_v2020.12.1.jar -noverify -jar burpsuite_pro_v2020.12.1.jar &'
alias blr='systemctl restart bluetooth.service'
alias c='cd ~/Code'
alias tvpn='sudo openvpn /home/shanks/Code/TryHackMe/kaizokudevx.ovpn'
alias d='cd ~/Downloads/'
alias vim='nvim'
alias gs='git status'
alias gaa='git add *'
alias gcm='git commit -m'
alias gpom='git push origin master'
alias gag='git add gitlet/*'
alias gc='git clone'
alias ga='git add'
#alias cat='bat'
alias sdi='sudo dpkg -i'
alias cam='cvlc v4l2:///dev/video0'
alias fipr='ps aux | grep'
alias joomscan='perl /home/shanks/Code/joomscan/joomscan.pl'
alias nmapAutomator='/home/shanks/Code/nmapAutomator/nmapAutomator.sh'
alias ij='/opt/idea-IC-212.4746.92/bin/idea.sh > /dev/null 2>&1 &'
alias pse='pse -v'
alias harvester='python3 /home/shanks/Code/theHarvester/theHarvester.py'
alias cd='z'
alias msf_pattern_create='/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb'
alias msf_pattern_offset='/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb'
alias o='cd ~/OSCP'
alias pen='sudo openvpn ~/OSCP/OS-549400-PWK.ovpn'
alias ax='axel -a -n 5'
alias op='vlc "file:///home/shanks/Music/one_piece_bgm.m4a"'
alias byobue='sudo vim /usr/share/byobu/keybindings/f-keys.tmux'
alias vime='sudo vim /etc/vim/vimrc'
alias chisel='/home/shanks/Code/HTB/bins/linux/chiselx64' 

# wordlists
SECLISTS='/usr/share/seclists'
WEB_CONTENT='/usr/share/seclists/Discovery/Web-Content'
COMMON_DIRS='/usr/share/seclists/Discovery/Web-Content/common.txt'
MEDIUM_DIRS='/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'
RAFT_MED_DIRS='/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'
ROCKYOU='/usr/share/wordlists/rockyou.txt'
SUBDOMAINS='/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'

# offsec
alias smbserver='sudo python3 /home/shanks/.local/bin/smbserver.py'
alias rot13='tr "A-Za-z" "N-ZA-Mn-za-m" <<<'
alias john='/opt/john-1.9.0-jumbo-1/run/john'
alias ss='searchsploit'
alias davtest='/home/shanks/Code/davtest/davtest.pl'
alias wes='python2 /home/shanks/Code/Windows-Exploit-Suggester/windows-exploit-suggester.py'
alias he='python3 -m http.server 13377 --directory=/home/shanks/Code/HTB/bins'
alias jd='java -jar /home/shanks/Code/jd-gui/jd-gui.jar'
alias odat='python3 ~/Code/odat/odat.py'
alias vol='python ~/Code/volatility/vol.py'
#alias smbwin='smbserver share ~/Code/HTB/bins/windows/ -smb2support -username taxi -password taxi'
alias smbwin='smbserver share ~/Code/HTB/bins/windows/ -smb2support'
alias pdf2john='/opt/john-1.9.0-jumbo-1/run/pdf2john.pl'
alias ssh2john='/opt/john-1.9.0-jumbo-1/run/ssh2john.py'
alias gpg2john='/opt/john-1.9.0-jumbo-1/run/gpg2john'
alias bloodhound='/home/shanks/Code/BloodHound-linux-x64/BloodHound'

function mkhtb () {
	cd /home/shanks/Code/HTB;
	mkdir $1;
	cd $1;
	mkdir nmap ffuf;
	touch cmds learnings;
	echo "ip=${2}" > cmds;
	echo "\n\n" >> cmds;
	echo 'nmap -sT -Pn -p- --min-rate 10000 -oN nmap/tcp_ports_scan $ip' >> cmds;
	echo "\n" >> cmds;
	echo 'nmap --privileged -sU -Pn -p- --min-rate 10000 -oN nmap/udp_ports_scan $ip' >> cmds;
	echo "\n\n" >> cmds;
	echo 'nmap -Pn -sT -A -p _tcp_ports_comma_separated_ -oN nmap/tcp_script_scan $ip' >> cmds;
	echo "\n" >> cmds;
	echo 'nmap --privileged -Pn -sU -A -p _udp_ports_comma_separated_ -oN nmap/udp_script_scan $ip' >> cmds;
	echo "\n\n" >> cmds;
	echo "#############" >> cmds;
	echo "\n\n" >> cmds;
	echo "#############" >> cmds;
	echo "\n\n\n" >> cmds;
	echo 'ffuf -u http://$ip/FUZZ -w $COMMON_DIRS -e .php,.txt,.html -t 500 -ic -rate 1000 -r -c | tee ffuf/common_dirs.txt' >> cmds;
	echo "\n\n\n" >> cmds;
	echo 'ffuf -u http://$ip/FUZZ -w $MEDIUM_DIRS -e .php,.txt,.html -t 500 -ic -rate 1000 -r -c | tee ffuf/medium_dirs.txt' >> cmds;
	echo "\n\n\n" >> cmds;
	echo 'ffuf -u http://builder.htb/ -w $SUBDOMAINS -H "Host: FUZZ.builder.htb" -t 500 -ic -rate 1000 -r -c -fw 1337 | tee ffuf/common_subdomains.txt' >> cmds;
}


function nmt () {
        nmap -sT -Pn -p- --min-rate 10000 -oN nmap/tcp_ports_scan $ip;
        TCP_PORTS=$(grep '/tcp' nmap/tcp_ports_scan | grep -v Nmap | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//');
        # handle when TCP_PORTS is empty
        sed -i -e "s/_tcp_ports_comma_separated_/${TCP_PORTS}/g" cmds;
        nmap -Pn -sT -A -p ${TCP_PORTS} -oN nmap/tcp_script_scan $ip;
}


function nmu () {
        nmap --privileged -sU -Pn -p- --min-rate 10000 -oN nmap/udp_ports_scan $ip;
        UDP_PORTS=$(grep '/udp' nmap/udp_ports_scan | grep -v Nmap | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//');
        # handle when UDP_PORTS is empty
        sed -i -e "s/_udp_ports_comma_separated_/${UDP_PORTS}/g" cmds;
        nmap --privileged -Pn -sU -A -p ${UDP_PORTS} -oN nmap/udp_script_scan $ip;
}


function ath() {
        DOMAIN="${1}"
        sudo cp /etc/hosts /etc/hosts.bkp;
        echo "${ip}    ${DOMAIN}" | sudo tee -a /etc/hosts;
        # if /etc/hosts contains the domain already, print err msg

        sed -i -e "s/http\:\/\/\$ip/http\:\/\/${DOMAIN}/g" cmds;
        sed -i -e "s/builder.htb/${DOMAIN}/g" cmds;
}


function ffc() {
        # add support for .asp,.aspx
        CMD=$(grep 'common_dirs.txt' cmds);
        eval ${CMD};
}


function ffm() {
        CMD=$(grep 'medium_dirs.txt' cmds);
        eval ${CMD};
}


function ffs() {
        CMD=$(grep 'common_subdomains.txt' cmds);
        eval "timeout 2s ${CMD}" > /dev/null;
        WORDS=$(grep -m 1 'Words' ffuf/common_subdomains.txt | cut -d ':' -f 4 | cut -d ',' -f 1 | awk '{$1=$1};1');
        sed -i -e "s/-fw 1337/-fw ${WORDS}/g" cmds;

        NEW_CMD=$(grep 'common_subdomains.txt' cmds);
        eval ${NEW_CMD};
}



function mkthm () {
	cd /home/shanks/Code/THM;
	mkdir $1;
	cd $1;
	mkdir nmap ffuf;
	touch cmds learnings;
	echo "ip=${2}" > cmds;
	echo "\n\n" >> cmds;
	echo 'nmap -sT -Pn -p- --min-rate 10000 -oN nmap/tcp_ports_scan $ip' >> cmds;
	echo "\n" >> cmds;
	echo 'nmap --privileged -sU -Pn -p- --min-rate 10000 -oN nmap/udp_ports_scan $ip' >> cmds;
	echo "\n\n" >> cmds;
	echo 'nmap -Pn -sT -A -p _tcp_ports_comma_separated_ -oN nmap/tcp_script_scan $ip' >> cmds;
	echo "\n" >> cmds;
	echo 'nmap --privileged -Pn -sU -A -p _udp_ports_comma_separated_ -oN nmap/udp_script_scan $ip' >> cmds;
	echo "\n\n" >> cmds;
	echo "#############" >> cmds;
	echo "\n\n" >> cmds;
	echo "#############" >> cmds;
	echo "\n\n\n" >> cmds;
	echo 'ffuf -u http://$ip/FUZZ -w $COMMON_DIRS -e .php,.txt,.html -t 500 -ic -rate 1000 -r -c | tee ffuf/common_dirs.txt' >> cmds;
	echo "\n\n\n" >> cmds;
	echo 'ffuf -u http://$ip/FUZZ -w $MEDIUM_DIRS -e .php,.txt,.html -t 500 -ic -rate 1000 -r -c | tee ffuf/medium_dirs.txt' >> cmds;
	echo "\n\n\n" >> cmds;
	echo 'ffuf -u http://builder.htb/ -w $SUBDOMAINS -H "Host: FUZZ.builder.htb" -t 500 -ic -rate 1000 -r -c -fw 1337 | tee ffuf/common_subdomains.txt' >> cmds;
}

function ssm(){
	searchsploit -m exploits/${1}
}

function nl(){
	cat ${1} | wc -l;
}

function fixbt(){
	sudo hciconfig hci0 down;
	sudo rmmod btusb;
	sudo modprobe btusb;
	sudo hciconfig hci0 up;
}

function al(){
        bluetoothctl trust 34:AF:B3:A7:1F:5A
        bluetoothctl disconnect
        bluetoothctl connect 34:AF:B3:A7:1F:5A
}

function sn(){
        bluetoothctl trust 94:DB:56:02:4C:5C
        bluetoothctl disconnect
        bluetoothctl connect 94:DB:56:02:4C:5C
}

function bs(){
        bluetoothctl trust FC:58:FA:C4:3F:A7
        bluetoothctl disconnect
        bluetoothctl connect FC:58:FA:C4:3F:A7
}


function b64d(){
	echo -n $1 | base64 --decode
}

function b64e(){
	echo -n $1 | base64 -w0
}


function lch() {
	    until [ $(curl -s 'https://onepiecechapters.com/mangas/5/one-piece' | grep -m 1 'one-piece-chapter' | cut -d '-' -f4 | cut -d '"' -f1) -eq ${1} ]; do echo "Chapter ${1} not out yet!!"; sleep 60; done; vlc "file:///home/shanks/Music/one_piece_bgm.m4a"
}

function datesbtw() {
    start_dt=$1
    end_dt=$2

    dt=$start_dt
    until [[ $dt > $end_dt ]]; do 
        echo "$dt"
        dt=$(date -I -d "$dt + 1 day")
    done
}

# Set Burp Proxy
function sbp(){
	HTTP_PROXY_HOST="127.0.0.1";
	HTTP_PROXY_PORT="8080";

	HTTPS_PROXY_HOST="127.0.0.1";
	HTTPS_PROXY_PORT="8080";

	gsettings set org.gnome.system.proxy mode manual;
	gsettings set org.gnome.system.proxy.http host "$HTTP_PROXY_HOST";
	gsettings set org.gnome.system.proxy.http port "$HTTP_PROXY_PORT";
	gsettings set org.gnome.system.proxy.https host "$HTTPS_PROXY_HOST";
	gsettings set org.gnome.system.proxy.https port "$HTTPS_PROXY_PORT";
}

# Unset Burp Proxy
function ubp(){
	gsettings set org.gnome.system.proxy mode none;
}

# Full Update - packages + firmware
function fup() {
    sudo apt update;
    sudo apt upgrade;
    sudo apt dist-upgrade;
    sudo apt autoremove;
    sudo apt autoclean;
    sudo fwupdmgr get-devices;
    sudo fwupdmgr get-updates;
    sudo fwupdmgr update;
}



