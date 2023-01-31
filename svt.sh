
# Simple Bash script for VirusTotal V3


v_file () {
    FILE=$OPTARG
    curl -s --request POST --url "https://www.virustotal.com/api/v3/files" --header "x-apikey: ${APIKEY}" --form "file=@$FILE"
}

v_large () {
    FILE=$OPTARG
    URL=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/files/upload_url" --header "x-apikey: $APIKEY" | grep -o '"data": ".*"' test.json | cut -d " " -f2 | tr -d '\"')
    curl -s --request POST --url "$URL" --header "x-apikey: $APIKEY" --form "file=@$FILE"
}
v_url () {
    URL=$OPTARG
    curl --request POST --url https://www.virustotal.com/api/v3/urls --form url=$URL --header "x-apikey: ${APIKEY}"
}

v_hash () {
    HASH=$OPTARG
    curl --request GET --url https://www.virustotal.com/api/v3/files/{$HASH} --header "x-apikey: ${APIKEY}"
}

v_ip () {
    IP=$OPTARG
    curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/{$IP} --header "x-apikey: ${APIKEY}"
}

key_check () {
    if [[ $OPTARG =~ [0-9a-z]{64} ]];
    then
        APIKEY=$OPTARG
    else 
        echo "Invalid API key."
        exit 2 
    fi
}

info () {
    echo "Bash Script to work with VirusTotal API V3"
    echo -ne "Usage example: ./svt.sh -k <API TOKEN> -f <FILE PATH>\n\n"
    echo -ne "\t-h\t\tDisplay help text.\n"
    echo -ne "\t-k\t\tAPI Key.\n"
    echo -ne "\t-f\t\tFull path to a file or scan.\n"
    echo -ne "\t-l\t\tFull path to a large file ( >32 Mb ) for scan.\n"
    echo -ne "\t-s\t\tHash of a file for scan.\n"
    echo -ne "\t-i\t\tIP address of a server for scan.\n"
    echo -ne "\t-u\t\tURL of a site for scan.\n\n"
}


while getopts "f:l:u:s:i:k:h" FLAG; do 
case $FLAG in

    f) # File 
        v_file $OPTARG
        exit 0
        ;;
    l) # Large Files
        v_large $OPTARG
        exit 0
        ;;
    u) # URL t
        v_url $OPTARG
        exit 0
        ;;
    s) # Hash
        v_hash $OPTARG
        exit 0
        ;;
    i) # IP address
        v_ip $OPTARG
        exit 0
        ;;
    k) #API key
        key_check $OPTARG
        ;;
    h | * ) # Information message
        info 
        exit 0
        ;;

esac
done

info 
