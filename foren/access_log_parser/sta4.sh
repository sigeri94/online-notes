(zcat access.log*.gz 2>/dev/null; cat access.log.1 access.log 2>/dev/null) | \
awk '
BEGIN{
month["Jan"]="01";month["Feb"]="02";month["Mar"]="03";month["Apr"]="04";
month["May"]="05";month["Jun"]="06";month["Jul"]="07";month["Aug"]="08";
month["Sep"]="09";month["Oct"]="10";month["Nov"]="11";month["Dec"]="12";
}

$9==200 {
    url=$7

    split(url,u,"?")
    path=u[1]

    if(path ~ /\.(css|js|pdf|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map)$/) next

    split($4,a,":")
    date=substr(a[1],2)
    split(date,b,"/")

    ymd=b[3]"-"month[b[2]]"-"b[1]

    key=ymd" "path
    count[key]++
}

END{
    for(k in count){
        split(k,v," ")
        printf "%s %s %d\n", v[1], v[2], count[k]
    }
}' | sort -k1,1 -k3,3nr | \
awk '
{
day=$1
if(day!=prev){
    if(prev!="") print ""
    print "Tanggal:",day
    i=0
}
if(i<5){
    printf "%-60s %s\n",$2,$3
    i++
}
prev=day
}'
