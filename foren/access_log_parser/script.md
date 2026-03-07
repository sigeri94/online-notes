```bash
 (zcat access.log*.gz 2>/dev/null; cat access.log.1 access.log 2>/dev/null) | awk -F\" '
BEGIN{
month["Jan"]="01";month["Feb"]="02";month["Mar"]="03";month["Apr"]="04";
month["May"]="05";month["Jun"]="06";month["Jul"]="07";month["Aug"]="08";
month["Sep"]="09";month["Oct"]="10";month["Nov"]="11";month["Dec"]="12";
}
{
    agent=$6

    split($1,a,"[")
    split(a[2],b,":")
    split(b[1],d,"/")

    day=d[3] "-" month[d[2]] "-" d[1]

    key=day SUBSEP agent
    count[key]++
}
END{
    for(k in count){
        split(k,v,SUBSEP)
        printf "%s\t%d\t%s\n", v[1], count[k], v[2]
    }
}' | sort -k1,1 -k2,2nr | grep -v Mozilla > useragent.txt
```
```bash
(zcat access.log*.gz 2>/dev/null; cat access.log.1 access.log 2>/dev/null) | awk -F\" '
BEGIN{
month["Jan"]="01";month["Feb"]="02";month["Mar"]="03";month["Apr"]="04";
month["May"]="05";month["Jun"]="06";month["Jul"]="07";month["Aug"]="08";
month["Sep"]="09";month["Oct"]="10";month["Nov"]="11";month["Dec"]="12";
}
{
    referer=$4

    split($1,a,"[")
    split(a[2],b,":")
    split(b[1],d,"/")

    day=d[3] "-" month[d[2]] "-" d[1]

    key=day SUBSEP referer
    count[key]++
}
END{
    for(k in count){
        split(k,v,SUBSEP)
        printf "%s\t%d\t%s\n", v[1], count[k], v[2]
    }
}' | sort -k1,1 -k2,2nr | egrep -v 'google.com|192.168.99.86|udara.com' > refer.txt
```
```bash

(zcat access.log*.gz 2>/dev/null; cat access.log.1 access.log 2>/dev/null) | \
awk '
BEGIN{
month["Jan"]="01";month["Feb"]="02";month["Mar"]="03";month["Apr"]="04";
month["May"]="05";month["Jun"]="06";month["Jul"]="07";month["Aug"]="08";
month["Sep"]="09";month["Oct"]="10";month["Nov"]="11";month["Dec"]="12";
}
{
    split($4,a,":")
    date=substr(a[1],2)
    split(date,b,"/")

    day=b[3]"-"month[b[2]]"-"b[1]

    bytes=$10
    if(bytes=="-") bytes=0

    total[day]+=bytes
}
END{
    for(d in total){
        printf "%s\t%.2f GB\n", d, total[d]/1024/1024/1024
    }
}' | sort > down.txt

```
```bash

(zcat access.log*.gz 2>/dev/null; cat access.log.1 access.log 2>/dev/null) | \
awk '
BEGIN{
month["Jan"]="01";month["Feb"]="02";month["Mar"]="03";month["Apr"]="04";
month["May"]="05";month["Jun"]="06";month["Jul"]="07";month["Aug"]="08";
month["Sep"]="09";month["Oct"]="10";month["Nov"]="11";month["Dec"]="12";
}
{
    split($4,a,":")
    date=substr(a[1],2)
    split(date,b,"/")
    day=b[3]"-"month[b[2]]"-"b[1]

    url=$7
    split(url,u,"?")
    path=u[1]

    bytes=$10
    if(bytes=="-") bytes=0

    key=day "|" path
    total[key]+=bytes
}
END{
    for(k in total){
        split(k,v,"|")
        printf "%s\t%.2f\t%s\n", v[1], total[k]/1024/1024, v[2]
    }
}' | sort -k1,1 -k2,2nr | \
awk '
{
day=$1
mb=$2
url=$3

if(day!=prev){
    if(prev!="") print ""
    print "Tanggal:",day
    n=0
}

if(n<5){
    printf "%10.2f MB  %s\n", mb, url
    n++
}

prev=day
}' > down_file.txt

```

