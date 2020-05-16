traefik plugins

```shell
$ mysql -u admin -h  mysql.api.local -padmin --skip-ssl
```


```sql
CREATE TABLE admin.users (
	id INT auto_increment NOT NULL PRIMARY KEY,
	name varchar(100) NULL,
	email varchar(100) NULL
)
ENGINE=InnoDB
DEFAULT CHARSET=latin5
COLLATE=latin5_turkish_ci;

```


inside traefik container
```shell
$ wget http://percona.com/get/percona-toolkit.tar.gz
$ apk update && \
    apk add perl perl-dbd-mysql && \
   apk add --virtual=build make && \
   tar zxf /percona-toolkit.tar.gz && \
   ( \
     cd percona-toolkit-* && \
     perl Makefile.PL && \
     make && \
     make install \
   ) && \
   rm -rf percona-toolkit* && \
   apk del --purge build


tcpdump -x -nn -q -tttt -i any -c 1000 port 3306 and host traefik-mysql-proxy_mysql_1.traefik-mysql-proxy_traefik > mysql.tcp.txt

pt-query-digest --type tcpdump mysql.tcp.txt

```

tcpdum inside traefik to monitor msyql 
```
$ tcpdump -i eth0 -s 0 -A port 3306 and host traefik-mysql-proxy_mysql_1.traefik-mysql-proxy_traefik

# -i: interface
# -X: show content as hexadecimal
# -w: capture file to output
# -A: show content as ASCII
# see more on https://danielmiessler.com/study/tcpdump/
``` 


```shell
watch "mysql -u admin -h  mysql.api.local -padmin --skip-ssl -e 'select * from admin.users;' "
```

or using tshark
