# A mysql traefik proxy
This poc is a study of how traefik can be used as a mysql proxy
and the observation os mysql packages can be used to provida a mechanism
of replication data when binary mysql log is not disponible.

# envronment
	- has used mysql 5.7
	- ssl has disabled in connection
	- nodejs v8.17.0 

# run
```shell
$ docker-compose up
```

# try
disable ssl: this poc not cover ssl encryptation
```shell
$ mysql -u admin -h  mysql.api.local -padmin --skip-ssl --compression-algorithms=uncompressed
```

run your sql commands
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



```shell
$ mysql -u admin -h  mysql.api.local -padmin ---compression-algorithms=uncompressed --skip-ssl -e 'select * from admin.users;'
$ watch "mysql -u admin -h  mysql.api.local -padmin ---compression-algorithms=uncompressed --skip-ssl -e 'select * from admin.users;'"
```


## observe
in app dir, has one node app that capture network package from a desired interface, it is a playground, it s incomplete. The idea is study. 
