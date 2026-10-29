# keystore-certificate-updater

## Command Sample
<pre>sudo java -jar keystore-certificate-updater-0.0.1-SNAPSHOT.jar url=https://mvnrepository.com keyStore=/etc/ssl/certs/java/cacerts password=c******t</pre>
### Output Sample (Add)
<pre>URL                 =https://mvnrepository.com
Certificate(SHA-256)=e331d797babb14784ee512669a192efdcccb79b4c1a5168f116ed533fc0a3408
keyStore            =/etc/ssl/certs/java/cacerts
alias               =mvnrepository.com_20260906_20261205
Certificate is added in keystore /etc/ssl/certs/java/cacerts</pre>
### Output Sample (Found)
<pre>URL                 =https://mvnrepository.com
Certificate(SHA-256)=e331d797babb14784ee512669a192efdcccb79b4c1a5168f116ed533fc0a3408
keyStore            =/etc/ssl/certs/java/cacerts
Certificate is found in keystore /etc/ssl/certs/java/cacerts</pre>
