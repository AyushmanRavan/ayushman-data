#!/bin/bash
# https://www.modb.pro/db/324536
# https://www.server-world.info/en/note?os=CentOS_Stream_8&p=elasticstack7&f=12

# 9200: This is used to create HTTP connections
# 9300: This is used to create a TCP connection through a JAVA client and the node's interconnection inside a cluster

# Elasticsearch has two levels of communications,https://www.golinuxcloud.com/enable-https-ssl-secure-elasticsearch-linux/
# ----------------------------------------------------------------------
# A) Transport Communications: The transport protocol is used for internal communications between Elasticsearch nodes,
    #  xpack.security.transport.ssl: communication between nodes
# B) HTTP Communications:  HTTP protocol is used for communications from clients to the Elasticsearch cluster.
    #  xpack.security.http.ssl: communication with clients

# Also note that for each of these networks we configure the following:
# ===========================================================================
# 1) Certificate verification type (verification_mode)
# 2) The certificate itself (certificate)
# 3) The certificate key (key)
# The complete chain of certificates up to the Certificate Authority (certificate_authorities)


# Keep in mind that the token-based authentication requires an HTTPS connection to ElasticSearch.
#https://www.securitynik.com/2022/04/installing-configuring-elasticsearch-8.html

sudo apt -y install openjdk-11-jdk
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
# echo "export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64" >> /root/.bashrc
# echo "export PATH=/usr/lib/jvm/java-11-openjdk-amd64/bin/:$PATH" >> /root/.bashrc

#Download and install the PGP Key using wget command.
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

#Install the apt-transport-https package
sudo apt install apt-transport-https -y

#to add the Elasticsearch repository to the system
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Update apt package before installing Elasticsearch
sudo apt update -y && sudo apt install elasticsearch -y

# sudo cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.ORIGINAL
# sudo cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.ORIGINAL

sudo cp /etc/elasticsearch/elasticsearch.yml.ORIGINAL /etc/elasticsearch/elasticsearch.yml

# Add path to environment
# echo "export PATH=/usr/share/elasticsearch/bin/:$PATH" >> /root/.bashrc


# Without comment lines, this is how the default Elasticsearch 8.0 configuration looks like.
# grep -Ev '^#|^$' /etc/elasticsearch/elasticsearch.yml

sudo systemctl daemon-reload
sudo systemctl enable --now elasticsearch.service
sudo systemctl start elasticsearch.service
sudo systemctl status elasticsearch.service

#  verify ES status using curl command.
# curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic:PASSWORD https://localhost:9200

#  imp :: https://medium.com/devops-dudes/elasticsearch-8-x-deployment-ac990b9e4c56
# https://juejin.cn/post/7084963931718402078#heading-6
# https://www.jentsch.io/spring-boot-elasticsearch-java-api-client-demo-application/
# https://www.pixeltrice.com/spring-boot-elasticsearch-crud-example/
# https://www.cnblogs.com/xxyopen/p/16329099.html
# https://techblog.zozo.com/entry/elasticsearch-java
# https://tech.groww.in/simple-search-service-using-springboot-and-elasticsearch-2-e8e856c7bc8f
# https://blog.arcoptimizer.com/spring-boot-avec-java-api-client-pour-creer-et-executer-des-requetes-dans-elasticsearch
# https://www.skyer9.pe.kr/wordpress/?p=5655
# https://levelup.gitconnected.com/elasticsearch-with-java-41daeda3e6b1
# https://blogs.perficient.com/2022/08/22/elasticsearch-java-api-client-springboot/
# https://medium.com/devops-dudes/elasticsearch-8-x-deployment-ac990b9e4c56
# https://www.gooksu.com/2022/08/install-elasticsearch-using-enrollment-tokens/
# https://blog.pythian.com/how-to-secure-your-elastic-stack-plus-kibana-logstash-and-beats/
# https://kifarunix.com/install-elk-stack-8-x-on-ubuntu/
# https://www.devopsschool.com/blog/how-to-install-kibana-8-x-and-configure-with-elasticsearch-8-x/
# https://alexmarquardt.com/2018/11/05/security-tls-ssl-pki-authentication-in-elasticsearch/
# https://www.allerstorfer.at/elasticsearch-8/
# https://kifarunix.com/install-elk-stack-8-x-on-ubuntu/
# https://www.golinuxcloud.com/install-configure-kibana-https-elasticsearch/

# https://praveeng-nair.medium.com/quick-find-unused-maven-dependencies-c32ece492709



# http_ca.crt: This is the self-signed ca certificate for elastic search
# http.p12: This is the certificate that is used to encrypt client communication such as communication between Kibana and elastic search.
# transport.p12: This is the certificate that is used to encrypt cluster communications.

# During the installation, the Security features will be enabled by default;
# -------------------------------------------------------------------------------------
# Authentication and authorization are enabled.
# TLS for the transport and HTTP layers is enabled and configured.
# Elastic super user account (elastic) and its password is created.

# First, you can see x-pack security is enabled by default using this line in the elasticsearch.yml file, 
# you can also see that security enrollments are enabled as well
# ------------------------------------------------------------
# xpack.security.enabled: true
# xpack.security.enrollment.enabled: true


# Secondly, you will see that is certificates to be used for encryption with API clients such as Kibana, Logstash, are stored in http.p12 file
# ----------------------------------------------------------------------
# xpack.security.http.ssl:
#  enabled: true
#  keystore.path: certs/http.p12


# Thirdly, the following code instructs the system that cluster communication is encrypted and the relevant certificates can be found in certs/transport.p12
# ---------------------------------------------------------------------------
# xpack.security.transport.ssl:
#  enabled: true
#  verification_mode: certificate
#  keystore.path: certs/transport.p12
#  truststore.path: certs/transport.p12



# Next, we provide a static set of initial master nodes which is by default only this node but if you are 
# setting up a cluster you will edit this entry to include other initial master nodes.
# ---------------------------------------------------------
# cluster.initial_master_nodes: [“elk-1”]


# Lastly, we specify which networks are HTTP and cluster communication allowed on
# -------------------------------------------------------
# Allow HTTP API connections from localhost and local networks
# Connections are encrypted and require user authentication
# http.host: [_local_, _site_]
# Allow other nodes to join the cluster from localhost and local networks
# Connections are encrypted and mutually authenticated
# transport.host: [_local_, _site_]


# Validate Elasticsearch cluster health
# --------------------------------------------------
# curl -k -u elastic:<password> https://localhost:9200/_cluster/health?pretty 
## -k to ignore ssl verification, if you are providing enterprise certificates you can remove it.




# https://www.devopsschool.com/blog/how-to-install-kibana-8-x-and-configure-with-elasticsearch-8-x/

# How to generate serviceAccountToken for kibana aka serviceAccountToken in elasticsearch server?
# -------------------------------------------------------------------------
# ./elasticsearch-service-tokens create elastic/kibana my-token


# How to generate enrollment token?
# -----------------------------------------------
# $ ./elasticsearch-create-enrollment-token -s kibana


# How to register kibana with elasticsearch using enrollment token?
# -----------------------------------------------------------------
# $ ./kibana-setup --enrollment-token <enrollment-token>

# We can choose auto or interactive mode while executing it! The auto will generate all users’ passwords automatically but the interactive mode prompts you to enter passwords.
# bin/elasticsearch-setup-passwords interactive|auto   // 

# curl -XGET --cacert /home/elastic/elasticsearch-8.4.2/config/certs/http_ca.crt -u elastic:D+oYlbieuG3n2=EpiKU6 'https://192.68.1.2:9200/rajesh111/_search?pretty=true&q=*:*'









































# https://techexpert.tips/elasticsearch/elasticsearch-enable-tls-https/
# Elasticsearch comes with a utility called elasticsearch-certutil that can be used for generating self signed certificates that can be used to secure elasticsearch for encrypting internal communications within an Elasticsearch cluster.

# On an Elasticsearch Master Node in Cluster, Generate CA and Certificate.

# Create a self-signed certificate authority(CA). 
# =====================================================In our example, no password was set.========
# /usr/share/elasticsearch/bin/elasticsearch-certutil ca
# Please enter the desired output file [elastic-stack-ca.p12]: -> [ENTER]
# Enter password for elastic-stack-ca.p12 :

# Note: Certificate saved in: /usr/share/elasticsearch/elastic-stack-ca.p12 -> Default P12
# Important: If ELK stack has more than one node, scp elastic-stack-ca.p12 to all the remaining nodes.
# scp /usr/share/elasticsearch/elastic-stack-ca.p12 root@node2:/usr/share/elasticsearch/                           ///// scp -r /opt/certs root@node2:/opt

# Create a certificate for the ElasticSearch node.(node certificate, node key, and CA certificate)
# ====This activity is performed from the master node only============In our example, no password was set.========
# /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca elastic-stack-ca.p12

# Copy the certificates to the proper directory and set the correct permissions. 
# ======================================================================================
# cp /usr/share/elasticsearch/elastic-certificates.p12 /etc/elasticsearch/
# chown root.elasticsearch /etc/elasticsearch/elastic-certificates.p12
# chmod 660 /etc/elasticsearch/elastic-certificates.p12


# Create a certificate to enable HTTPS communication.
# ======================================================In our example, no password, no DNS, and no IP addresses were set.=======
# /usr/share/elasticsearch/bin/elasticsearch-certutil http


# In our example, we used the self-signed certificate authority created before.
# Copy the certificates to the proper directory and set the correct permissions.
# cd /usr/share/elasticsearch
# unzip elasticsearch-ssl-http.zip
# cp  /usr/share/elasticsearch/elasticsearch/http.p12 /etc/elasticsearch/
# chown root.elasticsearch /etc/elasticsearch/http.p12
# chmod 660 /etc/elasticsearch/http.p12


# vim /etc/elasticsearch/elasticsearch.yml
# =======================================
# path.data: /var/lib/elasticsearch
# path.logs: /var/log/elasticsearch
# network.host: 0
# cluster.initial_master_nodes: elasticsearch.local
# 
# xpack.security.transport.ssl.enabled: true
# xpack.security.transport.ssl.verification_mode: certificate
# xpack.security.transport.ssl.keystore.path: elastic-certificates.p12
# xpack.security.transport.ssl.truststore.path: elastic-certificates.p12
# 
# xpack.security.authc.token.enabled: true   // only for Token-based authentication,instead of basic auth.
# xpack.security.http.ssl.enabled: true
# xpack.security.http.ssl.keystore.path: "http.p12"


# If we have secured the node’s certificate with a password while generating certificates, we should add the password to our Elasticsearch Keystore. 
# If the signed certificate is in PKCS#12 format, we can use the following commands:

# Add Password to ES KeyStore
# ================================================
# bin/elasticsearch-keystore add xpack.security.transport.ssl.keystore.secure_password
# bin/elasticsearch-keystore add xpack.security.transport.ssl.truststore.secure_password
# bin/elasticsearch-keystore add xpack.security.http.ssl.keystore.secure_password


# Note : Copy the self-signed certification authority certificate.
# =======================================================================
# cp /usr/share/elasticsearch/kibana/elasticsearch-ca.pem /etc/kibana/


# vim /etc/kibana/kibana.yml
# =================
# server.host: "0.0.0.0"
# elasticsearch.hosts: ["https://localhost:9200"]
# elasticsearch.username: "kibana"
# elasticsearch.password: "kibana123"
# elasticsearch.ssl.certificateAuthorities: [ "https://d1ny9casiyy5u5.cloudfront.net/etc/kibana/elasticsearch-ca.pem" ]
# elasticsearch.ssl.verificationMode: none


























































# 1) Create input yml file  =======================https://www.golinuxcloud.com/enable-https-ssl-secure-elasticsearch-linux/
# We will use a yml file as an input to generate self signed certificates to enable https configuration and secure elasticsearch. You can add more nodes based on your environment

# [root@server1 ~]# cat /tmp/instance.yml
# instances:
#   - name: 'server1'
#     dns: [ 'server1.example.com' ]
#     ip: [ '192.168.0.11' ]
#   - name: "server2"
#     dns: [ 'server2.example.com' ]
#     ip: [ '192.168.0.12' ]
#   - name: 'server3'
#     dns: [ 'server3.example.com' ]
#     ip: [ '192.168.0.13' ]
#   - name: 'centos-8'
#     dns: [ 'centos-8.example.com' ]
#     ip: [ '192.168.0.14' ]

# 2) Generate self signed certificate
# Here we will use elasticsearch-certutil to generate our own self signed certificate to secure elasticsearch. We will store these certificates under /tmp/certs. If the output directory does not exists, the elasticsearch-certutil tool will create the same.
# Navigate inside "/usr/share/elasticsearch/" where we have all the elasticsearch tools
# [root@server3 ~]# cd /usr/share/elasticsearch/
# [root@server3 elasticsearch]# bin/elasticsearch-certutil cert --keep-ca-key ca --pem --in /tmp/instance.yml --out /tmp/certs/certs.zip

# It is important
# that option --keep-ca-key is included here. If later you require to generate more certificates for
# additional nodes/beats (devices), you will need both the ca.crt and ca.key. 


# Next navigate inside the output directory /tmp/certs
# [root@server3 elasticsearch]# cd /tmp/certs/
# [root@server3 certs]# ls
# certs.zip

# Extract the certificates. You will need unzip utility to extract the certificates files
# [root@server1 certs]# unzip certs.zip

# 3) Place the certificates
# Next to enable HTTPS configuration we will create certs directory inside /etc/elasticsearch/ on all the cluster nodes to store the self signed certificates

# [root@server1 ~]# mkdir -p /etc/elasticsearch/certs
# [root@server2 ~]# mkdir -p /etc/elasticsearch/certs
# [root@server3 ~]# mkdir -p /etc/elasticsearch/certs
# [root@centos-8 ~]# mkdir -p /etc/kibana/certs
# Copy the applicable certificate file to /etc/elasticsearch/certs directory on the localhost which in our case is server1

# [root@server1 ~]# cp /tmp/certs/ca/ca.crt /tmp/certs/server1/* /etc/elasticsearch/certs
# Verify the list of files and permissions on these certificate files

# [root@server1 certs]# ls -l /etc/elasticsearch/certs
# total 20
# -rw-r--r--. 1 root elasticsearch 1200 Dec 24 22:25 ca.crt
# -rw-r--r--. 1 root elasticsearch 1196 Dec 24 22:24 server1.crt
# -rw-r--r--. 1 root elasticsearch 1675 Dec 24 22:24 server1.key
# Next copy these certificates to all the elasticsearch cluster nodes in the same location under /etc/elasticsearch/certs and under /etc/kibana/certs on centos-8

# [root@server1 ~]# scp -r /tmp/certs/ca/ca.crt /tmp/certs/server2/* server2:/etc/elasticsearch/certs/
# [root@server1 ~]# scp -r /tmp/certs/ca/ca.crt /tmp/certs/server3/* server3:/etc/elasticsearch/certs/
# [root@server1 ~]# scp -r /tmp/certs/ca/ca.crt /tmp/certs/centos-8/centos-8.* centos-8:/etc/kibana/certs/



# 4) Enable authentication to secure Elasticsearch
# Set xpack.security.enabled to true in elasticsearch.yml of all the elasticsearch cluster nodes to secure elasticsearch and force a custom user authentication for processing any request.
# xpack.security.enabled: true

# 5) Enable SSL/TLS to encrypt communication between cluster nodes
# The transport protocol is used for communication between nodes to secure Elasticsearch cluster. Because each node in an Elasticsearch cluster is both a client and a server to other nodes in the cluster, all transport certificates must be both client and server certificates.

# xpack.security.transport.ssl.enabled: true
# xpack.security.transport.ssl.key: certs/server1.key
# xpack.security.transport.ssl.certificate: certs/server1.crt
# xpack.security.transport.ssl.certificate_authorities: [ "certs/ca.crt" ]


# 6) Enable HTTPS configuration to encrypt HTTP Client Communications
# When security features are enabled, you can optionally use TLS to enable HTTPS configuration and to ensure that communication between HTTP clients and the cluster is encrypted.

# NOTE: Enabling TLS on the HTTP layer is strongly recommended but is not required. If you enable TLS on the HTTP layer in Elasticsearch, then you might need to make configuration changes in other parts of the Elastic Stack and in any Elasticsearch clients that you use
# xpack.security.http.ssl.enabled: true
# xpack.security.http.ssl.key: certs/server1.key
# xpack.security.http.ssl.certificate: certs/server1.crt
# xpack.security.http.ssl.certificate_authorities: certs/ca.crt

# 7) Restart Elasticsearch Cluster services
# You must perform a full cluster restart to enable HTTPS configuration and secure elasticsearch cluster. Nodes which are configured to use TLS cannot communicate with nodes that are using unencrypted networking (and vice-versa). After enabling TLS you must restart all nodes in order to maintain communication across the cluster.












# https://handlers.sans.edu/gbruneau/elk/TLS_elasticsearch_configuration.pdf
# /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca-cert /opt/certs/ca/ca.crt --ca-key /opt/certs/ca/ca.key --in /opt/certs1/instance.yml --out /opt/certs1/certs.zip
# /var/lib/elasticsearch → Default Elasticsearch database location
# /dev/sdb1 → Suggests minimum of 250 GB for elasticsearch database













































# vim /etc/elasticsearch/elasticsearch.yml
# =======================================
# cluster.name: mycluster
# node.name: node01
# network.host: [ _eth0_, _local_ ]
# discovery.seed_hosts: elastic02.mycompany.com, elastic03.mycompany.com               //Provides a list of master-eligible nodes in the cluster.
# cluster.initial_master_nodes: node01, node02, node03

# xpack.security.enabled: true
# xpack.security.transport.ssl.enabled: true
# xpack.security.transport.ssl.verification_mode: certificate
# xpack.security.transport.ssl.key: /etc/elasticsearch/config/certs/elastic01.mycompany.com/privkey1.pem
# xpack.security.transport.ssl.certificate: /etc/elasticsearch/config/certs/elastic01.mycompany.com/cert1.pem
# xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/config/certs/elastic01.mycompany.com/fullchain1.pem" ]

# xpack.security.http.ssl.enabled: true
# xpack.security.http.ssl.verification_mode: certificate
# xpack.security.http.ssl.key: /etc/elasticsearch/config/certs/elastic01.mycompany.com/privkey1.pem
# xpack.security.http.ssl.certificate: /etc/elasticsearch/config/certs/elastic01.mycompany.com/cert1.pem


# Just remember that you must have already copied the certificate files generated by Certbot to the Kibana settings directory, in a similar way as was done for Elasticsearch.
# vim /etc/kibana/kibana.yml
# =================
# server.host: kibana.mycompany.com
# server.port: 5601
# server.name: "dlp.srv.world"

# elasticsearch.hosts: [ "https://elastic01.mycompany.com:9200", "https://elastic02.mycompany.com:9200", "https://elastic03.mycompany.com:9200" ]
# elasticsearch.username: "kibana_system"
# elasticsearch.password: "password"
# elasticsearch.ssl.certificateAuthorities: [ "https://d1ny9casiyy5u5.cloudfront.net/etc/kibana/elasticsearch-ca.pem" ]   ///specify a list of paths to the PEM file for the certificate authority for your Elasticsearch instance.
# elasticsearch.ssl.verificationMode: none      /// Valid values are none, certificate, and full. full performs hostname verification, and certificate does not.

# server.ssl.enabled: true
# server.ssl.certificate: /etc/kibana/config/certs/kibana.mycompany.com/fullchain.pem   ///Paths to the PEM-format SSL certificate.
# server.ssl.key: /etc/kibana/config/certs/kibana.mycompany.com/privkey.pem             ///Paths to the SSL key file.


# server.ssl.enabled: Enables SSL for outgoing requests from the Kibana server to the browser. When set to true, server.ssl.certificate and server.ssl.key are required.
# server.ssl.certificate and server.ssl.key: Paths to the PEM-format SSL certificate and SSL key files, respectively.
# elasticsearch.ssl.certificateAuthorities: Optional setting that enables you to specify a list of paths to the PEM file for the certificate authority for your Elasticsearch instance.
# elasticsearch.ssl.verificationMode: Controls the verification of certificates presented by Elasticsearch. Valid values are none, certificate, and full. full performs hostname verification, and certificate does not.


# [root@centos-8 ~]# journalctl -u kibana.service
# Or to monitor live logs using journalctl
# [root@centos-8 ~]# journalctl -u kibana.service -f













































































# 1) Secure Communications Inside An ElasticSearch Cluster
# 2) Create Certificate Authority
# 3) Generate Node Certificates
# 4) Transfer Node Certificates
# 5) Update Keystore And Truststore
# 6) Enable TLS

# https://kifarunix.com/enable-https-connection-between-elasticsearch-nodes/
# **** Generate private key and X.509 certificate for each node
# Commands are provided in the Elasticsearch program elasticsearch-certutilto simplify the process of generating certificates.

# There are 3 modes of this command:

# 1) CA mode, used to generate a new certificate authority.
# 2) CERT mode for generating X.509 certificates and private keys.
# 3) CSR mode, used to generate a certificate signing request that points to a trusted certificate authority for a signed certificate. Signing certificates must be in PEM or PKCS#12 format to be used with Elasticsearch security features.

# Term	         Description
# X.509	         X.509 is a standard defining the format of public key certificates.
#                An X.509 certificate contains a public key and an identity (a hostname, or an organization, or an individual), and is either signed by a certificate authority or self-signed.
# CA	         Certificate authority(CA) is an entity that issues digital certificates.
#                A CA acts as a trusted third party—trusted both by the subject (owner) of the certificate and by the party relying upon the certificate.

# There are two formats in which you can generate X.509 certificates, namely, PEM and PKCS12.
# PEM	    Container format that includes an entire certificate chain including public key, private key, and root certificates.
# PKCS12	Passworded container format that contains both public and private certificate pairs. Unlike .pem files, this container is fully encrypted.

# Each instance has a single PKCS#12 (.p12) file containing the instance certificate, instance private key and the CA certificate.


# *****************************************************************************************************
# ************Encrypting communications between nodes in a cluster*************************************
# *****************************************************************************************************
# Step One:) Create Certificate Authority (PKCS#12 (.p12))
# *****************************************************************************************************
# Generate CA in PKCS#12 (.p12) format: (generates a CA certificate and private key)(default file elastic-stack-ca.p12)
# ======================================================================================================= [name]-ca.p12
# /usr/share/elasticsearch/bin/elasticsearch-certutil ca --out /etc/elasticsearch/certs/elk-ca.p12 --days 3650
#  OR  
# /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pass [password] --out /etc/elasticsearch/certs/[name]-ca.p12 --days 3650 --ca-dn CN="[Distinguished Name]"
# --ca-dn <name>: Defines the Distinguished Name (DN) used for the generated CA certificate. The default value is CN="Elastic Certificate Tool Autogenerated CA".

# If you had generated the certificate in PKCS12 format, you can view the certificate output like expiration date, common name, issuer by running below command (You will prompted for the password which you had provided earlier for generating the certificate).
# $ openssl pkcs12 -info -in elastic-stack-ca.p12

# Step Two:) Generate Node Certificates (PKCS#12 (.p12))
# Now, we can generate certificates for each of the nodes in our cluster using the CA authority which we had created earlier.
# *****************************************************************************************************
# Generate the certificates in PKCS#12 format: (a certificate, private key and the CA certificate)
# =======================================================================================================
#  It also prompts for the CA password, if you set the password above, and the certificate password.
# /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca /etc/elasticsearch/certs/elk-ca.p12 --out /etc/elasticsearch/certs/elk-cert.p12 --days 3650
# OR
# Issue 1 certificate and key:
# /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca /etc/elasticsearch/certs/[CA 证书名称].p12 --ca-pass [CA 证书密码] --out /etc/elasticsearch/certs/node-01.p12 --name node-01 --pass "" --days 3650 --ip 192.168.1.198
# The command to issue node certificates in batches:
# /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca [CA 证书] --ca-pass [CA 证书密码] --in /etc/elasticsearch/certs/instances.yml --out /etc/elasticsearch/certs/instances.zip --pass "" --days 3650

# Enable Elasticsearch Security Features (/etc/elasticsearch/elasticsearch.yml)
# Enable HTTPS Connection Between Elasticsearch Nodes
# If you used the PKCS#12 format, enter the following lines in elasticsearch.yml file on every node in Elasticsearch.
# =======================================================================================================
# xpack.security.enabled: true
# xpack.security.transport.ssl.enabled: true
# xpack.security.transport.ssl.verification_mode: certificate 
# xpack.security.transport.ssl.keystore.path: certs/elk-cert.p12 
# xpack.security.transport.ssl.truststore.path: certs/elk-cert.p12

# Step Three:) Add Certificate Password to Elasticsearch Keystore
# If you secured your node certificate with a password, add the password to your Elasticsearch keystore on all the cluster nodes.
# If you used the certificates in PKCS#12 format, run the commands below to add the certificate password to the keystore:
# =======================================================================================================
# /usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.transport.ssl.truststore.secure_password
# /usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.transport.ssl.keystore.secure_password





# Step One:) Create Certificate Authority (.pem)
# *****************************************************************************************************
# Generate CA in PEM (.pem) format: (generates a zip file containing individual files for the CA certificate and private key)
# =======================================================================================================
# /usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --out /etc/elasticsearch/certs/elk-ca.zip --days 3650

# Note: If you plan to add more nodes to your cluster in the future, retain a copy of the file and remember its password (if you provided one).
# If you had generated the certificate in PEM format, unzip the files.
# You can use OpenSSL to view the certificate output like expiration date, common name, issuer.
# $ openssl x509 -text -noout -in ca/ca.crt


# Step Two:) Generate Node Certificates (.pem)
# *****************************************************************************************************
# Generate the certificates in PEM format:
# Unzip the CA cert and key files;
# unzip /etc/elasticsearch/certs/elk-ca.zip -d /etc/elasticsearch/certs/

# 1) Next, generate the certificates in PEM format;
# /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca-cert /etc/elasticsearch/certs/ca/ca.crt --ca-key /etc/elasticsearch/certs/ca/ca.key --days 3650 --out /etc/elasticsearch/certs/elk-cert.zip
# 2) Unzip the CA cert and key files;(Distribute elk-ca.zip File to all other Devices)
# unzip /etc/elasticsearch/certs/elk-ca.zip -d /etc/elasticsearch/certs/
# 3) Set the ownership of the certificate files to elasticsearch user.
# chown -R elasticsearch: /etc/elasticsearch/certs/

# Enable Elasticsearch Security Features (/etc/elasticsearch/elasticsearch.yml)
# Enable HTTPS Connection Between Elasticsearch Nodes
# If you are using the PEM files, then enter the lines below in elasticsearch.yml file on every node in Elasticsearch.
# =======================================================================================================
# xpack.security.enabled: true
# xpack.security.transport.ssl.enabled: true
# xpack.security.transport.ssl.verification_mode: certificate
# xpack.security.transport.ssl.key: certs/node01/node01.key
# xpack.security.transport.ssl.certificate: certs/node01/node01.crt
# xpack.security.transport.ssl.certificate_authorities: certs/ca/ca.crt


# Step Three:) Add Certificate Password to Elasticsearch Keystore
# If you secured your node certificate with a password, add the password to your Elasticsearch keystore on all the cluster nodes.
# If you used the certificates in PEM format, use the command below to add the certificate key to keystore:
# =======================================================================================================
# /usr/share/elasticsearch/bin/elasticsearch-keystore add xpack.security.transport.ssl.secure_key_passphrase


# Restart Elasticsearch
# Next, restart Elasticsearch service to effect the changes;
# systemctl restart elasticsearch

# Create Passwords for Built-in Elastic Users
# /usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive|auto
# /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic --interactive|auto
# /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana-system --interactive|auto


# In most cases, we will be using the passwords for elastic and kibana_system users.
# =======================================================================================================
# elastic is a built-in superuser in Elastic stack.
# kibana_system is the user Kibana uses to connect and communicate with Elasticsearch.

# For example, you can now specify the username in the curl command ran above.
# curl -XGET es-node-01.kifarunix-demo.com:9200/_cat/nodes?pretty --cacert /etc/elasticsearch/certs/elk-ca.p12 -u elastic
# Enter the password generated above for elastic user.


# *****************************************************************************************************
# **************************Encrypting HTTP client communications**************************************
# *****************************************************************************************************
# Step One:) If you have not done so already, generate node certificates.
# # *************************************************************************
# bin/elasticsearch-certutil http                     //////This command generates a zip file that contains certificates and keys for use in Elasticsearch and Kibana.

# Step Two:) If the certificates are in PKCS#12 format:
# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& ${node.name}.p12
# xpack.security.http.ssl.enabled: true
# xpack.security.http.ssl.keystore.path: "http.p12"
# xpack.security.http.ssl.truststore.path: "http.p12"

# Step Three:) If you secured the keystore or the private key with a password, add that password to a secure setting in Elasticsearch.
# If the certificates are in PKCS#12 format:
# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
# bin/elasticsearch-keystore add xpack.security.http.ssl.keystore.secure_password
# bin/elasticsearch-keystore add xpack.security.http.ssl.truststore.secure_password




# Step Two:) If you have certificates in PEM format:
# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& 
# xpack.security.http.ssl.enabled: true
# xpack.security.http.ssl.key:  certs/node01/node01_http.key 
# xpack.security.http.ssl.certificate: certs/node01/node01_http.crt 
# xpack.security.http.ssl.certificate_authorities: [ "certs/ca/ca.crt" ]

# Step Three:) If you secured the keystore or the private key with a password, add that password to a secure setting in Elasticsearch.
# If the certificates are in PEM format:
# &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
# bin/elasticsearch-keystore add xpack.security.http.ssl.secure_key_passphrase


# Configure each node to:
# # &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
# Required: Enable TLS on the transport layer.
# Recommended: Enable TLS on the HTTP layer.





# *****************************************************************************************************
# **************************Kibana setup for Encrypting HTTP client communications*********************
# *****************************************************************************************************
# Kibana supports certificates and private keys in PEM or PKCS#12 format.
# Obtain TLS Certificates and Private Key
# You can choose to obtain a commercially trusted certificates and keys from an public CA of your preference.
# Similarly, you can use self-signed certificates for your non-public facing Kibana.
# If you opt to use the self-signed certificates, then there are two options. You can either obtain the TLS certs and key using;
# QQ) OpenSSL
# ZZ) elasticsearch-certutil tool
# Configure Security in Kibana
# Credentials for the user can be defined in plain text in Kibana configuration file, kibana.yml or can be added to Kibana keystore.
# To add the credentials in Kibana configuration file, enter the lines in the /etc/kibana/kibana.yml.
# elasticsearch.username: "kibana_system"
# elasticsearch.password: "mLhDnalWA8yPpPuE0GFB"

# To add the credentials to the Keystore instead of putting them on /etc/kibana/kibana.yml, create Kibana keystore and add them as shown below;
# chmod g+w /etc/kibana/
# sudo -u kibana /usr/share/kibana/bin/kibana-keystore create

# Add the user, kibana_system:
# sudo -u kibana /usr/share/kibana/bin/kibana-keystore add elasticsearch.username

# Add the password:
# sudo -u kibana /usr/share/kibana/bin/kibana-keystore add elasticsearch.password


# kibana.yml
# ==========================================================
# server.port: 5602
# server.host: "0.0.0.0"
# elasticsearch.hosts: ["https://172.17.0.1:9201"]
# # # xpack.security.enabled: true
# elasticsearch.username: "kibana_system"
# elasticsearch.password: "k_j6s0hItIv0CysusGRK"
# elasticsearch.ssl.certificateAuthorities: [ "/home/jdw/app/es_single/kibana-8.2.2/config/elasticsearch-ca.pem" ]
# # # elasticsearch.ssl.verificationMode: certificate
# server.ssl.enabled: true
# server.ssl.certificate: config/kibana-server.crt
# server.ssl.key: config/kibana-server.key




# elasticsearch.ssl.certificate: /path/to/cert/pem
# elasticsearch.ssl.key: /path/to/key/pem
# elasticsearch.ssl.certificateAuthorities: ["/path/to/ca/pem"]


# Restart Kibana Service
# ==============================================
# systemctl restart kibana
















































































# # [node1] /etc/hosts:
# 192.168.0.2 node1.elastic.com node1
# 192.168.0.3 node2.elastic.com node2

# # [node2] /etc/hosts:
# 192.168.0.2 node1.elastic.com node1
# 192.168.0.3 node2.elastic.com node2

# [root@node1 ~]# mkdir /opt/cert
# [root@node1 ~]# cd /opt/cert

# Create the instance.yml file:
# [root@node1 cert]# vim /opt/cert/instance.yml

# instance.yml:
# =======================================
# instances:
#  - name: 'node1'
#    dns: [ 'node1.elastic.com' ]
#    ip: [ '192.168.0.2' ]
#  - name: 'node2'
#    dns: [ 'node2.elastic.com' ]
#    ip: [ '192.168.0.3' ]

# instance.yml:
# =======================================
# instances:
#  - name: 'node1'
#    dns: 
#     - 'node1.elastic.com'
#    ip: 
#     - '192.168.0.2'
#  - name: 'node2'
#    dns: 
#     - 'node2.elastic.com'
#    ip: [ '' ]
#     - '192.168.0.3'

# Create the CA:
# [root@node1 ~]# cd  /usr/share/elasticsearch/
# [root@node1 elasticsearch]# sudo /usr/share/elasticsearch/bin/elasticsearch-certutil ca cert --keep-ca-key --pem --in /opt/cert/instance.yml --out /opt/cert/certs.zip

# sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert --pem --ca-cert /opt/cert/ca/ca.crt --ca-key /opt/cert/ca/ca.key --in /opt/cert/instance.yml --out /opt/cert/certs.zip

# Unzip it:
# [root@node1 elasticsearch]# cd /opt/cert
# [root@node1 cert]# unzip certs.zip
# certs.zip
# |-- ca
# |   |-- ca.crt
#     |-- ca.key
# |-- node1
# |   |-- node1.crt
# |   |-- node1.key
# |-- node2
# |   |-- node2.crt
# |   |-- node2.key
# |-- node3
#     |-- node3.crt
#     |-- node3.key

# Note : The ca.crt file is shared for all the instances. The .crt and .key pairs are unique for each instance.






















# https://www.server-world.info/en/note?os=CentOS_Stream_8&p=elasticstack7&f=12
# https://techexpert.tips/elasticsearch/elasticsearch-enable-tls-https/
# https://www.golinuxcloud.com/enable-https-ssl-secure-elasticsearch-linux/
# https://kifarunix.com/enable-https-connection-between-elasticsearch-nodes/
# https://rharshad.com/secure-elasticsearch-cluster-aws-ec2/
# https://alexnogard.com/install-elastic-stack-7-x-on-centos-7-with-ssl-tls-https/?cn-reloaded=1
# https://handlers.sans.edu/gbruneau/elk/TLS_elasticsearch_configuration.pdf
# https://groups.google.com/g/wazuh/c/fkB8sODJmaU?pli=1
# https://documentation.wazuh.com/3.12/installation-guide/installing-elastic-stack/protect-installation/xpack.html
# https://www.ibm.com/docs/en/sle/10.2.0?topic=elasticsearch-enabling-https
# https://www.cnblogs.com/hahaha111122222/p/12061475.html
# https://kupczynski.info/posts/elasticsearch-fun-with-tls/
# https://www.cnblogs.com/listjiang/p/16327983.html