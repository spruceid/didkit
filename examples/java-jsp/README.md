# Java JSP Example

This project demonstrates use of verifiable credentials and presentation to enable
user authentication for an application.

## Dependencies

### Java

To run this example you will need Java installed.

For example, on Ubuntu you could install OpenJDK:

```bash
# apt-get install openjdk-11-{jre,jdk}
```

### Maven

To install Maven, run the following command:

```bash
# apt-get install maven
```

### Tomcat

To install tomcat locally, you could run the following sequence of commands,
sourced from
[Digital Ocean's Tutorial](https://www.digitalocean.com/community/tutorials/install-tomcat-9-ubuntu-1804)

Create `tomcat` user and group.
```bash
# groupadd tomcat
# useradd -s /bin/false -g tomcat -d /opt/tomcat tomcat
```

Download and extract `tomcat` to `/opt/tomcat`.
```bash
$ curl -O https://downloads.apache.org/tomcat/tomcat-9/v9.0.43/bin/apache-tomcat-9.0.43.tar.gz
# mkdir /opt/tomcat
# tar xzvf apache-tomcat-*tar.gz -C /opt/tomcat --strip-components=1
```

Set permissions and groups.
```bash
# chgrp -R tomcat /opt/tomcat
# chmod -R g+r /opt/tomcat/conf
# chmod g+x /opt/tomcat/conf
# chown -R tomcat /opt/tomcat/webapps /opt/tomcat/work /opt/tomcat/temp /opt/tomcat/logs
```

Find out where your JAVA_HOME is located.
```bash
```

Create `tomcat` service file at `/etc/systemd/system/tomcat.service`.
```bash
[Unit]
Description=Apache Tomcat Web Application Container
After=network.target

[Service]
Type=forking

Environment=JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
Environment=CATALINA_PID=/opt/tomcat/temp/tomcat.pid
Environment=CATALINA_HOME=/opt/tomcat
Environment=CATALINA_BASE=/opt/tomcat
Environment='CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC'
Environment='JAVA_OPTS=-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom'

ExecStart=/opt/tomcat/bin/startup.sh
ExecStop=/opt/tomcat/bin/shutdown.sh

User=tomcat
Group=tomcat
UMask=0007
RestartSec=10
Restart=always

[Install]
WantedBy=multi-user.target
```

Reload the systemd daemon and start the service:
```bash
# systemctl daemon-reload
# systemctl start tomcat
# systemctl status tomcat
```

Optionally, enable it at start-up with: 
```bash
# systemctl enable tomcat
```

#### Create `data` directory

We will create a directory to store our database and key file and give `tomcat`
user the appropriate permissions:

```bash
# mkdir /opt/tomcat/data
# chown tomcat:tomcat /opt/tomcat/data
# chmod u+wrx /opt/tomcat/data
```

## Building

### Build DIDKit

The web application makes use of DIDKit to handle credentials and presentations,
please refer to the project's documentation to build the library for your platform,
`libdidkit.so` on UNIX-like systems, `didkit.dll` on Windows, `libdidkit.dylib`
on MacOS, etc.

Then you will have to add it to the classpath of your platform. On UNIX systems,
for example, you can copy (or symlink) `libdidkit.so` to `/usr/lib` or
`/usr/local/lib`. In the instructions below, we will list commands to create a
symlink to the local build folder.

You will then require the Java artifact (`didkit.jar`). This example project
already has a symlink in the build directory.  All you have to do is run the
following commands in the root folder to build everything and ensure proper
linking.

```bash
$ git clone https://github.com/spruceid/didkit
$ cd didkit/
$ cargo build
# Use libdidkit.so for UNIX-like, didkit.dll for Windows, libdidkit.dylib for MacOS
$ make -C lib ../target/didkit.jar
```

To link the library files like described above, you could use one of the
following commands:

```bash
# ln -s target/libdidkit.so /usr/lib # on Linux
# ln -s target/libdidkit.dylib /usr/lib # on MacOS
```

### Install `didkit.jar` to local Maven repository

To avoid a complicated Maven setup, the easiest way to be able to include the
library in the `war` executable is adding it to the local Maven repository. To
do so, execute the following command from `examples/java-jsp`:

```bash
$ cd examples/java-jsp
$ mvn install:install-file \
  -Dfile=didkit.jar \
  -DgroupId=com.spruceid.didkit \
  -DartifactId=didkit \
  -Dversion=0.1 \
  -Dpackaging=jar
```

### Generate `.war` file

To generate the `war` file, execute:

```bash
$ mvn package
```

Copy the resulting file `target/java-jsp-0.1.war` to `/opt/tomcat/webapps` and
restart the server.

```bash
# cp target/java-jsp-0.1.war /opt/tomcat/webapps
# systemctl restart tomcat
```

The example should now be accessible on http://localhost:8080/java-jsp-0.1/

## CHAPI Wallet

To sign in and receive your credentials, you will need a CHAPI Wallet. To provide
an easy way to test out this example and others we host our `svelte-chapi-wallet`
example implementation over at
[https://demo-wallet.spruceid.com](https://demo-wallet.spruceid.com).

## Troubleshooting

### The Apache Tomcat Native library which allows using OpenSSL was not found on the java.library.path

If you encounter an error which says that the Apache Tomcat Native library is
missing, you will have to install it, there's documentation on how to build it
[here](http://tomcat.apache.org/native-doc/), but your system's package manager
might have a package for it like in the examples below:

```bash
# apt-get install libtcnative-1 # On Ubuntu
$ brew install tomcat-native # On MacOS
```
