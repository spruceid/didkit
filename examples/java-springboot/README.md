# Spring Boot Java Example

This project demonstrates use of verifiable credentials and presentation to enable
user authentication for an application.

## Dependencies

### Java

To run this example you will need Java 11 installed.

For example, on Ubuntu you could install OpenJDK:

```bash
$ apt-get install openjdk-11-{jre,jdk}
```

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
linking:

```bash
$ cargo build
# Use libdidkit.so for UNIX-like, didkit.dll for Windows, libdidkit.dylib for MacOS
$ ln -s target/debug/libdidkit.so examples/java-springboot/
$ make -C lib ../target/didkit.jar
```

If you are trying to use DIDKit with an external Java project, you will have to
point your build tool (Gradle, Maven, etc) to the `didkit.jar` file. Also
ensure that the static library (e.g., `libdidkit.so` is in the
`java.library.path` or specified using the proper environment variables, such
as `LD_LIBRARY_PATH` on UNIX-like. Please refer to the full documentation for
those tools. Here is an excerpt of how we have listed it on this project's
`pom.xml` for Maven:

```xml
<dependency>
  <groupId>com.spruceid.didkit</groupId>
  <artifactId>didkit</artifactId>
  <version>0.1</version>
  <scope>system</scope>
  <systemPath>${basedir}/didkit.jar</systemPath>
</dependency>
```

### Database Setup (MySQL)

This project uses a MySQL database to store the user entity. We will use the
`root` user for simplicity because this is only an example. In your actual
deployments, it is **very important** that you configure the correct accounts,
policies, and permissions for your SQL installations.


#### (a) Docker MySQL Database
One easy way to run an instance is by using docker:

```bash
$ docker run \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=didkit \
  -p 3306:3306 \
  --name didkit-java-db \
  -d mysql:5
```

#### (b) System MySQL Database
Here are some commands to use a local instance of the MySQL-compatible MariaDB
on Ubuntu:

```bash
$ sudo apt-get install mariadb-client mariadb-server
$ sudo service mysql start
$ sudo mysql_secure_installation  # set the root password to 'root'
$ sudo mariadb
# allow anyone to use the root account with the right password. DO NOT DO THIS IN PRODUCTION.
MariaDB [(none)]> UPDATE mysql.user SET plugin = 'mysql_native_password' WHERE User='root';
MariaDB [(none)]> FLUSH PRIVILEGES;
# create the example database
MariaDB [(none)]> CREATE DATABASE didkit;
MariaDB [(none)]> quit
```

### (Optional) Test MySQL
To ensure that mysql is working, try the following command:
```bash
$ sudo apt-get install mariadb-client
$ mariadb -uroot -proot
MariaDB [(none)]> SHOW DATABASES;
MariaDB [(none)]> quit
```

### Database Connection Configuration
If you need to modify the database credentials you will need to update the
relevant fields in `src/main/resources/application.properties`.

```
spring.datasource.url=jdbc:mysql://localhost:3306/didkit
spring.datasource.username=root
spring.datasource.password=root
```

### Redis

This project makes use of Redis to store single use tokens and authentication
information for the QR code flows.

#### (a) Docker Redis
One easy way, just like MySQL, to have it running locally is to use docker:
```bash
# docker run \
  -p 6379:6379 \
  --name didkit-java-redis \
  -d redis
```

#### (b) System Redis
Here are some commands to install and run Redis on Ubuntu:
```bash
sudo apt-get install redis
sudo service redis-server start
```

### (Optional) Test Redis
To ensure that mysql is working, try the following commands:
```bash
$ sudo apt-get install redis
$ redis-cli
127.0.0.1:6379> set foo "Hello, World!"
127.0.0.1:6379> get foo
127.0.0.1:6379> del foo
```

## Building and Running

We are now ready to build and run the installation. To download the required
Java dependencies, build the project, and then run it, you can execute the
following commands from the root project directory:

```bash
$ cd examples/java-springboot
$ LD_LIBRARY_PATH=`pwd` ./mvnw spring-boot:run
```

You can then load `http://localhost:8081` to see the web application.


To verify that DIDKit has been setup correctly, you can then run:

```bash
$ curl -v http://localhost:8081/version
```

And you should expect to see a version string in the response.

## Java Example App Walkthrough

1. Visit http://localhost:8081 with your web browser.
2. Create a user by clicking "Sign Up" on the navigation bar.
3. Log in with your newly created user by clicking "Sign In" on the navigation
   bar.
4. Issue yourself a credential to use for login instead of username and
   password. You can receive credentials in the example [CHAPI wallet](#) or
   using the QR code workflow and
   [Credible](https://github.com/spruceid/credible) mobile wallet.
