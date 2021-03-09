# Java JSP Example

## Install `DIDKit.jar` to local Maven repository

To avoid a complicated Maven setup, the easiest way to be able to include the
library in the `war` executable is adding it to the local Maven repository. To
do so, execute the following command:

```bash
mvn install:install-file \
  -Dfile=didkit.jar \
  -DgroupId=com.spruceid.didkit \
  -DartifactId=didkit \
  -Dversion=0.1 \
  -Dpackaging=jar
```
