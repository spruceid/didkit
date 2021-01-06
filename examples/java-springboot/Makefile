run: sync
	./mvnw spring-boot:run

sync:
	rsync -av --exclude=.\*.sw\* --exclude=\*~ --delete-after \
		src/main/resources/templates src/main/resources/static \
		target/classes/
