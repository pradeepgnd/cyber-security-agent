FROM openjdk:11-jre
WORKDIR /app
# vulnerable logging stack used by the public API
COPY log4j-core-2.14.1.jar /app/lib/log4j-core-2.14.1.jar
COPY app.jar /app/app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
