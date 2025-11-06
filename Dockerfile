# Stage 1: Build the JAR with Gradle
FROM gradle:9.0.0-jdk21 AS build

WORKDIR /app

# Copy Gradle files and source
COPY build.gradle settings.gradle gradlew ./
COPY gradle ./gradle
COPY src ./src

# Build the Spring Boot application
RUN ./gradlew clean build -x test

# Stage 2: Run the application
FROM eclipse-temurin:21-jdk

RUN apt-get update && apt-get install -y openssl && apt-get clean

WORKDIR /app

# Copy the built JAR from the build stage
COPY --from=build /app/build/libs/SLUDI-Backend.jar app.jar

# Expose Spring Boot port
EXPOSE 5000

# Run the Spring Boot app
ENTRYPOINT ["java", "-jar", "app.jar"]
