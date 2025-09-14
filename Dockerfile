# Stage 1: Build the JAR with Gradle
FROM gradle:8.11.1-jdk21 AS build

# Set working directory
WORKDIR /app

# Copy Gradle files and source
COPY build.gradle settings.gradle gradlew ./
COPY gradle ./gradle
COPY src ./src

# Build the Spring Boot application
RUN ./gradlew clean build -x test

# Stage 2: Run the application
FROM openjdk:21-jdk-slim

WORKDIR /app

# Copy only the built JAR from the previous stage
COPY --from=build /app/build/libs/*.jar app.jar

# Expose Spring Boot port
EXPOSE 5000

# Run Spring Boot app
ENTRYPOINT ["java", "-jar", "app.jar"]
