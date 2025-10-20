FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN --mount=type=cache,target=/root/.m2 \
    mvn clean install -DskipTests

FROM eclipse-temurin:17-jdk-jammy AS jre-builder
WORKDIR /opt/build

COPY --from=build /app/target/*.jar ./application.jar

RUN java -Djarmode=layertools -jar application.jar extract

RUN $JAVA_HOME/bin/jlink \
    --add-modules $(jdeps --ignore-missing-deps -q --recursive --multi-release 17 --print-module-deps -cp 'dependencies/BOOT-INF/lib/*' application.jar),jdk.crypto.ec,java.security.jgss,jdk.httpserver \
    --strip-debug \
    --no-man-pages \
    --no-header-files \
    --compress=2 \
    --output /opt/jdk

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/opt/jdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

RUN groupadd --gid 1000 spring-app && \
    useradd --uid 1000 --gid spring-app --shell /bin/bash --create-home spring-app

USER spring-app:spring-app

WORKDIR /app

COPY --from=jre-builder /opt/jdk $JAVA_HOME
COPY --from=jre-builder /opt/build/spring-boot-loader/ ./
COPY --from=jre-builder /opt/build/dependencies/ ./
COPY --from=jre-builder /opt/build/snapshot-dependencies/ ./
COPY --from=jre-builder /opt/build/application/ ./

EXPOSE 8080
ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]