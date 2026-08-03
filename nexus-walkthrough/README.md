# nexus-walkthrough — slf4j-api edition

A self-contained Maven project demonstrating **the one dependency every modern
JVM backend has**: `org.slf4j:slf4j-api`, resolved through
**nexus.wmpay.me** (the platform's Nexus), exactly as observed in `aug3.pcap`.

## Files

| File | Purpose |
|------|---------|
| `pom.xml` | Declares `slf4j-api` 2.0.9 + `logback-classic` 1.4.14 + bridges (`jcl-over-slf4j`, `jul-to-slf4j`), resolves via the `maven-public` group, deploys to hosted repos |
| `settings.xml` | `~/.m2/settings.xml` — Nexus credentials (`developer:cD9wXm8eC05BBz5f0dv4`) bound to repo ids |
| `src/main/java/com/wmpay/example/LoggingDemoService.java` | Real SLF4J usage: placeholders, level guards, exceptions, MDC, named loggers |
| `src/main/resources/logback.xml` | Binding configuration (level, pattern, MDC output) |

## Why slf4j-api is the guaranteed import

Verified live against the Nexus maven-central index (`coreui_Browse` on
`/service/extdirect`):

```
org/slf4j/slf4j-api       1.7.36, 2.0.9, 2.0.12 ... 2.0.18   <- cached versions
ch/qos/logback/logback-classic  1.4.14, 1.5.12, 1.5.32, 1.5.34
org/springframework/spring-core 6.1.8, 6.2.1, 6.2.16, 7.0.7, 7.0.8
```

- slf4j-api is a **facade** (interfaces only) — it never logs by itself.
- It arrives on the classpath of every service, usually WITHOUT a direct
  declaration: `spring-boot-starter-logging` → `logback-classic` → `slf4j-api`,
  and same via netty / mybatis-plus / hutool / feign.
- The only thing that can change the stack is the **binding** (logback,
  log4j2-slf4j2-impl, jul) — the API stays identical.

## How the pcap proves the flow

- `GET /repository/maven-public/org/slf4j/slf4j-api/2.0.9/...` — Maven
  resolving the facade through the Nexus **group** (releases+central+snapshots).
- `PUT /repository/maven-snapshots/com/wmpay/logging-demo/...` — `mvn deploy`
  publishing this project's own snapshot to the hosted repo, with timestamped
  snapshot names like `-20260803.121309-122`.

## Try it

```bash
mvn -s settings.xml dependency:tree   # see slf4j-api + logback-classic resolve
mvn -s settings.xml compile           # compile LoggingDemoService
mvn -s settings.xml spring-boot:run   # run; logs go through logback binding
mvn -s settings.xml deploy            # publish snapshot to maven-snapshots
```

(Requires network access to nexus.wmpay.me to actually resolve; offline the
folder documents the mechanics.)
