package com.wmpay.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.UUID;

/**
 * EXAMPLE ONLY — demonstrates the slf4j-api facade that every service on
 * this platform already has on its classpath (directly or transitively via
 * spring-boot-starter-logging / netty / mybatis-plus / hutool).
 *
 * All imports below come from org.slf4j:* resolved through the Nexus group:
 *   https://nexus.wmpay.me/repository/maven-public/org/slf4j/slf4j-api/2.0.9/
 *   https://nexus.wmpay.me/repository/maven-public/org/slf4j/jcl-over-slf4j/2.0.9/
 *   https://nexus.wmpay.me/repository/maven-public/ch/qos/logback/logback-classic/1.4.14/
 */
@Service
public class LoggingDemoService {

    // Standard SLF4J logger creation. getLogger(String) is also available —
    // the class-based overload derives the logger name from the class FQN.
    private static final Logger log = LoggerFactory.getLogger(LoggingDemoService.class);

    /**
     * Core SLF4J idioms used across the platform's services:
     * parameterized placeholders ({}), level checks, exceptions, MDC.
     */
    public String depositSettled(String orderNo, String channel, BigDecimal amount) {
        // 1) Parameterized logging — lazy, no string concat when disabled.
        //    SLF4J never evaluates args unless the level is enabled.
        log.debug("deposit received orderNo={} channel={}", orderNo, channel);
        log.info("deposit settled orderNo={} amount={}", orderNo, amount);

        // 2) Level guard for expensive args (e.g. building big strings).
        if (log.isTraceEnabled()) {
            log.trace("full payload for {}: {}", orderNo, new String(new char[64]).replace('\0', 'x'));
        }

        // 3) Exception logging — pass the throwable LAST, it gets stacktrace.
        try {
            if (amount.signum() <= 0) {
                throw new IllegalArgumentException("non-positive amount: " + amount);
            }
        } catch (IllegalArgumentException e) {
            log.error("rejected deposit orderNo={} amount={}", orderNo, amount, e);
            throw e;
        }

        // 4) MDC (Mapped Diagnostic Context) — trace-id correlation across
        //    logback output. Value is auto-cleared after log().
        MDC.put("traceId", UUID.randomUUID().toString().substring(0, 8));
        MDC.put("orderNo", orderNo);
        try {
            log.info("deposit committed");
        } finally {
            MDC.clear();
        }

        // 5) Nested logger by name — loggers form a hierarchy: child inherits
        //    level from parent unless overridden in logback.xml.
        Logger audit = LoggerFactory.getLogger("audit.deposit");
        audit.info("ORDER {} CHANNEL {} AMOUNT {}", orderNo, channel, amount);

        return orderNo;
    }
}
