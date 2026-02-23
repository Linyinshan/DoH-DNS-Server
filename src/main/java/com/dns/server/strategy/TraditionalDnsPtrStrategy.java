// TraditionalDnsPtrStrategy.java
package com.dns.server.strategy;

import com.dns.dns.DnsMessage;
import com.dns.resolver.TraditionalPtrResolver;
import com.dns.server.PtrResolutionStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * 传统DNS解析PTR策略
 */
public class TraditionalDnsPtrStrategy implements PtrResolutionStrategy {
    private static final Logger logger = LoggerFactory.getLogger(TraditionalDnsPtrStrategy.class);
    private final TraditionalPtrResolver resolver;
    
    public TraditionalDnsPtrStrategy(TraditionalPtrResolver resolver) {
        this.resolver = resolver;
    }
    
    @Override
    public DnsMessage resolve(DnsMessage request, String clientIp) throws IOException {
        String ptrDomain = request.getQuestions().get(0).getName();
        logger.debug("使用传统DNS解析PTR: {} 来自 {}", ptrDomain, clientIp);
        return resolver.resolvePtr(ptrDomain, request.getId());
    }
}