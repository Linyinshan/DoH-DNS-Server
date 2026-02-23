package com.dns.server.strategy;

import com.dns.dns.DnsMessage;
import com.dns.doh.PtrResolver;
import com.dns.server.PtrResolutionStrategy;
import com.dns.util.DnsResponseFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DoH解析PTR策略
 */
public class DohPtrStrategy implements PtrResolutionStrategy {
    private static final Logger logger = LoggerFactory.getLogger(DohPtrStrategy.class);
    private final PtrResolver ptrResolver;
    
    public DohPtrStrategy(PtrResolver ptrResolver) {
        this.ptrResolver = ptrResolver;
    }
    
    @Override
    public DnsMessage resolve(DnsMessage request, String clientIp) {
        String ptrDomain = request.getQuestions().get(0).getName();
        logger.debug("使用DoH解析PTR: {} 来自 {}", ptrDomain, clientIp);
        
        try {
            DnsMessage response = ptrResolver.resolvePtrQuery(request);
            if (response != null && !response.getAnswers().isEmpty()) {
                return response;
            } else {
                // 如果返回空响应，返回NOT FOUND
                return DnsResponseFactory.createNotFoundResponse(request);
            }
        } catch (Exception e) {
            logger.error("DoH PTR解析失败: {}", e.getMessage());
            // 解析失败时返回服务器故障响应
            return DnsResponseFactory.createServFailResponse(request);
        }
    }
}