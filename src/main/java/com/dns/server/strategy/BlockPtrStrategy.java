/**
 * 屏蔽PTR查询策略
 */
package com.dns.server.strategy;

import com.dns.dns.DnsMessage;
import com.dns.dns.DnsQuestion;
import com.dns.server.PtrResolutionStrategy;
import com.dns.util.DnsResponseFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 屏蔽PTR查询策略
 */
public class BlockPtrStrategy implements PtrResolutionStrategy {
    private static final Logger logger = LoggerFactory.getLogger(BlockPtrStrategy.class);
    
    @Override
    public DnsMessage resolve(DnsMessage request, String clientIp) {
        String ptrDomain = request.getQuestions().get(0).getName();
        logger.info("屏蔽PTR查询: {} 来自 {}", ptrDomain, clientIp);
        return DnsResponseFactory.createNotFoundResponse(request);
    }
}