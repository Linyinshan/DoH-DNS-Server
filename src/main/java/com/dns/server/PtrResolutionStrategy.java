/**
 * PTR解析策略接口
 */
package com.dns.server;

import com.dns.dns.DnsMessage;
import java.io.IOException;

/**
 * PTR解析策略接口
 */
public interface PtrResolutionStrategy {
    DnsMessage resolve(DnsMessage request, String clientIp) throws IOException;
}