// DnsResponseFactory.java
package com.dns.util;

import com.dns.dns.DnsMessage;
import com.dns.dns.DnsQuestion;
import com.dns.dns.DnsRecord;
import com.dns.dns.DnsRecordType;

/**
 * DNS响应工厂类
 */
public class DnsResponseFactory {
    
    public static DnsMessage createBlockedResponse(DnsMessage request, String ipAddress) {
        DnsMessage response = new DnsMessage();
        response.setId(request.getId());
        
        int flags = 0x8000; // QR=1 (响应)
        flags |= 0x0400;    // AA=1 (权威回答)
        flags |= 0x0080;    // RA=1 (递归可用)
        response.setFlags(flags);
        
        response.getQuestions().addAll(request.getQuestions());
        
        DnsQuestion question = request.getQuestions().get(0);
        DnsRecord record = new DnsRecord(
            question.getName(),
            question.getType(),
            1, // IN class
            300, // 5分钟TTL
            ipAddress
        );
        response.addAnswer(record);
        
        return response;
    }
    
    public static DnsMessage createNotFoundResponse(DnsMessage request) {
        DnsMessage response = new DnsMessage();
        response.setId(request.getId());
        
        int flags = 0x8000; // QR=1 (响应)
        flags |= 0x0400;    // AA=1 (权威回答)
        flags |= 0x0080;    // RA=1 (递归可用)
        flags |= 0x0003;    // RCODE=3 (域名不存在)
        response.setFlags(flags);
        
        response.getQuestions().addAll(request.getQuestions());
        return response;
    }
    
    public static DnsMessage createServFailResponse(DnsMessage request) {
        DnsMessage response = new DnsMessage();
        response.setId(request.getId());
        response.setFlags(0x8182); // QR=1, RA=1, RD=1, RCODE=2 (SERVFAIL)
        response.getQuestions().addAll(request.getQuestions());
        return response;
    }
    
    public static DnsMessage createErrorResponse(DnsMessage request, String errorMessage) {
        DnsMessage response = new DnsMessage();
        response.setId(request.getId());
        response.setFlags(0x8181); // QR=1, RA=1, RD=1, RCODE=1 (FORMERR)
        response.getQuestions().addAll(request.getQuestions());
        return response;
    }
}