package com.dns.resolver;

import com.dns.dns.DnsMessage;
import com.dns.dns.DnsQuestion;
import com.dns.dns.DnsRecord;
import com.dns.dns.DnsRecordType;
import com.dns.config.DnsConfig;
import com.dns.util.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * 传统DNS PTR解析器
 * 使用UDP协议直接向DNS服务器查询PTR记录
 */
public class TraditionalPtrResolver {
    private static final Logger logger = LoggerFactory.getLogger(TraditionalPtrResolver.class);
    
    private final DnsConfig config;
    private final String dnsServer;
    private final int dnsPort;
    private final int timeout;
    
    public TraditionalPtrResolver(DnsConfig config) {
        this.config = config;
        this.dnsServer = config.getString("ptr_traditional_dns_server", "8.8.8.8");
        this.dnsPort = config.getInt("ptr_traditional_dns_port", 53);
        this.timeout = config.getInt("ptr_timeout", 5000);
        
        logger.info("传统DNS PTR解析器初始化 - 服务器: {}:{}, 超时: {}ms", 
                   dnsServer, dnsPort, timeout);
    }
    
    /**
     * 解析PTR查询
     */
    public DnsMessage resolvePtr(String ptrDomain, int requestId) throws IOException {
        logger.debug("使用传统DNS解析PTR: {} [ID: {}]", ptrDomain, requestId);
        
        // 检查本地映射
        if (isLocalPtr(ptrDomain)) {
            return generateLocalPtrResponse(ptrDomain, requestId);
        }
        
        // 构建DNS查询报文
        byte[] queryData = buildPtrQuery(ptrDomain, requestId);
        
        // 发送UDP请求
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeout);
            
            InetAddress serverAddress = InetAddress.getByName(dnsServer);
            DatagramPacket sendPacket = new DatagramPacket(queryData, queryData.length, 
                                                          serverAddress, dnsPort);
            
            // 发送请求
            long startTime = System.currentTimeMillis();
            socket.send(sendPacket);
            logger.debug("已发送传统DNS PTR查询到 {}:{}", dnsServer, dnsPort);
            
            // 接收响应
            byte[] buffer = new byte[512]; // DNS响应最大512字节
            DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);
            socket.receive(receivePacket);
            
            long responseTime = System.currentTimeMillis() - startTime;
            logger.debug("收到传统DNS PTR响应，耗时: {}ms", responseTime);
            
            // 解析响应
            return parseDnsResponse(buffer, receivePacket.getLength(), requestId);
            
        } catch (SocketTimeoutException e) {
            logger.warn("传统DNS PTR查询超时: {}:{}", dnsServer, dnsPort);
            throw new IOException("DNS查询超时", e);
        } catch (UnknownHostException e) {
            logger.error("DNS服务器地址无效: {}", dnsServer);
            throw new IOException("无效的DNS服务器地址: " + dnsServer, e);
        }
    }
    
    /**
     * 构建PTR查询报文
     */
    private byte[] buildPtrQuery(String ptrDomain, int requestId) {
        ByteBuffer buffer = ByteBuffer.allocate(512);
        
        // DNS头部
        buffer.putShort((short) requestId);  // ID
        buffer.putShort((short) 0x0100);     // Flags: RD=1
        buffer.putShort((short) 1);          // QDCOUNT: 1个问题
        buffer.putShort((short) 0);          // ANCOUNT: 0个答案
        buffer.putShort((short) 0);          // NSCOUNT: 0个授权记录
        buffer.putShort((short) 0);          // ARCOUNT: 0个附加记录
        
        // 问题部分：PTR查询
        writeDomainName(buffer, ptrDomain);
        buffer.putShort((short) 12);         // TYPE: PTR (12)
        buffer.putShort((short) 1);          // CLASS: IN (1)
        
        byte[] result = new byte[buffer.position()];
        buffer.flip();
        buffer.get(result);
        return result;
    }
    
    /**
     * 写入域名（QNAME格式）
     */
    private void writeDomainName(ByteBuffer buffer, String domain) {
        String[] labels = domain.split("\\.");
        for (String label : labels) {
            buffer.put((byte) label.length());
            buffer.put(label.getBytes());
        }
        buffer.put((byte) 0); // 结束标记
    }
    
    /**
     * 解析DNS响应
     */
    private DnsMessage parseDnsResponse(byte[] data, int length, int expectedId) {
        ByteBuffer buffer = ByteBuffer.wrap(data, 0, length);
        
        // 读取头部
        int id = buffer.getShort() & 0xFFFF;
        int flags = buffer.getShort() & 0xFFFF;
        int questionCount = buffer.getShort() & 0xFFFF;
        int answerCount = buffer.getShort() & 0xFFFF;
        
        // 验证ID
        if (id != expectedId) {
            logger.warn("DNS响应ID不匹配: 期望 {}, 实际 {}", expectedId, id);
        }
        
        DnsMessage message = new DnsMessage(id, flags);
        message.setQr(true); // 这是响应
        
        // 跳过问题部分
        for (int i = 0; i < questionCount; i++) {
            skipDomainName(buffer);
            buffer.position(buffer.position() + 4); // 跳过TYPE和CLASS
        }
        
        // 读取答案部分
        for (int i = 0; i < answerCount && buffer.remaining() >= 12; i++) {
            try {
                String name = readDomainName(buffer);
                int type = buffer.getShort() & 0xFFFF;
                int clazz = buffer.getShort() & 0xFFFF;
                long ttl = buffer.getInt() & 0xFFFFFFFFL;
                int dataLength = buffer.getShort() & 0xFFFF;
                
                if (buffer.remaining() < dataLength) {
                    logger.warn("答案数据长度不足");
                    break;
                }
                
                if (type == 12) { // PTR记录
                    String ptrData = readDomainName(buffer);
                    DnsRecord record = new DnsRecord(name, DnsRecordType.PTR, clazz, ttl, ptrData);
                    message.addAnswer(record);
                    logger.debug("解析到PTR记录: {} -> {}", name, ptrData);
                } else {
                    // 跳过其他类型的记录
                    buffer.position(buffer.position() + dataLength);
                }
            } catch (Exception e) {
                logger.warn("解析DNS答案记录失败: {}", e.getMessage());
                break;
            }
        }
        
        return message;
    }
    
    /**
     * 检查是否是本地PTR查询
     */
    private boolean isLocalPtr(String ptrDomain) {
        return ptrDomain.equals("1.0.0.127.in-addr.arpa") ||
               ptrDomain.equals("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa");
    }
    
    /**
     * 生成本地PTR响应
     */
    private DnsMessage generateLocalPtrResponse(String ptrDomain, int requestId) {
        DnsMessage response = new DnsMessage(requestId, 0x8180); // QR=1, RD=1, RA=1
        response.setQr(true);
        
        // 添加问题
        response.addQuestion(new DnsQuestion(ptrDomain, DnsRecordType.PTR, 1));
        
        // 添加答案
        String hostname = ptrDomain.contains("ip6") ? "localhost" : "localhost";
        DnsRecord answer = new DnsRecord(ptrDomain, DnsRecordType.PTR, 1, 3600, hostname);
        response.addAnswer(answer);
        
        return response;
    }
    
    /**
     * 读取域名（简化实现）
     */
    private String readDomainName(ByteBuffer buffer) {
        StringBuilder name = new StringBuilder();
        int position = buffer.position();
        int length;
        
        while ((length = buffer.get() & 0xFF) != 0) {
            if ((length & 0xC0) == 0xC0) {
                // 压缩指针，简化处理：跳过
                buffer.get();
                break;
            }
            
            byte[] labelBytes = new byte[length];
            buffer.get(labelBytes);
            if (name.length() > 0) {
                name.append(".");
            }
            name.append(new String(labelBytes));
        }
        
        // 如果解析失败，恢复位置
        if (name.length() == 0) {
            buffer.position(position);
            return "unknown";
        }
        
        return name.toString();
    }
    
    /**
     * 跳过域名
     */
    private void skipDomainName(ByteBuffer buffer) {
        int length;
        while ((length = buffer.get() & 0xFF) != 0) {
            if ((length & 0xC0) == 0xC0) {
                buffer.get(); // 跳过指针
                break;
            }
            buffer.position(buffer.position() + length);
        }
    }
    
    /**
     * 获取配置的DNS服务器
     */
    public String getDnsServer() {
        return dnsServer;
    }
    
    /**
     * 获取配置的DNS端口
     */
    public int getDnsPort() {
        return dnsPort;
    }
}