package com.dns.doh;

import com.dns.dns.DnsMessage;
import com.dns.dns.DnsRecordType;
import com.dns.dns.DnsQuestion;
import com.dns.dns.DnsRecord;
import com.dns.config.DnsConfig;
import okhttp3.*;
import okhttp3.Authenticator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class DohResolver {
    private static final Logger logger = LoggerFactory.getLogger(DohResolver.class);
    private static final MediaType DNS_MESSAGE_TYPE = MediaType.parse("application/dns-message");
    
    private final OkHttpClient httpClient;
    private final List<String> dohServers;
    private int currentServerIndex = 0;
    
    // 代理配置
    private final DnsConfig config;
    private final String proxyHost;
    private final int proxyPort;
    private final String proxyType;
    private final String proxyUsername;
    private final String proxyPassword;
    private final boolean proxyEnabled;
    
    // 内置的DoH服务器列表
    private static final List<String> BUILTIN_SERVERS = Arrays.asList(
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/dns-query", 
        "https://doh.360.cn/dns-query"
    );
    
    // 构造方法重载
    public DohResolver() {
        this(null, new DnsConfig());
    }
    
    public DohResolver(String dohServerUrl) {
        this(dohServerUrl, new DnsConfig());
    }
    
    public DohResolver(String dohServerUrl, DnsConfig config) {
        this.config = config;
        this.proxyHost = config.getProxyIP();
        this.proxyPort = config.getProxyPort();
        this.proxyType = config.getProxyType();
        this.proxyUsername = config.getProxyUsername();
        this.proxyPassword = config.getProxyPassword();
        this.proxyEnabled = config.hasProxy();
        
        // 构建HTTP客户端，支持代理配置
        this.httpClient = createHttpClient();
        
        // 初始化服务器列表
        if (dohServerUrl != null && !dohServerUrl.trim().isEmpty()) {
            this.dohServers = new ArrayList<>(BUILTIN_SERVERS);
            this.dohServers.add(0, dohServerUrl);
            logger.info("已指定DoH服务器: {}，同时保留内置服务器列表", dohServerUrl);
        } else {
            this.dohServers = new ArrayList<>(BUILTIN_SERVERS);
            logger.info("使用内置DoH服务器列表，共{}个服务器", dohServers.size());
        }
        
        // 记录代理配置信息
        logProxyConfiguration();
        
        logger.info("DoH解析器初始化完成，共有{}个服务器", dohServers.size());
        
        // 记录所有可用服务器
        if (logger.isInfoEnabled()) {
            logger.info("可用DoH服务器列表:");
            for (int i = 0; i < dohServers.size(); i++) {
                logger.info("  {}. {}", i + 1, dohServers.get(i));
            }
        }
    }
    
    /**
     * 创建支持SOCKS/HTTP代理的HTTP客户端
     */
    private OkHttpClient createHttpClient() {
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .connectionPool(new ConnectionPool(5, 2, TimeUnit.MINUTES));
        
        // 配置代理
        if (proxyEnabled) {
            configureProxy(clientBuilder);
        }
        
        return clientBuilder.build();
    }
    
    /**
     * 配置代理设置（支持SOCKS和HTTP）
     */
    private void configureProxy(OkHttpClient.Builder clientBuilder) {
        try {
            InetSocketAddress proxyAddress = new InetSocketAddress(proxyHost, proxyPort);
            Proxy proxy;
            
            if ("socks".equalsIgnoreCase(proxyType)) {
                proxy = new Proxy(Proxy.Type.SOCKS, proxyAddress);
                logger.info("已配置SOCKS代理服务器: {}:{}", proxyHost, proxyPort);
            } else {
                proxy = new Proxy(Proxy.Type.HTTP, proxyAddress);
                logger.info("已配置HTTP代理服务器: {}:{}", proxyHost, proxyPort);
            }
            
            clientBuilder.proxy(proxy);
            
            // 配置代理认证
            if (config.hasProxyAuth()) {
                configureProxyAuthentication(clientBuilder);
            }
            
        } catch (Exception e) {
            logger.error("配置代理服务器失败: {}:{} (类型: {})", 
                       proxyHost, proxyPort, proxyType, e);
        }
    }
    
    /**
     * 配置代理认证
     */
    private void configureProxyAuthentication(OkHttpClient.Builder clientBuilder) {
        // 为HTTP代理配置认证
        if (config.isHttpProxy() && config.hasProxyAuth()) {
            Authenticator proxyAuthenticator = new Authenticator() {
                @Override
                public Request authenticate(Route route, Response response) throws IOException {
                    if (response.request().header("Proxy-Authorization") != null) {
                        return null; // 已经尝试过认证，放弃
                    }
                    
                    String credential = Credentials.basic(proxyUsername, proxyPassword);
                    return response.request().newBuilder()
                        .header("Proxy-Authorization", credential)
                        .build();
                }
            };
            
            clientBuilder.proxyAuthenticator(proxyAuthenticator);
            logger.info("已配置HTTP代理认证: 用户名为 {}", proxyUsername);
        }
        
        // 为SOCKS代理设置系统属性
        if (config.isSocksProxy() && config.hasProxyAuth()) {
            System.setProperty("java.net.socks.username", proxyUsername);
            System.setProperty("java.net.socks.password", proxyPassword);
            logger.info("已配置SOCKS代理认证: 用户名为 {}", proxyUsername);
        }
    }
    
    /**
     * 记录代理配置信息
     */
    private void logProxyConfiguration() {
        if (proxyEnabled) {
            String authInfo = config.hasProxyAuth() ? 
                String.format(" (认证用户: %s)", proxyUsername) : " (无认证)";
            logger.info("代理配置: {} {}:{}{}", 
                       proxyType.toUpperCase(), proxyHost, proxyPort, authInfo);
        } else {
            logger.info("代理配置: 未启用");
        }
    }
    
    /**
     * 解析DNS查询请求
     */
    public DnsMessage resolve(DnsMessage request) throws IOException {
        byte[] requestData = encodeDnsMessage(request);
        
        // 记录查询信息用于调试
        if (!request.getQuestions().isEmpty()) {
            String domain = request.getQuestions().get(0).getName();
            String type = request.getQuestions().get(0).getType().toString();
            logger.debug("开始解析DNS查询: {} {} [服务器: {}, 代理: {}]", 
                        domain, type, getCurrentServer(), proxyEnabled ? "是" : "否");
        }
        
        for (int i = 0; i < dohServers.size(); i++) {
            String dohServer = dohServers.get(currentServerIndex);
            logger.debug("尝试使用DoH服务器 {} 查询", dohServer);
            
            try {
                DnsMessage response = doQuery(dohServer, requestData);
                if (response != null) {
                    logger.debug("DoH查询成功，服务器: {}", dohServer);
                    return response;
                }
            } catch (IOException e) {
                logger.warn("DoH服务器 {} 查询失败 (尝试 {}/{}): {}", 
                           dohServer, i + 1, dohServers.size(), e.getMessage());
                
                // 切换到下一个服务器
                currentServerIndex = (currentServerIndex + 1) % dohServers.size();
                
                if (i == dohServers.size() - 1) {
                    logger.error("所有DoH服务器查询失败");
                    throw new IOException("所有DoH服务器查询失败: " + e.getMessage(), e);
                }
            }
        }
        
        return null;
    }
    
    /**
     * 执行DoH查询
     */
    private DnsMessage doQuery(String dohServer, byte[] requestData) throws IOException {
        RequestBody body = RequestBody.create(requestData, DNS_MESSAGE_TYPE);
        Request request = new Request.Builder()
            .url(dohServer)
            .post(body)
            .addHeader("Content-Type", "application/dns-message")
            .addHeader("Accept", "application/dns-message")
            .addHeader("User-Agent", "DoH-DNS-Server/1.0")
            .build();
        
        // 增加重试机制
        int maxRetries = 2;
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    if (response.code() == 502 || response.code() == 503) {
                        logger.warn("DoH服务器 {} 返回 {}，尝试重试 {}/{}", 
                                   dohServer, response.code(), attempt + 1, maxRetries);
                        if (attempt < maxRetries) {
                            try {
                                Thread.sleep(1000); // 等待1秒后重试
                            } catch (InterruptedException ie) {
                                Thread.currentThread().interrupt();
                                throw new IOException("重试被中断", ie);
                            }
                            continue;
                        }
                    }
                    throw new IOException("HTTP请求失败: " + response.code() + " " + response.message());
                }
                
                byte[] responseData = response.body().bytes();
                return decodeDnsMessage(responseData);
                
            } catch (IOException e) {
                if (e.getMessage().contains("timed out") || e.getMessage().contains("reset")) {
                    logger.warn("DoH服务器 {} 连接异常，尝试重试 {}/{}: {}", 
                               dohServer, attempt + 1, maxRetries, e.getMessage());
                    if (attempt < maxRetries) {
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            throw new IOException("重试被中断", ie);
                        }
                        continue;
                    }
                }
                throw e;
            }
        }
        
        throw new IOException("所有重试尝试均失败");
    }
    
    /**
     * 编码DNS消息
     */
    private byte[] encodeDnsMessage(DnsMessage message) {
        try {
            return encodeDnsMessageInternal(message);
        } catch (Exception e) {
            logger.error("DNS消息编码失败: {}", e.getMessage());
            throw new RuntimeException("DNS编码错误", e);
        }
    }
    
    /**
     * 内部DNS消息编码实现
     */
    private byte[] encodeDnsMessageInternal(DnsMessage message) {
        try {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.io.DataOutputStream dos = new java.io.DataOutputStream(baos);
            
            // 写入头部
            dos.writeShort(message.getId());
            dos.writeShort(message.getFlags());
            dos.writeShort(message.getQuestions().size());
            dos.writeShort(message.getAnswers().size());
            dos.writeShort(0); // Authority count
            dos.writeShort(0); // Additional count
            
            // 写入问题部分
            for (DnsQuestion question : message.getQuestions()) {
                writeDomainName(dos, question.getName());
                dos.writeShort(question.getType().getValue());
                dos.writeShort(question.getClazz());
            }
            
            // 写入答案部分
            for (DnsRecord answer : message.getAnswers()) {
                writeDomainName(dos, answer.getName());
                dos.writeShort(answer.getType().getValue());
                dos.writeShort(answer.getClazz());
                dos.writeInt((int) answer.getTtl());
                
                byte[] data = getRecordData(answer);
                dos.writeShort(data.length);
                dos.write(data);
            }
            
            return baos.toByteArray();
            
        } catch (Exception e) {
            throw new RuntimeException("DNS编码失败", e);
        }
    }
    
    /**
     * 写入域名（QNAME格式）
     */
    private void writeDomainName(java.io.DataOutputStream dos, String domain) throws IOException {
        if (domain == null || domain.isEmpty()) {
            dos.writeByte(0);
            return;
        }
        
        String[] labels = domain.split("\\.");
        for (String label : labels) {
            if (label.isEmpty()) continue;
            dos.writeByte(label.length());
            dos.writeBytes(label);
        }
        dos.writeByte(0); // 结束标记
    }
    
    /**
     * 获取记录数据字节
     */
    private byte[] getRecordData(DnsRecord record) {
        try {
            switch (record.getType()) {
                case A:
                    return ipv4ToBytes(record.getData());
                case AAAA:
                    return ipv6ToBytes(record.getData());
                case CNAME:
                case PTR:
                case NS:
                    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                    java.io.DataOutputStream dos = new java.io.DataOutputStream(baos);
                    writeDomainName(dos, record.getData());
                    return baos.toByteArray();
                default:
                    return record.getData().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            }
        } catch (Exception e) {
            logger.warn("获取记录数据失败: {}", e.getMessage());
            return new byte[0];
        }
    }
    
    /**
     * IPv4地址转换为字节
     */
    private byte[] ipv4ToBytes(String ip) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + ip);
            }
            
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                int num = Integer.parseInt(parts[i]);
                if (num < 0 || num > 255) {
                    throw new IllegalArgumentException("Invalid IPv4 octet: " + num);
                }
                bytes[i] = (byte) num;
            }
            return bytes;
        } catch (Exception e) {
            logger.warn("IPv4地址转换失败: {}, 使用默认地址", ip);
            return new byte[] {0, 0, 0, 0}; // 返回默认地址
        }
    }
    
    /**
     * IPv6地址转换为字节（简化实现）
     */
    private byte[] ipv6ToBytes(String ip) {
        try {
            return java.net.InetAddress.getByName(ip).getAddress();
        } catch (Exception e) {
            logger.warn("IPv6地址转换失败: {}, 使用默认地址", ip);
            return new byte[16]; // 返回空的IPv6地址
        }
    }
    
    /**
     * 解码DNS消息
     */
    private DnsMessage decodeDnsMessage(byte[] data) {
        try {
            return decodeDnsMessageInternal(data);
        } catch (Exception e) {
            logger.error("DNS消息解码失败: {}", e.getMessage());
            throw new RuntimeException("DNS解码错误", e);
        }
    }
    
    /**
     * 内部DNS消息解码实现
     */
    private DnsMessage decodeDnsMessageInternal(byte[] data) {
        try {
            java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(data);
            java.io.DataInputStream dis = new java.io.DataInputStream(bais);
            
            // 读取头部
            int id = dis.readShort() & 0xFFFF;
            int flags = dis.readShort() & 0xFFFF;
            int questionCount = dis.readShort() & 0xFFFF;
            int answerCount = dis.readShort() & 0xFFFF;
            int authorityCount = dis.readShort() & 0xFFFF;
            int additionalCount = dis.readShort() & 0xFFFF;
            
            DnsMessage message = new DnsMessage();
            message.setId(id);
            message.setFlags(flags);
            
            // 读取问题部分
            for (int i = 0; i < questionCount; i++) {
                String name = readDomainName(dis);
                int typeValue = dis.readShort() & 0xFFFF;
                int clazz = dis.readShort() & 0xFFFF;
                
                DnsRecordType type = DnsRecordType.fromValue(typeValue);
                if (type == null) {
                    type = DnsRecordType.A; // 默认类型
                }
                
                message.addQuestion(new DnsQuestion(name, type, clazz));
            }
            
            // 读取答案部分
            for (int i = 0; i < answerCount; i++) {
                String name = readDomainName(dis);
                int typeValue = dis.readShort() & 0xFFFF;
                int clazz = dis.readShort() & 0xFFFF;
                long ttl = dis.readInt() & 0xFFFFFFFFL;
                int dataLength = dis.readShort() & 0xFFFF;
                
                DnsRecordType type = DnsRecordType.fromValue(typeValue);
                if (type == null) {
                    // 跳过未知类型的记录
                    if (dis.available() >= dataLength) {
                        dis.skipBytes(dataLength);
                    }
                    continue;
                }
                
                byte[] recordData = new byte[dataLength];
                dis.readFully(recordData);
                
                String dataStr = parseRecordData(type, recordData);
                message.addAnswer(new DnsRecord(name, type, clazz, ttl, dataStr));
            }
            
            return message;
            
        } catch (Exception e) {
            throw new RuntimeException("DNS解码失败", e);
        }
    }
    
    /**
     * 读取域名
     */
    private String readDomainName(java.io.DataInputStream dis) throws IOException {
        StringBuilder name = new StringBuilder();
        int length;
        while ((length = dis.readByte() & 0xFF) != 0) {
            if ((length & 0xC0) == 0xC0) {
                // 压缩指针，简化处理：跳过
                dis.readByte();
                break;
            }
            
            byte[] labelBytes = new byte[length];
            dis.readFully(labelBytes);
            if (name.length() > 0) {
                name.append(".");
            }
            name.append(new String(labelBytes, java.nio.charset.StandardCharsets.US_ASCII));
        }
        return name.toString();
    }
    
    /**
     * 解析记录数据
     */
    private String parseRecordData(DnsRecordType type, byte[] data) {
        try {
            switch (type) {
                case A:
                    if (data.length == 4) {
                        return String.format("%d.%d.%d.%d", 
                            data[0] & 0xFF, data[1] & 0xFF, data[2] & 0xFF, data[3] & 0xFF);
                    }
                    break;
                case AAAA:
                    if (data.length == 16) {
                        StringBuilder ipv6 = new StringBuilder();
                        for (int i = 0; i < 16; i += 2) {
                            if (i > 0) ipv6.append(":");
                            int segment = ((data[i] & 0xFF) << 8) | (data[i+1] & 0xFF);
                            ipv6.append(Integer.toHexString(segment));
                        }
                        return ipv6.toString();
                    }
                    break;
                case CNAME:
                case PTR:
                case NS:
                    // 简化处理：尝试读取域名
                    try {
                        java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(data);
                        java.io.DataInputStream dis = new java.io.DataInputStream(bais);
                        return readDomainName(dis);
                    } catch (Exception e) {
                        // 如果解析失败，返回原始字节的字符串表示
                        return new String(data, java.nio.charset.StandardCharsets.US_ASCII);
                    }
                default:
                    return new String(data, java.nio.charset.StandardCharsets.US_ASCII);
            }
        } catch (Exception e) {
            logger.warn("解析记录数据失败: {}", e.getMessage());
        }
        return new String(data, java.nio.charset.StandardCharsets.US_ASCII);
    }
    
    /**
     * 切换到下一个DoH服务器
     */
    public void switchToNextServer() {
        if (dohServers.size() > 1) {
            int oldIndex = currentServerIndex;
            currentServerIndex = (currentServerIndex + 1) % dohServers.size();
            logger.info("DoH服务器切换: {} -> {}", 
                       dohServers.get(oldIndex), dohServers.get(currentServerIndex));
        }
    }
    
    /**
     * 获取当前使用的DoH服务器
     */
    public String getCurrentServer() {
        if (dohServers.isEmpty()) {
            return "NO_SERVER_AVAILABLE";
        }
        return dohServers.get(currentServerIndex);
    }
    
    /**
     * 获取可用的DoH服务器列表
     */
    public List<String> getAvailableServers() {
        return new ArrayList<>(dohServers);
    }
    
    /**
     * 获取内置的DoH服务器列表
     */
    public static List<String> getBuiltinServers() {
        return new ArrayList<>(BUILTIN_SERVERS);
    }
    
    /**
     * 获取代理主机
     */
    public String getProxyHost() {
        return proxyHost;
    }
    
    /**
     * 获取代理端口
     */
    public int getProxyPort() {
        return proxyPort;
    }
    
    /**
     * 获取代理类型
     */
    public String getProxyType() {
        return proxyType;
    }
    
    /**
     * 检查是否启用了代理
     */
    public boolean isProxyEnabled() {
        return proxyEnabled;
    }
    
    /**
     * 检查是否有代理认证
     */
    public boolean hasProxyAuth() {
        return config.hasProxyAuth();
    }
    
    /**
     * 设置特定的服务器索引（用于测试和特定场景）
     */
    public void setCurrentServerIndex(int index) {
        if (index >= 0 && index < dohServers.size()) {
            currentServerIndex = index;
            logger.debug("手动设置当前服务器为: {}", dohServers.get(currentServerIndex));
        }
    }
    
    /**
     * 获取当前服务器索引
     */
    public int getCurrentServerIndex() {
        return currentServerIndex;
    }
    
    /**
     * 获取服务器数量
     */
    public int getServerCount() {
        return dohServers.size();
    }
    
    /**
     * 检查服务器列表是否为空
     */
    public boolean hasServers() {
        return !dohServers.isEmpty();
    }
    
    /**
     * 添加自定义DoH服务器
     */
    public void addCustomServer(String serverUrl) {
        if (serverUrl != null && !serverUrl.trim().isEmpty()) {
            dohServers.add(serverUrl.trim());
            logger.info("已添加自定义DoH服务器: {}", serverUrl);
        }
    }
    
    /**
     * 移除DoH服务器
     */
    public boolean removeServer(String serverUrl) {
        boolean removed = dohServers.remove(serverUrl);
        if (removed) {
            logger.info("已移除DoH服务器: {}", serverUrl);
            // 如果移除的是当前服务器，切换到下一个
            if (dohServers.size() > 0 && currentServerIndex >= dohServers.size()) {
                currentServerIndex = 0;
            }
        }
        return removed;
    }
    
    /**
     * 清空服务器列表（谨慎使用）
     */
    public void clearServers() {
        dohServers.clear();
        currentServerIndex = 0;
        logger.warn("已清空所有DoH服务器");
    }
    
    public void close() {
        if (httpClient != null) {
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        }
        logger.info("DoH解析器已关闭");
    }
}