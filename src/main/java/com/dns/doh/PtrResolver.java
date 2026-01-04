package com.dns.doh;

import com.dns.dns.DnsMessage;
import com.dns.dns.DnsRecord;
import com.dns.dns.DnsRecordType;
import com.dns.dns.DnsQuestion;
import com.dns.config.DnsConfig;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class PtrResolver {
    private static final Logger logger = LoggerFactory.getLogger(PtrResolver.class);
    
    private OkHttpClient httpClient;
    private final DnsConfig config;
    
    // 支持PTR查询的DoH服务器列表
    private List<String> ptrDohServers;
    
    // 在PtrResolver中添加本地映射
    private Map<String, String> localPtrMappings = Map.of(
        "1.0.0.127.in-addr.arpa", "localhost",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", "localhost"
    );
    
    // 内置的PTR DoH服务器列表
    private static final List<String> DEFAULT_PTR_SERVERS = Arrays.asList(
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/dns-query", 
        "https://doh.360.cn/dns-query"
    );
    
    public PtrResolver() {
        this(new DnsConfig());
    }
    
    public PtrResolver(DnsConfig config) {
        this.config = config;
        initializeHttpClient();
        initializePtrServers();
        logger.info("PTR解析器初始化完成，共有{}个服务器，代理: {}", 
                   ptrDohServers.size(), config.hasProxy() ? 
                   config.getProxyIP() + ":" + config.getProxyPort() : "未启用");
    }
    
/**
     * 初始化HTTP客户端（支持SOCKS/HTTP代理和认证）
     */
    private void initializeHttpClient() {
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true);
        
        // 配置代理
        if (config.hasProxy()) {
            configureProxy(clientBuilder);
        }
        
        clientBuilder.connectionPool(new ConnectionPool(5, 2, TimeUnit.MINUTES));
        this.httpClient = clientBuilder.build();
    }
    
    /**
     * 配置代理设置
     */
    private void configureProxy(OkHttpClient.Builder clientBuilder) {
        try {
            InetSocketAddress proxyAddress = new InetSocketAddress(
                config.getProxyIP(), config.getProxyPort());
            Proxy proxy;
            
            if (config.isSocksProxy()) {
                proxy = new Proxy(Proxy.Type.SOCKS, proxyAddress);
                logger.info("PTR解析器已配置SOCKS代理: {}:{}", 
                           config.getProxyIP(), config.getProxyPort());
            } else {
                proxy = new Proxy(Proxy.Type.HTTP, proxyAddress);
                logger.info("PTR解析器已配置HTTP代理: {}:{}", 
                           config.getProxyIP(), config.getProxyPort());
            }
            
            clientBuilder.proxy(proxy);
            
            // 配置代理认证
            if (config.hasProxyAuth()) {
                Authenticator proxyAuthenticator = new Authenticator() {
                    @Override
                    public Request authenticate(Route route, Response response) throws IOException {
                        if (response.request().header("Proxy-Authorization") != null) {
                            return null;
                        }
                        
                        String credential = Credentials.basic(
                            config.getProxyUsername(), config.getProxyPassword());
                        return response.request().newBuilder()
                            .header("Proxy-Authorization", credential)
                            .build();
                    }
                };
                
                clientBuilder.proxyAuthenticator(proxyAuthenticator);
                logger.info("PTR解析器已配置代理认证");
            }
            
        } catch (Exception e) {
            logger.error("PTR解析器配置代理失败: {}:{}", 
                       config.getProxyIP(), config.getProxyPort(), e);
        }
    }
    
    /**
     * 初始化PTR服务器列表
     */
    private void initializePtrServers() {
        // 首先尝试使用配置的DoH服务器
        List<String> configuredServers = config.getDohServers();
        
        if (!configuredServers.isEmpty()) {
            ptrDohServers = new ArrayList<>(configuredServers);
            logger.info("PTR解析器使用配置的DoH服务器列表: {}个", ptrDohServers.size());
        } else {
            // 使用默认的PTR服务器列表
            ptrDohServers = new ArrayList<>(DEFAULT_PTR_SERVERS);
            logger.info("PTR解析器使用默认服务器列表: {}个", ptrDohServers.size());
        }
        
        // 记录所有可用服务器
        if (logger.isDebugEnabled()) {
            logger.debug("PTR解析器可用服务器列表:");
            for (int i = 0; i < ptrDohServers.size(); i++) {
                logger.debug("  {}. {}", i + 1, ptrDohServers.get(i));
            }
        }
    }
    
    /**
     * 解析PTR查询 - 修复版本
     */
    public DnsMessage resolvePtrQuery(DnsMessage query) throws IOException {
        if (query.getQuestions().isEmpty()) {
            throw new IllegalArgumentException("PTR query must contain at least one question");
        }
        
        String ptrDomain = query.getQuestions().get(0).getName();
        
        // 检查本地映射
        if (localPtrMappings.containsKey(ptrDomain)) {
            logger.debug("使用本地PTR映射: {} -> {}", ptrDomain, localPtrMappings.get(ptrDomain));
            return generateLocalPtrResponse(query, localPtrMappings.get(ptrDomain));
        }
        
        logger.debug("解析PTR查询: {}", ptrDomain);
        
        // 尝试多个服务器，直到成功或全部失败
        IOException lastException = null;
        
        for (int i = 0; i < ptrDohServers.size(); i++) {
            String dohServer = ptrDohServers.get(i);
            
            try {
                logger.debug("尝试使用PTR服务器 {}/{}: {}", i + 1, ptrDohServers.size(), dohServer);
                DnsMessage result = resolveWithServer(ptrDomain, query.getId(), dohServer);
                
                if (result != null && !result.getAnswers().isEmpty()) {
                    logger.info("PTR查询成功: {} -> {} 条记录 [服务器: {}]", 
                               ptrDomain, result.getAnswers().size(), dohServer);
                    return result;
                } else {
                    logger.debug("PTR服务器返回空结果: {}", dohServer);
                }
                
            } catch (IOException e) {
                lastException = e;
                logger.warn("PTR服务器 {} 查询失败 (尝试 {}/{}): {}", 
                           dohServer, i + 1, ptrDohServers.size(), e.getMessage());
                
                // 如果不是最后一个服务器，继续尝试
                if (i < ptrDohServers.size() - 1) {
                    logger.debug("尝试下一个PTR服务器...");
                }
            }
        }
        
        // 所有服务器都失败
        String errorMsg = "所有PTR服务器查询失败";
        if (lastException != null) {
            errorMsg += ": " + lastException.getMessage();
        }
        throw new IOException(errorMsg, lastException);
    }
    
    /**
     * 使用指定的DoH服务器解析PTR查询
     */
    private DnsMessage resolveWithServer(String ptrDomain, int queryId, String dohServerUrl) throws IOException {
        // 构建PTR查询URL
        String url = buildPtrDohUrl(ptrDomain, dohServerUrl);
        
        logger.debug("发送PTR DoH查询到: {}", url);
        
        Request request = new Request.Builder()
            .url(url)
            .header("Accept", "application/dns-json")
            .header("User-Agent", "DoH-DNS-Server/1.0")
            .addHeader("Cache-Control", "no-cache")
            .build();
        
        int maxRetries = config.getInt("ptr_max_retries", 2);
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    String errorMsg = "HTTP请求失败: " + response.code() + " " + response.message();
                    
                    // 可重试的错误码
                    if (isRetryableError(response.code()) && attempt < maxRetries) {
                        logger.warn("PTR服务器 {} 返回 {}，尝试重试 {}/{}", 
                                   dohServerUrl, response.code(), attempt + 1, maxRetries);
                        waitBeforeRetry(attempt);
                        continue;
                    }
                    
                    throw new IOException(errorMsg);
                }
                
                ResponseBody body = response.body();
                if (body == null) {
                    throw new IOException("PTR DoH响应内容为空");
                }
                
                String responseBody = body.string();
                return parsePtrDohResponse(responseBody, queryId, ptrDomain, dohServerUrl);
                
            } catch (IOException e) {
                if (isRetryableException(e) && attempt < maxRetries) {
                    logger.warn("PTR服务器 {} 连接异常，尝试重试 {}/{}: {}", 
                               dohServerUrl, attempt + 1, maxRetries, e.getMessage());
                    waitBeforeRetry(attempt);
                    continue;
                }
                throw e;
            }
        }
        
        throw new IOException("所有重试尝试均失败");
    }
    
    /**
     * 构建PTR查询的DoH URL
     */
    private String buildPtrDohUrl(String ptrDomain, String dohServer) {
        String encodedDomain = URLEncoder.encode(ptrDomain, StandardCharsets.UTF_8);
        
        // 根据服务器类型构建不同的URL格式
        if (dohServer.contains("?")) {
            // 服务器URL已包含参数
            return String.format("%s&name=%s&type=PTR", dohServer, encodedDomain);
        } else {
            // 标准格式
            return String.format("%s?name=%s&type=PTR", dohServer, encodedDomain);
        }
    }
    
    /**
     * 解析PTR查询的DoH JSON响应
     */
    private DnsMessage parsePtrDohResponse(String jsonResponse, int queryId, 
                                          String originalPtrDomain, String serverUrl) {
        try {
            JsonObject json = JsonParser.parseString(jsonResponse).getAsJsonObject();
            
            DnsMessage response = new DnsMessage();
            response.setId(queryId);
            
            // 设置响应标志
            int flags = 0x8000; // QR=1 (响应)
            if (json.has("Status")) {
                int status = json.get("Status").getAsInt();
                if (status == 0) {
                    flags |= 0x8000; // 成功
                } else if (status == 3) {
                    flags |= 0x8003; // NXDOMAIN
                } else {
                    flags |= 0x8002; // SERVFAIL
                }
            } else {
                flags |= 0x8080; // 默认成功，RA=1
            }
            response.setFlags(flags);
            
            // 添加原始问题（回显）
            response.addQuestion(new DnsQuestion(originalPtrDomain, DnsRecordType.PTR, 1));
            
            // 解析Answer部分
            if (json.has("Answer")) {
                JsonArray answers = json.getAsJsonArray("Answer");
                int validAnswerCount = 0;
                
                for (JsonElement answerElem : answers) {
                    JsonObject answer = answerElem.getAsJsonObject();
                    
                    try {
                        String name = answer.has("name") ? answer.get("name").getAsString() : originalPtrDomain;
                        int typeValue = answer.get("type").getAsInt();
                        int clazz = 1; // IN
                        long ttl = answer.has("TTL") ? answer.get("TTL").getAsLong() : 300L;
                        String data = answer.get("data").getAsString();
                        
                        if (typeValue == DnsRecordType.PTR.getValue()) {
                            DnsRecord ptrRecord = new DnsRecord(
                                name, 
                                DnsRecordType.PTR, 
                                clazz, 
                                ttl, 
                                data.endsWith(".") ? data : data + "."
                            );
                            response.addAnswer(ptrRecord);
                            validAnswerCount++;
                            
                            logger.debug("解析到PTR记录: {} -> {}", name, data);
                        }
                    } catch (Exception e) {
                        logger.warn("解析PTR应答记录失败: {}", e.getMessage());
                    }
                }
                
                logger.debug("从 {} 解析到 {} 个有效的PTR记录", serverUrl, validAnswerCount);
            }
            
            // 如果没有找到答案，记录调试信息
            if (response.getAnswers().isEmpty()) {
                logger.debug("未找到PTR记录: {} [服务器: {}]", originalPtrDomain, serverUrl);
                
                // 检查是否有权威信息
                if (json.has("Authority") && json.getAsJsonArray("Authority").size() > 0) {
                    logger.debug("服务器返回了权威信息但无答案记录");
                }
            }
            
            return response;
            
        } catch (Exception e) {
            logger.error("解析PTR DoH响应失败: {}", e.getMessage());
            throw new RuntimeException("PTR响应解析失败", e);
        }
    }
    
    /**
     * 生成本地的PTR响应
     */
    public DnsMessage generateLocalPtrResponse(DnsMessage query, String domainName) {
        DnsMessage response = new DnsMessage();
        response.setId(query.getId());
        response.setFlags(0x8180); // QR=1, RD=1, RA=1
        
        // 回显问题
        response.setQuestions(query.getQuestions());
        
        // 添加PTR答案
        if (!query.getQuestions().isEmpty()) {
            String ptrDomain = query.getQuestions().get(0).getName();
            DnsRecord ptrRecord = new DnsRecord(
                ptrDomain,
                DnsRecordType.PTR,
                1, // IN class
                300, // 5分钟TTL
                domainName.endsWith(".") ? domainName : domainName + "."
            );
            response.addAnswer(ptrRecord);
        }
        
        return response;
    }
    
    /**
     * 检查错误是否可重试
     */
    private boolean isRetryableError(int statusCode) {
        return statusCode == 502 || statusCode == 503 || statusCode == 504 || 
               statusCode == 429 || statusCode >= 500;
    }
    
    /**
     * 检查异常是否可重试
     */
    private boolean isRetryableException(Exception e) {
        String message = e.getMessage();
        return message != null && (
            message.contains("timed out") ||
            message.contains("reset") ||
            message.contains("timeout") ||
            message.contains("connection") ||
            message.contains("socket")
        );
    }
    
    /**
     * 重试前等待
     */
    private void waitBeforeRetry(int attempt) {
        try {
            long waitTime = Math.min(1000L * (attempt + 1), 5000L); // 指数退避，最大5秒
            Thread.sleep(waitTime);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("重试被中断", ie);
        }
    }
    
    /**
     * 获取当前使用的服务器列表
     */
    public List<String> getPtrServers() {
        return new ArrayList<>(ptrDohServers);
    }
    
    /**
     * 添加自定义PTR映射
     */
    public void addLocalPtrMapping(String ptrDomain, String domainName) {
        Map<String, String> newMappings = new HashMap<>(localPtrMappings);
        newMappings.put(ptrDomain.toLowerCase(), domainName);
        localPtrMappings = Collections.unmodifiableMap(newMappings);
        logger.info("添加本地PTR映射: {} -> {}", ptrDomain, domainName);
    }
    
    /**
     * 重新加载配置（用于热重载）
     */
    public synchronized void reloadConfig() {
        logger.info("重新加载PTR解析器配置");
        
        // 关闭旧的HTTP客户端
        if (httpClient != null) {
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        }
        
        // 重新初始化
        initializeHttpClient();
        initializePtrServers();
        
        logger.info("PTR解析器配置重载完成");
    }
    
    /**
     * 测试服务器连通性
     */
    public boolean testServerConnectivity(String serverUrl) {
        try {
            // 简单的连通性测试：查询本地反向域名
            String testDomain = "1.0.0.127.in-addr.arpa";
            String url = buildPtrDohUrl(testDomain, serverUrl);
            
            Request request = new Request.Builder()
                .url(url)
                .header("Accept", "application/dns-json")
                .header("User-Agent", "DoH-DNS-Server/1.0-Test")
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                boolean success = response.isSuccessful();
                logger.debug("PTR服务器 {} 连通性测试: {}", serverUrl, success ? "成功" : "失败");
                return success;
            }
        } catch (Exception e) {
            logger.debug("PTR服务器 {} 连通性测试失败: {}", serverUrl, e.getMessage());
            return false;
        }
    }
    
    /**
     * 获取服务器健康状态
     */
    public Map<String, Boolean> getServerHealthStatus() {
        Map<String, Boolean> healthStatus = new LinkedHashMap<>();
        
        for (String server : ptrDohServers) {
            boolean healthy = testServerConnectivity(server);
            healthStatus.put(server, healthy);
        }
        
        return healthStatus;
    }
    
    /**
     * 关闭资源
     */
    public void close() {
        if (httpClient != null) {
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        }
    }
    
    /**
     * 获取统计信息
     */
    public String getStats() {
        return String.format(
            "PTR解析器状态: 服务器数=%d, 代理=%s, 本地映射=%d",
            ptrDohServers.size(),
            config.hasProxy() ? config.getProxyIP() + ":" + config.getProxyPort() : "未启用",
            localPtrMappings.size()
        );
    }
}