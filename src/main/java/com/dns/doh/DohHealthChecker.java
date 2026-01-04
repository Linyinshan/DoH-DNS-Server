package com.dns.doh;

import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.dns.config.DnsConfig;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * DoH服务器健康检查器 - 增强版本
 * 支持SOCKS/HTTP代理、代理认证、多服务器健康检查、缓存结果等
 */
public class DohHealthChecker {
    private static final Logger logger = LoggerFactory.getLogger(DohHealthChecker.class);
    
    private final OkHttpClient httpClient;
    private final MediaType DNS_MESSAGE_TYPE = MediaType.parse("application/dns-message");
    
    // 配置字段
    private final DnsConfig config;
    private final String proxyHost;
    private final int proxyPort;
    private final String proxyType;
    private final String proxyUsername;
    private final String proxyPassword;
    private final boolean useProxy;
    
    // 健康状态缓存
    private final ConcurrentHashMap<String, ServerHealthStatus> healthCache = new ConcurrentHashMap<>();
    private final long cacheDuration = 30000; // 30秒缓存
    
    // 统计信息
    private final AtomicInteger totalChecks = new AtomicInteger(0);
    private final AtomicInteger failedChecks = new AtomicInteger(0);
    private final AtomicInteger successfulChecks = new AtomicInteger(0);
    
    /**
     * 服务器健康状态
     */
    private static class ServerHealthStatus {
        private final boolean healthy;
        private final long lastCheckTime;
        private final long responseTime;
        private final String errorMessage;
        
        public ServerHealthStatus(boolean healthy, long responseTime, String errorMessage) {
            this.healthy = healthy;
            this.lastCheckTime = System.currentTimeMillis();
            this.responseTime = responseTime;
            this.errorMessage = errorMessage;
        }
        
        public boolean isHealthy() { return healthy; }
        public long getLastCheckTime() { return lastCheckTime; }
        public long getResponseTime() { return responseTime; }
        public String getErrorMessage() { return errorMessage; }
        public boolean isExpired(long cacheDuration) {
            return System.currentTimeMillis() - lastCheckTime > cacheDuration;
        }
    }
    
    /**
     * 无参构造函数（不使用代理）
     */
    public DohHealthChecker() {
        this(new DnsConfig());
    }
    
    /**
     * 带配置的构造函数
     */
    public DohHealthChecker(DnsConfig config) {
        this.config = config;
        this.proxyHost = config.getProxyIP();
        this.proxyPort = config.getProxyPort();
        this.proxyType = config.getProxyType();
        this.proxyUsername = config.getProxyUsername();
        this.proxyPassword = config.getProxyPassword();
        this.useProxy = config.hasProxy();
        
        OkHttpClient.Builder clientBuilder = createHttpClientBuilder();
        this.httpClient = clientBuilder.build();
        
        logger.info("DoH健康检查器初始化完成，代理: {}", getProxyInfo());
    }
    
    /**
     * 创建支持SOCKS/HTTP代理的HTTP客户端
     */
    private OkHttpClient.Builder createHttpClientBuilder() {
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(5, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false) // 健康检查不重试
            .connectionPool(new ConnectionPool(3, 1, TimeUnit.MINUTES));
        
        // 配置代理
        if (useProxy) {
            configureProxy(clientBuilder);
        }
        
        return clientBuilder;
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
                logger.info("健康检查器已配置SOCKS代理: {}:{}", proxyHost, proxyPort);
            } else {
                proxy = new Proxy(Proxy.Type.HTTP, proxyAddress);
                logger.info("健康检查器已配置HTTP代理: {}:{}", proxyHost, proxyPort);
            }
            
            clientBuilder.proxy(proxy);
            
            // 配置代理认证
            if (config.hasProxyAuth()) {
                configureProxyAuthentication(clientBuilder);
            }
            
        } catch (Exception e) {
            logger.warn("健康检查器配置代理失败: {}:{} (类型: {}) - {}", 
                       proxyHost, proxyPort, proxyType, e.getMessage());
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
            logger.info("健康检查器已配置HTTP代理认证: 用户名为 {}", proxyUsername);
        }
        
        // 为SOCKS代理设置系统属性
        if (config.isSocksProxy() && config.hasProxyAuth()) {
            System.setProperty("java.net.socks.username", proxyUsername);
            System.setProperty("java.net.socks.password", proxyPassword);
            logger.info("健康检查器已配置SOCKS代理认证: 用户名为 {}", proxyUsername);
        }
    }
    
    /**
     * 检查单个DoH服务器是否健康
     */
    public boolean isServerHealthy(String dohServerUrl) {
        return isServerHealthy(dohServerUrl, false);
    }
    
    /**
     * 检查单个DoH服务器是否健康（可强制刷新）
     */
    public boolean isServerHealthy(String dohServerUrl, boolean forceCheck) {
        if (dohServerUrl == null || dohServerUrl.trim().isEmpty()) {
            logger.warn("DoH服务器URL为空，无法进行健康检查");
            return false;
        }
        
        // 检查缓存
        if (!forceCheck) {
            ServerHealthStatus cachedStatus = healthCache.get(dohServerUrl);
            if (cachedStatus != null && !cachedStatus.isExpired(cacheDuration)) {
                logger.debug("使用缓存健康状态: {} -> {} ({}ms)", 
                           dohServerUrl, cachedStatus.isHealthy() ? "健康" : "不健康", 
                           cachedStatus.getResponseTime());
                return cachedStatus.isHealthy();
            }
        }
        
        totalChecks.incrementAndGet();
        long startTime = System.currentTimeMillis();
        boolean healthy = false;
        String errorMessage = null;
        long responseTime = 0;
        
        try {
            // 创建测试DNS查询（查询根域名的A记录）
            byte[] testQuery = createDnsQuery(".", 1); // A记录查询根域名
            
            Request request = new Request.Builder()
                .url(dohServerUrl)
                .post(RequestBody.create(testQuery, DNS_MESSAGE_TYPE))
                .addHeader("Content-Type", "application/dns-message")
                .addHeader("Accept", "application/dns-message")
                .addHeader("User-Agent", "DoH-Health-Checker/1.0")
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                responseTime = System.currentTimeMillis() - startTime;
                
                if (response.isSuccessful()) {
                    healthy = true;
                    successfulChecks.incrementAndGet();
                    
                    // 验证响应内容
                    if (response.body() != null) {
                        byte[] responseData = response.body().bytes();
                        if (responseData.length < 12) {
                            healthy = false;
                            errorMessage = "响应数据过短: " + responseData.length + " 字节";
                        }
                    } else {
                        healthy = false;
                        errorMessage = "响应体为空";
                    }
                    
                    if (healthy) {
                        logger.debug("DoH服务器 {} 健康检查通过 ({}ms)", dohServerUrl, responseTime);
                    } else {
                        logger.warn("DoH服务器 {} 健康检查失败: {}", dohServerUrl, errorMessage);
                    }
                } else {
                    healthy = false;
                    errorMessage = "HTTP " + response.code() + " " + response.message();
                    logger.warn("DoH服务器 {} 健康检查失败: {}", dohServerUrl, errorMessage);
                }
            }
        } catch (IOException e) {
            responseTime = System.currentTimeMillis() - startTime;
            healthy = false;
            errorMessage = e.getMessage();
            failedChecks.incrementAndGet();
            logger.debug("DoH服务器 {} 健康检查异常: {}", dohServerUrl, errorMessage);
        } catch (Exception e) {
            responseTime = System.currentTimeMillis() - startTime;
            healthy = false;
            errorMessage = "Unexpected error: " + e.getMessage();
            failedChecks.incrementAndGet();
            logger.error("DoH服务器 {} 健康检查发生意外错误", dohServerUrl, e);
        }
        
        // 更新缓存
        ServerHealthStatus status = new ServerHealthStatus(healthy, responseTime, errorMessage);
        healthCache.put(dohServerUrl, status);
        
        return healthy;
    }
    
    /**
     * 批量检查服务器健康状态，返回健康服务器列表
     */
    public java.util.List<String> checkServers(java.util.List<String> servers) {
        return checkServers(servers, false);
    }
    
    /**
     * 批量检查服务器健康状态（可强制刷新缓存）
     */
    public java.util.List<String> checkServers(java.util.List<String> servers, boolean forceCheck) {
        if (servers == null || servers.isEmpty()) {
            return java.util.Collections.emptyList();
        }
        
        java.util.List<String> healthyServers = new java.util.ArrayList<>();
        logger.info("开始检查{}个DoH服务器的健康状态", servers.size());
        
        for (int i = 0; i < servers.size(); i++) {
            String server = servers.get(i);
            boolean healthy = isServerHealthy(server, forceCheck);
            
            ServerHealthStatus status = healthCache.get(server);
            long responseTime = status != null ? status.getResponseTime() : -1;
            
            if (healthy) {
                healthyServers.add(server);
                logger.info("服务器 {}. {} [健康] ({}ms)", i + 1, server, responseTime);
            } else {
                String error = status != null ? status.getErrorMessage() : "未知错误";
                logger.warn("服务器 {}. {} [不健康] - {}", i + 1, server, error);
            }
        }
        
        double healthRate = servers.size() > 0 ? (healthyServers.size() * 100.0 / servers.size()) : 0;
        logger.info("健康检查完成: {}/{} 个服务器健康 ({:.1f}%)", 
                   healthyServers.size(), servers.size(), healthRate);
        
        return healthyServers;
    }
    
    /**
     * 获取服务器健康状态详情
     */
    public ServerHealthInfo getServerHealthInfo(String dohServerUrl) {
        ServerHealthStatus status = healthCache.get(dohServerUrl);
        if (status == null) {
            // 强制检查一次
            isServerHealthy(dohServerUrl, true);
            status = healthCache.get(dohServerUrl);
        }
        
        return new ServerHealthInfo(
            dohServerUrl,
            status != null ? status.isHealthy() : false,
            status != null ? status.getLastCheckTime() : 0,
            status != null ? status.getResponseTime() : -1,
            status != null ? status.getErrorMessage() : "未检查"
        );
    }
    
    /**
     * 获取所有服务器的健康状态
     */
    public java.util.List<ServerHealthInfo> getAllServersHealthInfo(java.util.List<String> servers) {
        java.util.List<ServerHealthInfo> healthInfos = new java.util.ArrayList<>();
        for (String server : servers) {
            healthInfos.add(getServerHealthInfo(server));
        }
        return healthInfos;
    }
    
    /**
     * 清除健康状态缓存
     */
    public void clearCache() {
        healthCache.clear();
        logger.debug("健康检查缓存已清除");
    }
    
    /**
     * 清除指定服务器的缓存
     */
    public void clearCache(String dohServerUrl) {
        healthCache.remove(dohServerUrl);
        logger.debug("服务器 {} 的健康检查缓存已清除", dohServerUrl);
    }
    
    /**
     * 创建DNS查询数据包
     */
    private byte[] createDnsQuery(String domain, int type) {
        try {
            // 简单的DNS查询包构造
            return createSimpleDnsQuery(domain, type);
        } catch (Exception e) {
            logger.warn("创建DNS查询包失败，使用默认查询包", e);
            return createDefaultDnsQuery();
        }
    }
    
    /**
     * 创建简单的DNS查询包
     */
    private byte[] createSimpleDnsQuery(String domain, int type) {
        try {
            // 将域名转换为DNS格式
            String[] labels = domain.split("\\.");
            int totalLength = 12; // 头部长度
            
            // 计算域名长度
            for (String label : labels) {
                totalLength += 1 + label.length(); // 长度字节 + 标签
            }
            totalLength += 1; // 结束字节
            totalLength += 4; // 类型和类
            
            byte[] query = new byte[totalLength];
            
            // 设置ID
            query[0] = 0x00;
            query[1] = 0x01;
            
            // 设置标志：标准查询
            query[2] = 0x01; // QR=0, OPCODE=0
            query[3] = 0x00; // 其他标志为0
            
            // 问题数：1
            query[4] = 0x00;
            query[5] = 0x01;
            
            // 其他计数都为0
            for (int i = 6; i < 12; i++) {
                query[i] = 0x00;
            }
            
            // 编码域名
            int pos = 12;
            for (String label : labels) {
                query[pos++] = (byte) label.length();
                for (char c : label.toCharArray()) {
                    query[pos++] = (byte) c;
                }
            }
            query[pos++] = 0x00; // 域名结束
            
            // 查询类型
            query[pos++] = (byte) (type >> 8);
            query[pos++] = (byte) (type & 0xFF);
            
            // 查询类：IN
            query[pos++] = 0x00;
            query[pos++] = 0x01;
            
            return query;
            
        } catch (Exception e) {
            logger.warn("创建DNS查询包失败，使用默认查询包: {}", e.getMessage());
            return createDefaultDnsQuery();
        }
    }
    
    /**
     * 创建默认的DNS查询包（查询根域名的A记录）
     */
    private byte[] createDefaultDnsQuery() {
        // 硬编码的DNS查询包：查询根域名"."的A记录
        return new byte[] {
            0x00, 0x01,             // ID: 1
            0x01, 0x00,             // 标志：标准查询
            0x00, 0x01,             // 问题数：1
            0x00, 0x00,             // 回答数：0
            0x00, 0x00,             // 授权数：0
            0x00, 0x00,             // 附加数：0
            0x00,                   // 根域名（长度0）
            0x00, 0x01,             // 类型：A
            0x00, 0x01              // 类：IN
        };
    }
    
    /**
     * 获取健康检查统计信息
     */
    public HealthCheckStats getStats() {
        return new HealthCheckStats(
            totalChecks.get(),
            successfulChecks.get(),
            failedChecks.get(),
            healthCache.size()
        );
    }
    
    /**
     * 重置统计信息
     */
    public void resetStats() {
        totalChecks.set(0);
        successfulChecks.set(0);
        failedChecks.set(0);
        logger.info("健康检查统计信息已重置");
    }
    
    /**
     * 获取代理配置信息
     */
    public String getProxyInfo() {
        if (useProxy) {
            String authInfo = config.hasProxyAuth() ? 
                String.format(" (认证用户: %s)", proxyUsername) : " (无认证)";
            return String.format("%s %s:%s%s", 
                proxyType.toUpperCase(), proxyHost, proxyPort, authInfo);
        }
        return "未使用代理";
    }
    
    /**
     * 检查是否使用代理
     */
    public boolean isUsingProxy() {
        return useProxy;
    }
    
    public void close() {
        if (httpClient != null) {
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        }
        healthCache.clear();
        logger.info("DoH健康检查器已关闭");
    }
    
    /**
     * 服务器健康信息类
     */
    public static class ServerHealthInfo {
        private final String serverUrl;
        private final boolean healthy;
        private final long lastCheckTime;
        private final long responseTime;
        private final String errorMessage;
        
        public ServerHealthInfo(String serverUrl, boolean healthy, long lastCheckTime, 
                               long responseTime, String errorMessage) {
            this.serverUrl = serverUrl;
            this.healthy = healthy;
            this.lastCheckTime = lastCheckTime;
            this.responseTime = responseTime;
            this.errorMessage = errorMessage;
        }
        
        public String getServerUrl() { return serverUrl; }
        public boolean isHealthy() { return healthy; }
        public long getLastCheckTime() { return lastCheckTime; }
        public long getResponseTime() { return responseTime; }
        public String getErrorMessage() { return errorMessage; }
        
        @Override
        public String toString() {
            return String.format("ServerHealthInfo{serverUrl='%s', healthy=%s, responseTime=%dms, errorMessage='%s'}",
                               serverUrl, healthy, responseTime, errorMessage);
        }
    }
    
    /**
     * 健康检查统计信息类
     */
    public static class HealthCheckStats {
        private final int totalChecks;
        private final int successfulChecks;
        private final int failedChecks;
        private final int cachedEntries;
        
        public HealthCheckStats(int totalChecks, int successfulChecks, 
                               int failedChecks, int cachedEntries) {
            this.totalChecks = totalChecks;
            this.successfulChecks = successfulChecks;
            this.failedChecks = failedChecks;
            this.cachedEntries = cachedEntries;
        }
        
        public int getTotalChecks() { return totalChecks; }
        public int getSuccessfulChecks() { return successfulChecks; }
        public int getFailedChecks() { return failedChecks; }
        public int getCachedEntries() { return cachedEntries; }
        public double getSuccessRate() { 
            return totalChecks > 0 ? (successfulChecks * 100.0 / totalChecks) : 0; 
        }
        
        @Override
        public String toString() {
            return String.format("HealthCheckStats{total=%d, success=%d, failed=%d, successRate=%.1f%%, cached=%d}",
                               totalChecks, successfulChecks, failedChecks, getSuccessRate(), cachedEntries);
        }
    }
}