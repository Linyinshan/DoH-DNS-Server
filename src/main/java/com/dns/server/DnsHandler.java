package com.dns.server;

import com.dns.dns.DnsMessage;
import com.dns.dns.DnsQuestion;
import com.dns.dns.DnsRecordType;
import com.dns.doh.DohResolver;
import com.dns.resolver.DomainBlocker;
import com.dns.resolver.HostFileResolver;
import com.dns.config.DnsConfig;
import com.dns.util.DnsResponseFactory;
import com.dns.util.LoggerUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class DnsHandler implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(DnsHandler.class);
    
    private static final ConcurrentHashMap<String, Long> requestCache = new ConcurrentHashMap<>();
    private static final long CACHE_DURATION = 1000L; // 1秒缓存
    
    // 依赖注入
    private final DatagramSocket socket;
    private final DatagramPacket requestPacket;
    private final DohResolver dohResolver;
    private final PtrResolutionStrategy ptrResolutionStrategy;
    private final DomainBlocker domainBlocker;
    private final HostFileResolver hostFileResolver;
    private final DnsConfig config;
    private final DnsResolutionContext context;
    private final QueryProcessor queryProcessor;
    
    public DnsHandler(DatagramSocket socket, DatagramPacket requestPacket,
                     DnsHandlerBuilder builder) {
        this.socket = socket;
        this.requestPacket = requestPacket;
        this.dohResolver = builder.getDohResolver();
        this.ptrResolutionStrategy = builder.getPtrResolutionStrategy();
        this.domainBlocker = builder.getDomainBlocker();
        this.hostFileResolver = builder.getHostFileResolver();
        this.config = builder.getConfig();
        this.context = builder.getContext();
        this.queryProcessor = new QueryProcessor(this);
    }
    
    @Override
    public void run() {
        try {
            queryProcessor.process();
        } catch (Exception e) {
            logger.error("DNS查询处理异常", e);
            context.incrementFailedQueries();
        }
    }
    
    /**
     * 内部查询处理器
     */
    private class QueryProcessor {
        private final DnsHandler handler;
        private String clientIp;
        private String domain;
        private String queryType;
        private long startTime;
        private int requestId;
        
        public QueryProcessor(DnsHandler handler) {
            this.handler = handler;
        }
        
        public void process() throws IOException {
            startTime = System.currentTimeMillis();
            clientIp = requestPacket.getAddress().getHostAddress();
            
            // 1. 检查请求去重
            if (isDuplicateRequest()) {
                context.incrementDuplicateQueries();
                return;
            }
            
            context.incrementTotalQueries();
            
            // 2. 检查配置重新加载
            if (config.needsReload()) {
                reloadConfig();
            }
            
            // 3. 解码DNS请求
            DnsMessage request = decodeRequest();
            if (request == null) {
                sendErrorResponse();
                return;
            }
            
            // 4. 处理查询
            DnsMessage response = handleQuery(request);
            
            // 5. 发送响应
            sendResponse(response, "SUCCESS", getSource(response));
        }
        
        private boolean isDuplicateRequest() {
            String requestKey = generateRequestKey();
            long currentTime = System.currentTimeMillis();
            
            // 清理过期缓存
            cleanupRequestCache(currentTime);
            
            Long previousTime = requestCache.get(requestKey);
            if (previousTime != null && (currentTime - previousTime) < CACHE_DURATION) {
                logger.debug("检测到重复请求，跳过处理: {}", requestKey);
                return true;
            }
            
            requestCache.put(requestKey, currentTime);
            return false;
        }
        
        private void cleanupRequestCache(long currentTime) {
            // 定期清理过期缓存（每100次请求清理一次）
            if (context.getDohQueryCount() % 100 == 0) {
                long cleanupThreshold = currentTime - CACHE_DURATION * 2;
                requestCache.entrySet().removeIf(entry -> entry.getValue() < cleanupThreshold);
            }
        }
        
        private String generateRequestKey() {
            String clientInfo = requestPacket.getAddress().getHostAddress() + ":" + requestPacket.getPort();
            int dataHash = java.util.Arrays.hashCode(
                java.util.Arrays.copyOf(requestPacket.getData(), Math.min(requestPacket.getLength(), 100))
            );
            return clientInfo + "#" + dataHash;
        }
        
        private void reloadConfig() {
            try {
                config.loadConfig();
                // 这里需要重新初始化PTR策略
                logger.info("配置已重新加载，当前服务器: {}", context.getCurrentDohServer());
            } catch (Exception e) {
                logger.error("重新加载配置失败", e);
            }
        }
        
        private DnsMessage decodeRequest() throws IOException {
            byte[] requestData = new byte[requestPacket.getLength()];
            System.arraycopy(requestPacket.getData(), requestPacket.getOffset(),
                           requestData, 0, requestPacket.getLength());
            
            // 调用DnsClient解码（需要确保DnsClient类存在）
            DnsMessage request = DnsClient.decodeDnsMessage(requestData);
            
            if (request == null || request.getQuestions().isEmpty()) {
                logger.warn("来自{}的DNS查询解码失败或为空", clientIp);
                return null;
            }
            
            DnsQuestion question = request.getQuestions().get(0);
            domain = question.getName();
            
            DnsRecordType recordType = question.getType();
            if (recordType == null) {
                logger.warn("来自{}的DNS查询中发现空记录类型，域名: {}", clientIp, domain);
                queryType = "UNKNOWN";
                return null;
            }
            queryType = recordType.toString();
            requestId = request.getId();
            
            return request;
        }
        
        private DnsMessage handleQuery(DnsMessage request) {
            String queryDomain = domain.toLowerCase();
            
            logger.debug("处理DNS查询: {} {} 来自{} [服务器: {}]", 
                        domain, queryType, clientIp, context.getCurrentDohServer());
            
            // 1. 检查域名是否被屏蔽
            if (domainBlocker.isBlocked(queryDomain)) {
                context.incrementBlockedQueries();
                // 修改：替换QueryLogger.logBlocked为LoggerUtil.logQuery，状态设为"BLOCKED"
                long responseTime = System.currentTimeMillis() - startTime;
                LoggerUtil.logQuery(clientIp, domain, queryType, responseTime, 
                                  "BLOCKED", "BLOCKED", requestId, context.getCurrentDohServer());
                return DnsResponseFactory.createBlockedResponse(request, getBlockedIp(request));
            }
            
            // 2. 优先检查hosts文件
            if (shouldCheckHostFile(request)) {
                DnsMessage hostResponse = hostFileResolver.resolve(request);
                if (hostResponse != null && !hostResponse.getAnswers().isEmpty()) {
                    context.incrementHostFileHits();
                    return hostResponse;
                }
            }
            
            // 3. 处理PTR查询（使用策略模式）
            if (request.getQuestions().get(0).getType() == DnsRecordType.PTR) {
                return handlePtrQuery(request);
            }
            
            // 4. 使用DoH服务器
            return handleDohQuery(request);
        }
        
        private boolean shouldCheckHostFile(DnsMessage request) {
            DnsRecordType type = request.getQuestions().get(0).getType();
            return type == DnsRecordType.A || type == DnsRecordType.AAAA;
        }
        
        private String getBlockedIp(DnsMessage request) {
            DnsRecordType type = request.getQuestions().get(0).getType();
            return type == DnsRecordType.AAAA ? "::" : "0.0.0.0";
        }
        
        private DnsMessage handlePtrQuery(DnsMessage request) {
            try {
                DnsMessage response = ptrResolutionStrategy.resolve(request, clientIp);
                if (response != null && !response.getAnswers().isEmpty()) {
                    context.incrementPtrHits();
                    return response;
                }
                return DnsResponseFactory.createNotFoundResponse(request);
            } catch (Exception e) {
                logger.error("PTR查询处理失败: {} - {}", domain, e.getMessage());
                return DnsResponseFactory.createErrorResponse(request, "PTR query failed");
            }
        }
        
        private DnsMessage handleDohQuery(DnsMessage request) {
            // 检查并切换服务器
            if (context.isAutoSwitchEnabled()) {
                checkAndSwitchDohServer();
            }
            
            try {
                DnsMessage response = dohResolver.resolve(request);
                if (response != null && !response.getAnswers().isEmpty()) {
                    context.incrementDohHits();
                    context.incrementDohQueryCount();
                    return response;
                }
                return DnsResponseFactory.createNotFoundResponse(request);
            } catch (Exception e) {
                logger.error("DoH解析失败: {} {} [服务器: {}]", domain, e.getMessage(), 
                           context.getCurrentDohServer());
                
                // 重试机制
                return retryWithNextServer(request, e);
            }
        }
        
        private void checkAndSwitchDohServer() {
            if (context.isAutoSwitchEnabled() && context.getDohServerList().size() > 1) {
                // 添加获取查询计数的方法调用（需要添加到DnsResolutionContext中）
                long dohQueryCount = context.getDohQueryCount();
                long lastSwitchCount = context.getLastSwitchQueryCount();
                long sinceLastSwitch = dohQueryCount - lastSwitchCount;
                
                if (sinceLastSwitch >= context.getSwitchThreshold()) {
                    context.switchToNextServer(false);
                    LoggerUtil.logDohServerSwitch("", context.getCurrentDohServer(),
                                                  dohQueryCount, false);
                }
            }
        }
        
        private DnsMessage retryWithNextServer(DnsMessage request, Exception originalError) {

            if (context.isAutoSwitchEnabled() && context.getDohServerList().size() > 1) {
                logger.info("DoH查询失败，尝试切换到下一个服务器");
                context.switchToNextServer(true);
                
                // 修改：替换QueryLogger.logDohServerSwitch为LoggerUtil.logDohServerSwitch
                LoggerUtil.logDohServerSwitch("", context.getCurrentDohServer(), 
                                             context.getDohQueryCount(), true);
                
                try {
                    DnsMessage response = dohResolver.resolve(request);
                    if (response != null && !response.getAnswers().isEmpty()) {
                        context.incrementDohHits();
                        context.incrementDohQueryCount();
                        return response;
                    }
                } catch (Exception retryException) {
                    logger.error("重试也失败: {} [服务器: {}]", domain, context.getCurrentDohServer());
                }
            }
            
            return DnsResponseFactory.createServFailResponse(request);
        }
        
        private String getSource(DnsMessage response) {
            // 根据响应类型确定来源
            if (response.getFlags() == 0x8182) return "DOH_FAILED_SERVFAIL";
            if ((response.getFlags() & 0x0003) == 0x0003) return "NOT_FOUND";
            if (response.getAnswers().isEmpty()) return "EMPTY_RESPONSE";
            return "DOH_SERVER";
        }
        
        private void sendResponse(DnsMessage response, String status, String source) throws IOException {
            byte[] responseData = DnsClient.encodeDnsMessage(response);
            
            DatagramPacket responsePacket = new DatagramPacket(
                responseData, responseData.length,
                requestPacket.getAddress(), requestPacket.getPort()
            );
            
            socket.send(responsePacket);
            
            long responseTime = System.currentTimeMillis() - startTime;
            if ("SUCCESS".equals(status)) {
                context.incrementSuccessfulQueries();
                LoggerUtil.logQuery(clientIp, domain, queryType, responseTime, 
                                  "SUCCESS", source, requestId, context.getCurrentDohServer());
            } else {
                context.incrementFailedQueries();
                LoggerUtil.logQuery(clientIp, domain, queryType, responseTime, 
                                  status, source, requestId, context.getCurrentDohServer());
            }
        }
        
        private void sendErrorResponse() throws IOException {
            byte[] requestData = requestPacket.getData();
            byte[] errorResponse = new byte[Math.min(requestData.length, 12)];
            System.arraycopy(requestData, 0, errorResponse, 0, errorResponse.length);
            
            errorResponse[2] = (byte) 0x81;
            errorResponse[3] = (byte) 0x83;
            
            DatagramPacket errorPacket = new DatagramPacket(
                errorResponse, errorResponse.length,
                requestPacket.getAddress(), requestPacket.getPort()
            );
            
            socket.send(errorPacket);
            
            long responseTime = System.currentTimeMillis() - startTime;
            LoggerUtil.logQuery(clientIp, domain, queryType, responseTime, 
                              "FAILED", "ERROR", 0, context.getCurrentDohServer());
        }
    }
    
    /**
     * 建造者类
     */
    public static class DnsHandlerBuilder {
        private DatagramSocket socket;
        private DatagramPacket requestPacket;
        private DohResolver dohResolver;
        private PtrResolutionStrategy ptrResolutionStrategy;
        private DomainBlocker domainBlocker;
        private HostFileResolver hostFileResolver;
        private DnsConfig config;
        private DnsResolutionContext context;
        
        public DnsHandlerBuilder setSocket(DatagramSocket socket) {
            this.socket = socket;
            return this;
        }
        
        public DnsHandlerBuilder setRequestPacket(DatagramPacket requestPacket) {
            this.requestPacket = requestPacket;
            return this;
        }
        
        public DnsHandlerBuilder setDohResolver(DohResolver dohResolver) {
            this.dohResolver = dohResolver;
            return this;
        }
        
        public DnsHandlerBuilder setPtrResolutionStrategy(PtrResolutionStrategy strategy) {
            this.ptrResolutionStrategy = strategy;
            return this;
        }
        
        public DnsHandlerBuilder setDomainBlocker(DomainBlocker blocker) {
            this.domainBlocker = blocker;
            return this;
        }
        
        public DnsHandlerBuilder setHostFileResolver(HostFileResolver resolver) {
            this.hostFileResolver = resolver;
            return this;
        }
        
        public DnsHandlerBuilder setConfig(DnsConfig config) {
            this.config = config;
            return this;
        }
        
        public DnsHandlerBuilder setContext(DnsResolutionContext context) {
            this.context = context;
            return this;
        }
        
        public DnsHandler build() {
            return new DnsHandler(socket, requestPacket, this);
        }
        
        // Getter方法供DnsHandler构造函数使用
        DohResolver getDohResolver() { return dohResolver; }
        PtrResolutionStrategy getPtrResolutionStrategy() { return ptrResolutionStrategy; }
        DomainBlocker getDomainBlocker() { return domainBlocker; }
        HostFileResolver getHostFileResolver() { return hostFileResolver; }
        DnsConfig getConfig() { return config; }
        DnsResolutionContext getContext() { return context; }
    }
    
    // 静态方法（供管理接口使用）
    public static String getCurrentDohServer() {
        return DnsResolutionContext.getInstance().getCurrentDohServer();
    }
    
    public static void manualSwitchToNextServer() {
        DnsResolutionContext.getInstance().switchToNextServer(false);
    }
    
    public static String getDetailedStatistics() {
        return DnsResolutionContext.getInstance().getDetailedStatistics();
    }
    
    public static void resetStatistics() {
        DnsResolutionContext.getInstance().resetStatistics();
    }
    
    public static long getTotalQueries() {
        return DnsResolutionContext.getInstance().getTotalQueries();
    }
    
    public static long getSuccessfulQueries() {
        return DnsResolutionContext.getInstance().getSuccessfulQueries();
    }
    
    public static long getFailedQueries() {
        return DnsResolutionContext.getInstance().getFailedQueries();
    }
    
    public static long getHostFileHits() {
        return DnsResolutionContext.getInstance().getHostFileHits();
    }
    
    public static long getPtrHits() {
        return DnsResolutionContext.getInstance().getPtrHits();
    }
    
    public static long getDohHits() {
        return DnsResolutionContext.getInstance().getDohHits();
    }
    
    public static long getBlockedQueries() {
        return DnsResolutionContext.getInstance().getBlockedQueries();
    }
    
    public static long getDuplicateQueries() {
        return DnsResolutionContext.getInstance().getDuplicateQueries();
    }
    
    public static long getDohQueryCount() {
        return DnsResolutionContext.getInstance().getDohQueryCount();
    }
    
    public static void reinitializeFromConfig(DnsConfig config) {
        DnsResolutionContext context = DnsResolutionContext.getInstance();
        context.initializeServerList(config.getDohServers(), config.isAutoSwitchEnabled());
        logger.info("服务器列表已根据配置重新初始化");
    }
}