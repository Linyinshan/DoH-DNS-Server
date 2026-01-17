package com.dns.server;

import com.dns.dns.DnsMessage;
import com.dns.dns.DnsQuestion;
import com.dns.dns.DnsRecord;
import com.dns.dns.DnsRecordType;
import com.dns.doh.DohResolver;
import com.dns.doh.PtrResolver;
import com.dns.resolver.DomainBlocker;
import com.dns.resolver.HostFileResolver;
import com.dns.util.LoggerUtil;
import com.dns.config.DnsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class DnsHandler implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(DnsHandler.class);
    
    // 请求去重缓存（防止重复处理相同请求）
    private static final ConcurrentHashMap<String, Long> requestCache = new ConcurrentHashMap<>();
    private static final long CACHE_DURATION = 1000L; // 1秒去重窗口
    
    // DoH服务器列表和当前索引
    private static final CopyOnWriteArrayList<String> dohServerList = new CopyOnWriteArrayList<>();
    private static volatile int currentServerIndex = 0;
    private static volatile boolean autoSwitchEnabled = true;
    private static volatile int switchThreshold = 20;
    
    private final DatagramSocket socket;
    private final DatagramPacket requestPacket;
    private final DohResolver dohResolver;
    private final PtrResolver ptrResolver;
    private final DomainBlocker domainBlocker;
    private final HostFileResolver hostFileResolver;
    private final DnsConfig config;
    

    // 统计信息
    private static volatile long totalQueries = 0;
    private static volatile long successfulQueries = 0;
    private static volatile long failedQueries = 0;
    private static volatile long hostFileHits = 0;
    private static volatile long ptrHits = 0;
    private static volatile long dohHits = 0;
    private static volatile long blockedQueries = 0;
    private static volatile long dohQueryCount = 0;
    private static volatile long duplicateQueries = 0;
    private static volatile long configBasedSwitches = 0;
    
    // 当前服务器信息
    private static volatile String currentDohServer = "UNKNOWN";
    
    public DnsHandler(DatagramSocket socket, DatagramPacket requestPacket, 
                 DohResolver dohResolver, PtrResolver ptrResolver,
                 HostFileResolver hostFileResolver, DomainBlocker domainBlocker,
                 DnsConfig config) {
			this.socket = socket;
			this.requestPacket = requestPacket;
			this.dohResolver = dohResolver;
			this.ptrResolver = ptrResolver;
			this.hostFileResolver = hostFileResolver;
			this.domainBlocker = domainBlocker;
			this.config = config;
			
			// 初始化服务器列表
			initializeDohServers();
			
			// 更新当前服务器信息
			updateCurrentDohServer();
		}
			
    /**
     * 初始化DoH服务器列表
     */
    private synchronized void initializeDohServers() {
        if (!dohServerList.isEmpty()) {
            return; // 已经初始化
        }
        
        List<String> configuredServers = config.getDohServers();
        
        if (!configuredServers.isEmpty()) {
            // 使用配置的服务器
            dohServerList.clear();
            dohServerList.addAll(configuredServers);
            
            // 根据服务器数量决定自动切换
            if (configuredServers.size() > 1) {
                autoSwitchEnabled = true;
                logger.info("配置了{}个DoH服务器，启用自动切换", configuredServers.size());
            } else {
                autoSwitchEnabled = false;
                logger.info("配置了1个DoH服务器，禁用自动切换");
            }
        } else {
            // 使用内置服务器列表
            dohServerList.clear();
            dohServerList.addAll(DohResolver.getBuiltinServers());
            autoSwitchEnabled = config.isAutoSwitchEnabled();
        }
        
        // 设置切换阈值
        switchThreshold = Math.max(10, config.getInt("switch_threshold", 20));
        
        logger.info("DoH服务器列表初始化完成，共{}个服务器，自动切换：{}，切换阈值：{}", 
                   dohServerList.size(), autoSwitchEnabled ? "启用" : "禁用", switchThreshold);
        
        if (logger.isDebugEnabled()) {
            for (int i = 0; i < dohServerList.size(); i++) {
                logger.debug("  {}. {}", i + 1, dohServerList.get(i));
            }
        }
    }
    
    @Override
    public void run() {
        long startTime = System.currentTimeMillis();
        String clientIp = requestPacket.getAddress().getHostAddress();
        String domain = "";
        String queryType = "";
        int answerCount = 0;
        String source = "UNKNOWN";
        int requestId = 0;
        
        try {
            // 检查请求去重
            String requestKey = generateRequestKey(requestPacket);
            if (isDuplicateRequest(requestKey)) {
                duplicateQueries++;
                logger.debug("检测到重复请求，跳过处理: {}", requestKey);
                return;
            }
            
            totalQueries++;
            
            // 检查配置是否需要重新加载
            if (config.needsReload()) {
                reloadConfig();
            }
            
            // 解码DNS请求
            byte[] requestData = new byte[requestPacket.getLength()];
            System.arraycopy(requestPacket.getData(), requestPacket.getOffset(), 
                           requestData, 0, requestPacket.getLength());
            
            DnsMessage request = DnsClient.decodeDnsMessage(requestData);
            requestId = request.getId();
            
            if (request.getQuestions().isEmpty()) {
                logger.warn("来自{}的空DNS查询", clientIp);
                sendErrorResponse(requestPacket, clientIp, domain, queryType, startTime);
                return;
            }
            
            DnsQuestion question = request.getQuestions().get(0);
            domain = question.getName();
            
            DnsRecordType recordType = question.getType();
            if (recordType == null) {
                logger.warn("来自{}的DNS查询中发现空记录类型，域名: {}", clientIp, domain);
                queryType = "UNKNOWN";
                sendErrorResponse(requestPacket, clientIp, domain, queryType, startTime);
                return;
            }
            queryType = recordType.toString();
            
            String queryDomain = question.getName().toLowerCase();
            
            // 在调试日志中显示当前服务器和配置信息
            logger.debug("正在处理DNS查询: {} {} 来自{} [当前DoH服务器: {}, 自动切换: {}]", 
                        domain, queryType, clientIp, currentDohServer, 
                        autoSwitchEnabled ? "开启" : "关闭");
            
            DnsMessage response = null;
            
            // 第一步：检查域名是否被屏蔽
            if (domainBlocker.isBlocked(queryDomain)) {
                if (recordType == DnsRecordType.A) {
                    response = createBlockedResponse(request, "0.0.0.0");
                } else if (recordType == DnsRecordType.AAAA) {
                    response = createBlockedResponse(request, "::");
                } else {
                    response = createNotFoundResponse(request);
                }
                
                blockedQueries++;
                source = "BLOCKED";
                answerCount = response.getAnswers().size();
                
                logger.info("已屏蔽域名: {} {} -> {} (返回 {}) [服务器: {}]", 
                           domain, queryType, answerCount, 
                           recordType == DnsRecordType.A ? "0.0.0.0" : "::",
                           currentDohServer);
                
                sendResponse(response, clientIp, domain, queryType, startTime, source, requestId);
                return;
            }
            
            // 第二步：优先检查hosts文件
            if (recordType == DnsRecordType.A || recordType == DnsRecordType.AAAA) {
                if (hostFileResolver.containsDomain(queryDomain)) {
                    response = hostFileResolver.resolve(request);
                    if (response != null && response.getAnswers().size() > 0) {
                        hostFileHits++;
                        source = "HOST_FILE";
                        answerCount = response.getAnswers().size();
                        logger.info("Host文件命中: {} {} -> {} 条记录 [服务器: {}]", 
                                   domain, queryType, answerCount, currentDohServer);
                        
                        sendResponse(response, clientIp, domain, queryType, startTime, source, requestId);
                        return;
                    } else {
                        logger.debug("域名存在于Host文件但无匹配记录类型: {} {} [服务器: {}]", 
                                   queryDomain, recordType, currentDohServer);
                    }
                }
            }
            
            // 第三步：处理PTR查询
            if (recordType == DnsRecordType.PTR) {
                logger.debug("处理PTR反向查询: {} [服务器: {}]", domain, currentDohServer);
                
                response = hostFileResolver.resolve(request);
                if (response != null && response.getAnswers().size() > 0) {
                    hostFileHits++;
                    source = "HOST_FILE_PTR";
                    answerCount = response.getAnswers().size();
                    logger.info("Host文件PTR命中: {} -> {} 条记录 [服务器: {}]", 
                               domain, answerCount, currentDohServer);
                    
                    sendResponse(response, clientIp, domain, queryType, startTime, source, requestId);
                    return;
                }
                
                try {
                    response = ptrResolver.resolvePtrQuery(request);
                    if (response != null && response.getAnswers().size() > 0) {
                        ptrHits++;
                        source = "PTR_RESOLVER";
                        answerCount = response.getAnswers().size();
                        logger.info("PTR解析器命中: {} -> {} 条记录 [服务器: {}]", 
                                   domain, answerCount, currentDohServer);
                        
                        sendResponse(response, clientIp, domain, queryType, startTime, source, requestId);
                        return;
                    }
                } catch (Exception e) {
                    logger.warn("PTR解析器处理失败: {} [服务器: {}]", e.getMessage(), currentDohServer);
                }
            }
            
            // 第四步：使用DoH服务器
            logger.debug("未找到本地解析结果，使用DoH服务器查询{} [服务器: {}]", domain, currentDohServer);
            try {
                // 检查并切换DoH服务器
                if (autoSwitchEnabled) {
                    checkAndSwitchDohServer();
                }
                
                response = dohResolver.resolve(request);
                if (response != null && response.getAnswers().size() > 0) {
                    dohHits++;
                    dohQueryCount++;
                    source = "DOH_SERVER";
                    answerCount = response.getAnswers().size();
                    logger.info("DoH服务器解析成功: {} {} -> {} 条记录 [服务器: {}]", 
                               domain, queryType, answerCount, currentDohServer);
                    
                    sendResponse(response, clientIp, domain, queryType, startTime, source, requestId);
                } else {
                    response = createNotFoundResponse(request);
                    source = "DOH_FAILED_NXDOMAIN";
                    logger.warn("DoH返回空响应，返回NXDOMAIN: {} [服务器: {}]", domain, currentDohServer);
                    sendResponse(response, clientIp, domain, queryType, startTime, source, requestId);
                }
                
            } catch (Exception e) {
                logger.error("DoH解析失败: {} {} [服务器: {}]", domain, e.getMessage(), currentDohServer);
                
                // 如果启用自动切换，尝试切换到下一个服务器
                if (autoSwitchEnabled && dohServerList.size() > 1) {
                    logger.info("DoH查询失败，尝试切换到下一个服务器");
                    switchToNextServer(true); // 强制切换
                    
                    try {
                        // 使用新服务器重试
                        response = dohResolver.resolve(request);
                        if (response != null && response.getAnswers().size() > 0) {
                            dohHits++;
                            dohQueryCount++;
                            source = "DOH_SERVER_RETRY";
                            answerCount = response.getAnswers().size();
                            logger.info("重试成功: {} {} -> {} 条记录 [新服务器: {}]", 
                                       domain, queryType, answerCount, currentDohServer);
                            
                            sendResponse(response, clientIp, domain, queryType, startTime, source, requestId);
                            return;
                        }
                    } catch (Exception retryException) {
                        logger.error("重试也失败: {} [服务器: {}]", domain, currentDohServer);
                    }
                }
                
                response = createServFailResponse(request);
                source = "DOH_FAILED_SERVFAIL";
                sendResponse(response, clientIp, domain, queryType, startTime, source, requestId);
            }
            
        } catch (Exception e) {
            failedQueries++;
            long responseTime = System.currentTimeMillis() - startTime;
            
            String logDomain = (domain == null || domain.isEmpty()) ? "UNKNOWN_DOMAIN" : domain;
            String logQueryType = (queryType == null || queryType.isEmpty()) ? "UNKNOWN_TYPE" : queryType;
            
            LoggerUtil.logQuery(clientIp, logDomain, logQueryType, responseTime, "FAILED", source, requestId, currentDohServer);
            LoggerUtil.logError("DNS查询处理异常", clientIp, e);
            
            try {
                sendErrorResponse(requestPacket, clientIp, logDomain, logQueryType, startTime);
            } catch (IOException ex) {
                LoggerUtil.logError("发送错误响应失败", clientIp, ex);
            }
        } finally {
            cleanupRequestCache();
        }
    }
    
    /**
     * 重新加载配置
     */
    private synchronized void reloadConfig() {
        try {
            config.loadConfig();
            
            // 重新初始化服务器列表
            initializeDohServers();
            
            // 更新当前服务器索引（如果服务器列表发生变化）
            if (currentServerIndex >= dohServerList.size()) {
                currentServerIndex = 0;
                updateCurrentDohServer();
            }
            
            logger.info("配置已重新加载，当前服务器列表: {}个，自动切换: {}", 
                       dohServerList.size(), autoSwitchEnabled ? "开启" : "关闭");
            
        } catch (Exception e) {
            logger.error("重新加载配置失败", e);
        }
    }
    
    /**
     * 检查并切换DoH服务器
     */
    private void checkAndSwitchDohServer() {
        if (autoSwitchEnabled && dohServerList.size() > 1 && 
            dohQueryCount > 0 && dohQueryCount % switchThreshold == 0) {
            
            switchToNextServer(false);
        }
    }
    
    /**
     * 切换到下一个DoH服务器
     */
    private synchronized void switchToNextServer(boolean isErrorSwitch) {
        if (dohServerList.size() <= 1) {
            return; // 只有一个服务器，不需要切换
        }
        
        String oldServer = currentDohServer;
        
        // 切换到下一个服务器
        currentServerIndex = (currentServerIndex + 1) % dohServerList.size();
        updateCurrentDohServer();
        
        if (isErrorSwitch) {
            configBasedSwitches++;
            logger.warn("因查询错误切换DoH服务器: {} -> {} [错误切换]", 
                       oldServer, currentDohServer);
        } else {
            logger.info("定期切换DoH服务器: {} -> {} [累计查询: {}, 阈值: {}]", 
                       oldServer, currentDohServer, dohQueryCount, switchThreshold);
        }
        
        LoggerUtil.logDohServerSwitch(oldServer, currentDohServer, dohQueryCount, isErrorSwitch);
    }
    
    /**
     * 更新当前DoH服务器信息
     */
    private void updateCurrentDohServer() {
        if (dohServerList.isEmpty()) {
            currentDohServer = "UNKNOWN";
            return;
        }
        
        try {
            currentDohServer = dohServerList.get(currentServerIndex);
            
            // 这里可以添加服务器健康检查
            // 如果当前服务器不健康，可以自动切换到下一个
            
        } catch (Exception e) {
            currentDohServer = "UNKNOWN";
            logger.warn("无法获取当前DoH服务器信息: {}", e.getMessage());
        }
    }
    
    /**
     * 创建屏蔽响应
     */
    private DnsMessage createBlockedResponse(DnsMessage request, String ipAddress) {
        DnsMessage response = new DnsMessage();
        response.setId(request.getId());
        
        // 设置响应标志
        int flags = 0x8000; // QR=1 (响应)
        flags |= 0x0400;    // AA=1 (权威回答)
        flags |= 0x0080;    // RA=1 (递归可用)
        response.setFlags(flags);
        
        // 复制问题部分
        response.getQuestions().addAll(request.getQuestions());
        
        // 创建屏蔽记录
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
    
    /**
     * 创建未找到响应
     */
    private DnsMessage createNotFoundResponse(DnsMessage request) {
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
    
    /**
     * 创建服务器故障响应
     */
    private DnsMessage createServFailResponse(DnsMessage request) {
        DnsMessage response = new DnsMessage();
        response.setId(request.getId());
        response.setFlags(0x8182); // QR=1, RA=1, RD=1, RCODE=2 (SERVFAIL)
        response.getQuestions().addAll(request.getQuestions());
        return response;
    }
    
    /**
     * 生成请求唯一标识（用于去重）
     */
    private String generateRequestKey(DatagramPacket packet) {
        // 使用客户端IP、端口和数据内容生成唯一标识
        String clientInfo = packet.getAddress().getHostAddress() + ":" + packet.getPort();
        
        // 使用数据的前100字节的哈希（避免处理过大数据）
        int dataHash = java.util.Arrays.hashCode(
            java.util.Arrays.copyOf(packet.getData(), Math.min(packet.getLength(), 100))
        );
        
        return clientInfo + "#" + dataHash;
    }
    
    /**
     * 检查是否为重复请求
     */
    private boolean isDuplicateRequest(String requestKey) {
        long currentTime = System.currentTimeMillis();
        Long lastTime = requestCache.get(requestKey);
        
        if (lastTime != null && (currentTime - lastTime) < CACHE_DURATION) {
            return true; // 在去重窗口内认为是重复请求
        }
        
        // 更新或添加缓存
        requestCache.put(requestKey, currentTime);
        return false;
    }
    
    /**
     * 清理过期的缓存条目
     */
    private void cleanupRequestCache() {
        long currentTime = System.currentTimeMillis();
        long cleanupThreshold = currentTime - CACHE_DURATION * 2; // 清理2倍时间窗口前的数据
        
        requestCache.entrySet().removeIf(entry -> entry.getValue() < cleanupThreshold);
    }
    
    /**
     * 发送成功响应
     */
    private void sendResponse(DnsMessage response, String clientIp, String domain, 
                            String queryType, long startTime, String source, int requestId) throws IOException {
        byte[] responseData = DnsClient.encodeDnsMessage(response);
        
        DatagramPacket responsePacket = new DatagramPacket(
            responseData, responseData.length,
            requestPacket.getAddress(), requestPacket.getPort()
        );
        
        socket.send(responsePacket);
        successfulQueries++;
        
        long responseTime = System.currentTimeMillis() - startTime;
        
        // 记录查询日志（包含当前服务器信息）
        LoggerUtil.logQuery(clientIp, domain, queryType, responseTime, "SUCCESS", source, requestId, currentDohServer);
        
        logger.debug("成功处理查询 {} [ID:{}] 耗时 {}ms (来源: {}, 服务器: {})", 
                    domain, requestId, responseTime, source, currentDohServer);
    }
    
    /**
     * 发送错误响应
     */
    private void sendErrorResponse(DatagramPacket requestPacket, String clientIp, 
                                 String domain, String queryType, long startTime) throws IOException {
        try {
            byte[] requestData = requestPacket.getData();
            byte[] errorResponse = new byte[requestData.length];
            System.arraycopy(requestData, 0, errorResponse, 0, 
                           Math.min(requestData.length, errorResponse.length));
            
            errorResponse[2] = (byte) 0x81;
            errorResponse[3] = (byte) 0x83;
            
            DatagramPacket errorPacket = new DatagramPacket(
                errorResponse, errorResponse.length,
                requestPacket.getAddress(), requestPacket.getPort()
            );
            
            socket.send(errorPacket);
            failedQueries++;
            
            long responseTime = System.currentTimeMillis() - startTime;
            LoggerUtil.logQuery(clientIp, domain, queryType, responseTime, "FAILED", "ERROR", 0, currentDohServer);
            
        } catch (Exception e) {
            logger.error("Failed to send error response for {}: {} [服务器: {}]", 
                        domain, e.getMessage(), currentDohServer);
            throw e;
        }
    }
    
    // 新增：获取当前服务器的方法
    public static String getCurrentDohServer() {
        return currentDohServer;
    }
    
    // 新增：获取服务器列表
    public static List<String> getDohServerList() {
        return new java.util.ArrayList<>(dohServerList);
    }
    
    // 新增：获取自动切换状态
    public static boolean isAutoSwitchEnabled() {
        return autoSwitchEnabled;
    }
    
    // 新增：获取切换阈值
    public static int getSwitchThreshold() {
        return switchThreshold;
    }
    
    // 统计信息获取方法
    public static long getTotalQueries() {
        return totalQueries;
    }
    
    public static long getSuccessfulQueries() {
        return successfulQueries;
    }
    
    public static long getFailedQueries() {
        return failedQueries;
    }
    
    public static long getHostFileHits() {
        return hostFileHits;
    }
    
    public static long getPtrHits() {
        return ptrHits;
    }
    
    public static long getDohHits() {
        return dohHits;
    }
    
    public static long getBlockedQueries() {
        return blockedQueries;
    }
    
    public static long getDohQueryCount() {
        return dohQueryCount;
    }
    
    public static long getDuplicateQueries() {
        return duplicateQueries;
    }
    
    // 新增：获取配置切换次数
    public static long getConfigBasedSwitches() {
        return configBasedSwitches;
    }
    
    public static void resetStatistics() {
        totalQueries = 0;
        successfulQueries = 0;
        failedQueries = 0;
        hostFileHits = 0;
        ptrHits = 0;
        dohHits = 0;
        blockedQueries = 0;
        dohQueryCount = 0;
        duplicateQueries = 0;
        configBasedSwitches = 0;
    }
    
    public static String getDetailedStatistics() {
        return String.format(
            "Total: %d, Success: %d, Failed: %d, Duplicate: %d, Blocked: %d, " +
            "HostFile: %d, PTR: %d, DoH: %d, DoHQueryCount: %d, ConfigSwitches: %d, " +
            "AutoSwitch: %s, Servers: %d, Current: %s",
            totalQueries, successfulQueries, failedQueries, duplicateQueries, blockedQueries,
            hostFileHits, ptrHits, dohHits, dohQueryCount, configBasedSwitches,
            autoSwitchEnabled ? "ON" : "OFF", dohServerList.size(), currentDohServer
        );
    }
    
    /**
     * 手动切换到下一个服务器（用于管理接口）
     */
    public static synchronized void manualSwitchToNextServer() {
        if (dohServerList.size() > 1) {
            String oldServer = currentDohServer;
            
            currentServerIndex = (currentServerIndex + 1) % dohServerList.size();
            updateCurrentDohServerStatic();
            
            logger.info("手动切换DoH服务器: {} -> {}", oldServer, currentDohServer);
        }
    }
    
    /**
     * 静态方法更新当前服务器（用于手动切换）
     */
    private static void updateCurrentDohServerStatic() {
        if (dohServerList.isEmpty()) {
            currentDohServer = "UNKNOWN";
            return;
        }
        
        try {
            currentDohServer = dohServerList.get(currentServerIndex);
        } catch (Exception e) {
            currentDohServer = "UNKNOWN";
        }
    }
    
    /**
     * 获取服务器健康状态（简化版本）
     */
    public static boolean isCurrentServerHealthy() {
        // 这里可以实现实际的健康检查逻辑
        // 暂时返回true，假设服务器健康
        return true;
    }
}