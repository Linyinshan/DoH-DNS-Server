package com.dns.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import com.dns.config.DnsConfig;

import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class LoggerUtil {
    private static final Logger logger = LoggerFactory.getLogger(LoggerUtil.class);
    private static final Logger queryLogger = LoggerFactory.getLogger("DNS_QUERY");
    private static final Logger serverLogger = LoggerFactory.getLogger("DNS_SERVER_STATUS");
    private static final Logger configLogger = LoggerFactory.getLogger("DNS_CONFIG");
    private static final Logger performanceLogger = LoggerFactory.getLogger("DNS_PERFORMANCE");
    
    private static final DateTimeFormatter QUERY_FORMATTER = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    /**
     * 记录DNS查询日志 - 添加服务器信息
     */
    public static void logQuery(String clientIp, String domain, String type, 
                              long responseTime, String status, String source, int requestId, String server) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        String safeDomain = (domain == null || domain.isEmpty()) ? "未知域名" : domain;
        String safeType = (type == null || type.isEmpty()) ? "未知类型" : type;
        String safeSource = (source == null || source.isEmpty()) ? "未知来源" : source;
        String safeServer = (server == null || server.isEmpty()) ? "UNKNOWN_SERVER" : server;
        
        // 查询日志格式：时间|客户端IP|域名|类型|请求ID|响应时间|状态|来源|服务器
        String logEntry = String.format("%s|%s|%s|%s|%d|%dms|%s|%s|%s", 
            timestamp, clientIp, safeDomain, safeType, requestId, responseTime, status, safeSource, safeServer);
        
        // 记录到查询日志文件
        queryLogger.info(logEntry);
        
        // 只有在调试模式或错误时才记录到主日志
        if (!"SUCCESS".equals(status) || logger.isDebugEnabled()) {
            logger.info("DNS查询[ID:{}]: {} {} 来自 {} - {}ms - {} [{}] [服务器: {}]", 
                requestId, safeDomain, safeType, clientIp, responseTime, status, safeSource, safeServer);
        }
    }
    
    /**
     * 重载方法，向后兼容
     */
    public static void logQuery(String clientIp, String domain, String type, 
                              long responseTime, String status, String source, int requestId) {
        logQuery(clientIp, domain, type, responseTime, status, source, requestId, "UNKNOWN_SERVER");
    }
    
    /**
     * 记录服务器状态信息
     */
    public static void logServerStatus(String server, boolean isHealthy, long queryCount) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        String status = isHealthy ? "HEALTHY" : "UNHEALTHY";
        
        String logEntry = String.format("%s|%s|%s|%d", 
            timestamp, server, status, queryCount);
        
        // 记录到服务器状态日志
        serverLogger.info(logEntry);
        
        if (!isHealthy) {
            logger.warn("服务器状态异常: {} [查询计数: {}]", server, queryCount);
        }
    }
    
    /**
     * 记录DoH服务器切换信息 - 增强版本
     */
    public static void logDohServerSwitch(String fromServer, String toServer, long queryCount, boolean isErrorSwitch) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        String switchType = isErrorSwitch ? "ERROR_SWITCH" : "SCHEDULED_SWITCH";
        
        String logEntry = String.format("%s|SWITCH|%s|%s|%s|%d", 
            timestamp, switchType, fromServer, toServer, queryCount);
        
        // 记录到查询日志和服务器状态日志
        queryLogger.info(logEntry);
        serverLogger.info(logEntry);
        
        if (isErrorSwitch) {
            logger.warn("{} - DoH服务器错误切换: 从 {} 切换到 {} [累计查询: {}]", 
                timestamp, fromServer, toServer, queryCount);
        } else {
            logger.info("{} - DoH服务器定期切换: 从 {} 切换到 {} [累计查询: {}]", 
                timestamp, fromServer, toServer, queryCount);
        }
    }
    
    /**
     * 重载方法，向后兼容
     */
    public static void logDohServerSwitch(String fromServer, String toServer, long queryCount) {
        logDohServerSwitch(fromServer, toServer, queryCount, false);
    }
    
    /**
     * 记录服务器启动信息 - 增强版本
     */
    public static void logServerStart(int port, String dohServer, String hostFilePath, boolean autoSwitchEnabled, DnsConfig config) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        
        logger.info("================================================");
        logger.info("{} - DoH DNS 服务器已启动", timestamp);
        logger.info("监听端口: {}", port);
        logger.info("使用的DoH服务器: {}", dohServer);
        logger.info("主机文件: {}", hostFilePath);
        logger.info("自动切换功能: {}", autoSwitchEnabled ? "已启用" : "已禁用");
        
        // 记录代理配置信息
        logProxyInfo(config);
        
        // 记录服务器信息
        try {
            logger.info("服务器IP: {}", InetAddress.getLocalHost().getHostAddress());
        } catch (Exception e) {
            logger.warn("无法获取服务器IP地址");
        }
        
        logger.info("日志目录: logs/");
        logger.info("================================================");
        
        // 记录到服务器状态日志
        String proxyInfo = config.hasProxy() ? 
            String.format("|代理:%s:%s:%s", config.getProxyType(), config.getProxyIP(), config.getProxyPort()) : 
            "|代理:未启用";
            
        String logEntry = String.format("%s|START|%s|%d|%s%s", 
            timestamp, dohServer, port, 
            autoSwitchEnabled ? "AUTO_SWITCH_ON" : "AUTO_SWITCH_OFF",
            proxyInfo);
        serverLogger.info(logEntry);
    }
	
	/**
     * 记录代理配置信息
     */
    public static void logProxyInfo(DnsConfig config) {
        if (config.hasProxy()) {
            String proxyType = config.getProxyType().toUpperCase();
            String authInfo = config.hasProxyAuth() ? 
                String.format(" (认证用户: %s)", config.getProxyUsername()) : " (无认证)";
            
            logger.info("代理服务器: {} {}:{}{}", 
                       proxyType, config.getProxyIP(), config.getProxyPort(), authInfo);
        } else {
            logger.info("代理服务器: 未启用");
        }
    }
    
    /**
     * 记录服务器关闭信息
     */
    public static void logServerStop() {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        
        logger.info("================================================");
        logger.info("{} - DoH DNS 服务器已停止", timestamp);
        logger.info("================================================");
        
        // 记录到服务器状态日志
        serverLogger.info(timestamp + "|STOP");
    }
    
    /**
     * 记录详细的统计信息 - 修复百分比格式化问题
     */
    public static void logDetailedStatistics(long totalQueries, long successfulQueries, 
                                           long failedQueries, long duplicateQueries, 
                                           long hostFileHits, long ptrHits, long dohHits, 
                                           long blockedQueries, String currentServer) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        
        // 修复百分比计算：避免除零错误
        double successRate = totalQueries > 0 ? (successfulQueries * 100.0 / totalQueries) : 0.0;
        double failedRate = totalQueries > 0 ? (failedQueries * 100.0 / totalQueries) : 0.0;
        double duplicateRate = totalQueries > 0 ? (duplicateQueries * 100.0 / totalQueries) : 0.0;
        double hostFileRate = totalQueries > 0 ? (hostFileHits * 100.0 / totalQueries) : 0.0;
        double ptrRate = totalQueries > 0 ? (ptrHits * 100.0 / totalQueries) : 0.0;
        double dohRate = totalQueries > 0 ? (dohHits * 100.0 / totalQueries) : 0.0;
        double blockedRate = totalQueries > 0 ? (blockedQueries * 100.0 / totalQueries) : 0.0;
        
        // 修复：先格式化百分比字符串，再记录日志
        String successRateStr = String.format("%.2f", successRate);
        String failedRateStr = String.format("%.2f", failedRate);
        String duplicateRateStr = String.format("%.2f", duplicateRate);
        String hostFileRateStr = String.format("%.2f", hostFileRate);
        String ptrRateStr = String.format("%.2f", ptrRate);
        String dohRateStr = String.format("%.2f", dohRate);
        String blockedRateStr = String.format("%.2f", blockedRate);
        
        logger.info("════════════════ 详细统计信息 ════════════════════");
        logger.info("时间: {}", timestamp);
        logger.info("当前服务器: {}", currentServer);
        logger.info("总查询数: {}", totalQueries);
        logger.info("成功查询: {} ({}%)", successfulQueries, successRateStr);
        logger.info("失败查询: {} ({}%)", failedQueries, failedRateStr);
        logger.info("重复查询: {} ({}%)", duplicateQueries, duplicateRateStr);
        logger.info("Host文件命中: {} ({}%)", hostFileHits, hostFileRateStr);
        logger.info("PTR解析命中: {} ({}%)", ptrHits, ptrRateStr);
        logger.info("DoH解析命中: {} ({}%)", dohHits, dohRateStr);
        logger.info("拦截查询: {} ({}%)", blockedQueries, blockedRateStr);
        logger.info("═══════════════════════════════════════════════");
    }
    
    /**
     * 记录增强的统计信息 - 修复百分比格式化问题
     */
    public static void logEnhancedStatistics(long totalQueries, long successfulQueries, 
                                           long failedQueries, long duplicateQueries, 
                                           long hostFileHits, long ptrHits, long dohHits, 
                                           long blockedQueries, long configSwitches,
                                           boolean autoSwitchEnabled, int serverCount, 
                                           String currentServer, int switchThreshold) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        
        // 修复百分比计算
        double successRate = totalQueries > 0 ? (successfulQueries * 100.0 / totalQueries) : 0.0;
        double failedRate = totalQueries > 0 ? (failedQueries * 100.0 / totalQueries) : 0.0;
        double duplicateRate = totalQueries > 0 ? (duplicateQueries * 100.0 / totalQueries) : 0.0;
        double hostFileRate = totalQueries > 0 ? (hostFileHits * 100.0 / totalQueries) : 0.0;
        double ptrRate = totalQueries > 0 ? (ptrHits * 100.0 / totalQueries) : 0.0;
        double dohRate = totalQueries > 0 ? (dohHits * 100.0 / totalQueries) : 0.0;
        double blockedRate = totalQueries > 0 ? (blockedQueries * 100.0 / totalQueries) : 0.0;
        
        // 修复：先格式化百分比字符串
        String successRateStr = String.format("%.2f", successRate);
        String failedRateStr = String.format("%.2f", failedRate);
        String duplicateRateStr = String.format("%.2f", duplicateRate);
        String hostFileRateStr = String.format("%.2f", hostFileRate);
        String ptrRateStr = String.format("%.2f", ptrRate);
        String dohRateStr = String.format("%.2f", dohRate);
        String blockedRateStr = String.format("%.2f", blockedRate);
        
        logger.info("════════════════ 增强统计信息 ════════════════════");
        logger.info("时间: {}", timestamp);
        logger.info("当前服务器: {}", currentServer);
        logger.info("服务器总数: {}", serverCount);
        logger.info("自动切换: {}", autoSwitchEnabled ? "启用" : "禁用");
        logger.info("切换阈值: {} 个查询", switchThreshold);
        logger.info("配置切换次数: {}", configSwitches);
        logger.info("总查询数: {}", totalQueries);
        logger.info("成功查询: {} ({}%)", successfulQueries, successRateStr);
        logger.info("失败查询: {} ({}%)", failedQueries, failedRateStr);
        logger.info("重复查询: {} ({}%)", duplicateQueries, duplicateRateStr);
        logger.info("Host文件命中: {} ({}%)", hostFileHits, hostFileRateStr);
        logger.info("PTR解析命中: {} ({}%)", ptrHits, ptrRateStr);
        logger.info("DoH解析命中: {} ({}%)", dohHits, dohRateStr);
        logger.info("拦截查询: {} ({}%)", blockedQueries, blockedRateStr);
        logger.info("═══════════════════════════════════════════════");
    }
    
    /**
     * 记录统计信息 - 修复百分比格式化问题
     */
    public static void logStatistics(long totalQueries, long successfulQueries, 
                                   long failedQueries, long duplicateQueries) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        
        // 修复百分比计算
        double successRate = totalQueries > 0 ? (successfulQueries * 100.0 / totalQueries) : 0.0;
        double duplicateRate = totalQueries > 0 ? (duplicateQueries * 100.0 / totalQueries) : 0.0;
        
        // 修复：先格式化百分比字符串
        String successRateStr = String.format("%.2f", successRate);
        String duplicateRateStr = String.format("%.2f", duplicateRate);
        
        logger.info("{} - 服务器统计信息 - 总查询: {}, 成功: {} ({}%), 失败: {}, 重复: {} ({}%)", 
            timestamp, totalQueries, successfulQueries, successRateStr, 
            failedQueries, duplicateQueries, duplicateRateStr);
    }
    
    /**
     * 记录健康检查结果
     */
    public static void logHealthCheck(int healthyServers, int totalServers) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        
        if (healthyServers == 0) {
            logger.error("{} - 健康检查: 无可用DoH服务器！({}/{})", 
                timestamp, healthyServers, totalServers);
        } else {
            logger.info("{} - 健康检查: {}/{} 个DoH服务器正常", 
                timestamp, healthyServers, totalServers);
        }
        
        // 记录到服务器状态日志
        String logEntry = String.format("%s|HEALTH_CHECK|%d|%d", 
            timestamp, healthyServers, totalServers);
        serverLogger.info(logEntry);
    }
    
    /**
     * 记录配置相关日志
     */
    public static void logConfig(String operation, String details) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        
        logger.info("{} - 配置操作: {} - {}", timestamp, operation, details);
        
        // 记录到配置日志
        String logEntry = String.format("%s|%s|%s", timestamp, operation, details);
        configLogger.info(logEntry);
    }
    
    /**
     * 记录配置加载信息
     */
    public static void logConfigLoad(String configFile, int loadedItems, boolean success) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        String status = success ? "SUCCESS" : "FAILED";
        
        logger.info("{} - 配置加载: 文件 {} - 加载 {} 项配置 - {}", 
            timestamp, configFile, loadedItems, status);
        
        String logEntry = String.format("%s|LOAD|%s|%d|%s", 
            timestamp, configFile, loadedItems, status);
        configLogger.info(logEntry);
    }
    
    /**
     * 记录配置重载信息
     */
	public static void logConfigReload(String configType, int itemCount) {
		logConfigReload(configType, itemCount, true); // 默认成功
	}

	public static void logConfigReload(String configType, int itemCount, boolean success) {
		String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
		String status = success ? "SUCCESS" : "FAILED";
		
		if (success) {
			logger.info("{} - 配置重新加载: 从 {} 加载了 {} 项配置", 
				timestamp, configType, itemCount);
		} else {
			logger.error("{} - 配置重新加载失败: {}", timestamp, configType);
		}
		
		// 记录到配置日志
		String logEntry = String.format("%s|RELOAD|%s|%d|%s", 
			timestamp, configType, itemCount, status);
		configLogger.info(logEntry);
	}
    
    /**
     * 记录配置验证信息
     */
    public static void logConfigValidation(String configItem, String value, boolean valid) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        String status = valid ? "VALID" : "INVALID";
        
        if (!valid) {
            logger.warn("{} - 配置验证失败: {} = {}", timestamp, configItem, value);
        }
        
        String logEntry = String.format("%s|VALIDATION|%s|%s|%s", 
            timestamp, configItem, value, status);
        configLogger.info(logEntry);
    }
    
    /**
     * 记录性能信息
     */
    public static void logPerformance(String operation, long duration, String details) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        
        String level = "INFO";
        if (duration > 5000) {
            level = "ERROR";
        } else if (duration > 1000) {
            level = "WARN";
        }
        
        if ("ERROR".equals(level)) {
            logger.error("{} - 性能警告: {} 耗时 {}ms - {}", 
                timestamp, operation, duration, details);
        } else if ("WARN".equals(level)) {
            logger.warn("{} - 性能警告: {} 耗时 {}ms - {}", 
                timestamp, operation, duration, details);
        } else {
            logger.debug("{} - 性能监控: {} 耗时 {}ms - {}", 
                timestamp, operation, duration, details);
        }
        
        // 记录到性能日志
        String logEntry = String.format("%s|%s|%s|%d|%s", 
            timestamp, level, operation, duration, details);
        performanceLogger.info(logEntry);
    }
    
    /**
     * 记录错误信息
     */
    public static void logError(String operation, String clientIp, Throwable error) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        MDC.put("clientIp", clientIp);
        MDC.put("operation", operation);
        
        logger.error("{} - {} 操作失败: {}", timestamp, operation, error.getMessage(), error);
        
        // 记录到服务器状态日志
        String logEntry = String.format("%s|ERROR|%s|%s|%s", 
            timestamp, operation, clientIp, error.getMessage());
        serverLogger.info(logEntry);
        
        MDC.clear();
    }
    
    /**
     * 记录配置错误信息
     */
    public static void logConfigError(String operation, String configItem, String errorMessage) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        
        logger.error("{} - 配置错误: {} - {} - {}", timestamp, operation, configItem, errorMessage);
        
        String logEntry = String.format("%s|CONFIG_ERROR|%s|%s|%s", 
            timestamp, operation, configItem, errorMessage);
        configLogger.error(logEntry);
    }
    
    /**
     * 记录调试信息
     */
    public static void logDebug(String message, Object... args) {
        logger.debug(message, args);
    }
    
    /**
     * 记录警告信息
     */
    public static void logWarning(String message, Object... args) {
        logger.warn(message, args);
    }
    
    /**
     * 记录信息
     */
    public static void logInfo(String message, Object... args) {
        logger.info(message, args);
    }
    
    /**
     * 记录服务器列表信息
     */
    public static void logServerList(String currentServer, List<String> servers) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        
        logger.info("{} - 当前DoH服务器列表 ({}个):", timestamp, servers.size());
        for (int i = 0; i < servers.size(); i++) {
            String status = servers.get(i).equals(currentServer) ? "[当前]" : "[备用]";
            logger.info("  {}. {} {}", i + 1, servers.get(i), status);
        }
        
        // 记录到服务器状态日志
        StringBuilder serverList = new StringBuilder();
        for (String server : servers) {
            if (serverList.length() > 0) serverList.append(",");
            serverList.append(server.equals(currentServer) ? "*" + server : server);
        }
        String logEntry = String.format("%s|SERVER_LIST|%s|%s", 
            timestamp, currentServer, serverList.toString());
        serverLogger.info(logEntry);
    }
    
    /**
     * 记录代理配置信息
     */
    public static void logProxyConfig(String proxyHost, int proxyPort, boolean enabled, 
                                    String proxyType, String proxyUsername) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        String status = enabled ? "ENABLED" : "DISABLED";
        
        if (enabled) {
            String authInfo = proxyUsername != null && !proxyUsername.isEmpty() ? 
                String.format(" (认证用户: %s)", proxyUsername) : " (无认证)";
            logger.info("{} - 代理配置: {} {}:{} - 已启用{}", 
                       timestamp, proxyType.toUpperCase(), proxyHost, proxyPort, authInfo);
        } else {
            logger.info("{} - 代理配置: 未启用", timestamp);
        }
        
        String logEntry = String.format("%s|PROXY|%s|%d|%s|%s", 
            timestamp, proxyHost, proxyPort, proxyType, status);
        configLogger.info(logEntry);
    }
    
    /**
     * 记录缓存统计信息 - 修复百分比显示问题
     */
    public static void logCacheStats(long cacheHits, long cacheMisses, long cacheSize, long maxCacheSize) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        long totalRequests = cacheHits + cacheMisses;
        double hitRate = totalRequests > 0 ? (cacheHits * 100.0 / totalRequests) : 0.0;
        
        String hitRateStr = String.format("%.2f", hitRate);

        logger.debug("{} - 缓存统计: 命中率 {}% ({}/{}) 缓存大小: {}/{}", 
            timestamp, hitRateStr, cacheHits, totalRequests, cacheSize, maxCacheSize);
        
        String logEntry = String.format("%s|CACHE_STATS|%d|%d|%d|%d|%.2f"+"%", 
            timestamp, cacheHits, cacheMisses, cacheSize, maxCacheSize, hitRate);
        performanceLogger.info(logEntry);
    }
    
    /**
     * 记录内存使用情况
     */
    public static void logMemoryUsage() {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        double usedPercent = (double) usedMemory / maxMemory * 100;
        String usedPercentStr = String.format("%.2f", usedPercent);
        
        logger.debug("{} - 内存使用: {}/{} MB ({}%)", 
            timestamp, 
            usedMemory / (1024 * 1024), 
            maxMemory / (1024 * 1024), 
            usedPercentStr);
        
        String logEntry = String.format("%s|MEMORY|%d|%d|%d|%.2f", 
            timestamp, usedMemory, totalMemory, maxMemory, usedPercent);
        performanceLogger.info(logEntry);
    }
    
    /**
     * 记录线程池状态
     */
    public static void logThreadPoolStats(int activeThreads, int poolSize, int queueSize) {
        String timestamp = LocalDateTime.now().format(QUERY_FORMATTER);
        
        logger.debug("{} - 线程池状态: 活动线程: {}/{} 队列大小: {}", 
            timestamp, activeThreads, poolSize, queueSize);
        
        String logEntry = String.format("%s|THREAD_POOL|%d|%d|%d", 
            timestamp, activeThreads, poolSize, queueSize);
        performanceLogger.info(logEntry);
    }
}