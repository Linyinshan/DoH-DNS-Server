package com.dns.server;

import com.dns.doh.DohHealthChecker;
import com.dns.doh.DohResolver;
import com.dns.doh.PtrResolver;
import com.dns.resolver.DomainBlocker;
import com.dns.resolver.HostFileResolver;
import com.dns.util.LoggerUtil;
import com.dns.config.DnsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class DohDnsServer {
    private static final Logger logger = LoggerFactory.getLogger(DohDnsServer.class);
    
    private final int port;
    private final String dohServerUrl;
    private final DohResolver dohResolver;
    private final PtrResolver ptrResolver;
    private final HostFileResolver hostFileResolver;
    private final DomainBlocker domainBlocker;
    private final ExecutorService threadPool;
    private final ScheduledExecutorService statsScheduler;
    private final DohHealthChecker healthChecker;
    private final ScheduledExecutorService healthCheckScheduler;
    private final ScheduledExecutorService configCheckScheduler;
    private volatile boolean running = false;
    private DatagramSocket socket;
    private final long startTime;
    private final boolean autoSwitchEnabled;
    private final int switchThreshold = 20;
    private final DnsConfig config;
    
    public DohDnsServer() {
        this(new DnsConfig());
    }
    
    public DohDnsServer(DnsConfig config) {
        this.config = config;
        
        // 使用配置值初始化
        this.port = config.getPort();
        this.autoSwitchEnabled = shouldEnableAutoSwitch(config);
        
        // 根据配置创建解析器
        this.dohResolver = createDohResolver(config);
        this.ptrResolver = new PtrResolver();
        this.hostFileResolver = createHostFileResolver(config);
        this.domainBlocker = createDomainBlocker(config);
        
        this.threadPool = Executors.newFixedThreadPool(config.getThreadPoolSize());
        this.statsScheduler = Executors.newScheduledThreadPool(1);
        this.healthChecker = new DohHealthChecker();
        this.healthCheckScheduler = Executors.newScheduledThreadPool(1);
        this.configCheckScheduler = Executors.newScheduledThreadPool(1);
        this.startTime = System.currentTimeMillis();
        
        // 获取DoH服务器URL（用于兼容旧代码）
        List<String> dohServers = config.getDohServers();
        this.dohServerUrl = dohServers.isEmpty() ? null : dohServers.get(0);
        
        // 设置日志级别
        setLogLevel(config.getLogLevel());
        
        logger.info("DoH服务器自动切换功能: {}", autoSwitchEnabled ? "启用" : "禁用");
        logger.info("线程池大小: {}", config.getThreadPoolSize());
        
        // 初始化服务器信息显示
        logCurrentServerInfo();
    }
    
    /**
     * 判断是否启用自动切换
     */
    private boolean shouldEnableAutoSwitch(DnsConfig config) {
        List<String> dohServers = config.getDohServers();
        if (!dohServers.isEmpty()) {
            // 如果配置了多个服务器，强制启用自动切换
            // 如果只配置了一个服务器，强制禁用自动切换
            boolean enable = dohServers.size() > 1;
            logger.info("根据配置的DoH服务器数量({})，自动切换功能: {}", 
                       dohServers.size(), enable ? "启用" : "禁用");
            return enable;
        }
        // 使用内置服务器列表时，遵循autoswitch配置
        boolean enable = config.isAutoSwitchEnabled();
        logger.info("使用内置服务器列表，自动切换功能: {}", enable ? "启用" : "禁用");
        return enable;
    }
    
    /**
     * 创建DoH解析器（支持代理和自定义服务器）
     */
    private DohResolver createDohResolver(DnsConfig config) {
        List<String> dohServers = config.getDohServers();
        
        // 如果配置了自定义服务器，使用配置的服务器
        String dohServerUrl = null;
        if (!dohServers.isEmpty()) {
            dohServerUrl = dohServers.get(0);
            logger.info("使用配置的DoH服务器: {}", dohServerUrl);
            
            // 如果配置了多个服务器，记录日志
            if (dohServers.size() > 1) {
                logger.info("配置了 {} 个DoH服务器，将按顺序使用", dohServers.size());
                for (int i = 0; i < dohServers.size(); i++) {
                    logger.info("  {}. {}", i + 1, dohServers.get(i));
                }
            }
        } else {
            logger.info("使用内置DoH服务器列表");
        }
        
        DohResolver resolver = new DohResolver(dohServerUrl);
        
        // 配置代理（需要扩展DohResolver以支持代理）
        if (config.hasProxy()) {
            configureProxy(resolver, config);
        }
        
        return resolver;
    }
    
     /**
     * 配置代理设置 - 更新版本
     */
    private void configureProxy(DohResolver resolver, DnsConfig config) {
        try {
            if (config.hasProxy()) {
                String proxyType = config.getProxyType();
                String authInfo = config.hasProxyAuth() ? 
                    " (认证用户: " + config.getProxyUsername() + ")" : "";
                
                logger.info("代理服务器配置: {} {}:{} {}{}", 
                           proxyType.toUpperCase(), 
                           config.getProxyIP(), 
                           config.getProxyPort(),
                           config.hasProxyAuth() ? "有认证" : "无认证",
                           authInfo);
            } else {
                logger.info("代理服务器配置: 未启用");
            }
        } catch (Exception e) {
            logger.error("配置代理日志记录失败", e);
        }
    }
    
    /**
     * 创建Host文件解析器
     */
    private HostFileResolver createHostFileResolver(DnsConfig config) {
        String hostFile = config.getHostFile();
        if (hostFile != null && !hostFile.trim().isEmpty()) {
            logger.info("使用自定义Host文件: {}", hostFile);
            // 这里需要修改HostFileResolver以支持自定义文件路径
            // 暂时使用默认构造函数，后续需要扩展
            return new HostFileResolver();
        }
        return new HostFileResolver();
    }
    
    /**
     * 创建域名拦截器
     */
    private DomainBlocker createDomainBlocker(DnsConfig config) {
        String banDomainFile = config.getBanDomainFile();
        if (banDomainFile != null && !banDomainFile.trim().isEmpty()) {
            logger.info("使用自定义BanDomain文件: {}", banDomainFile);
            return new DomainBlocker(banDomainFile);
        }
        return new DomainBlocker("BanDomain.txt");
    }
    
    /**
     * 设置日志级别
     */
    private void setLogLevel(String level) {
        try {
            ch.qos.logback.classic.Logger rootLogger = 
                (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
            
            ch.qos.logback.classic.Level logbackLevel = ch.qos.logback.classic.Level.toLevel(level);
            rootLogger.setLevel(logbackLevel);
            
            logger.info("日志级别设置为: {}", level);
        } catch (Exception e) {
            logger.warn("设置日志级别失败: {}", e.getMessage());
        }
    }
    
    /**
     * 记录当前服务器信息
     */
    private void logCurrentServerInfo() {
        try {
            String currentServer = dohResolver.getCurrentServer();
            logger.info("当前使用的DoH服务器: {}", currentServer);
            
            // 显示完整的服务器信息
            List<String> servers = dohResolver.getAvailableServers();
            if (servers != null && !servers.isEmpty()) {
                logger.info("DoH服务器列表 ({}个):", servers.size());
                LoggerUtil.logServerList(currentServer, servers);
            }
        } catch (Exception e) {
            logger.warn("无法获取服务器信息: {}", e.getMessage());
        }
    }
    
    public void start() throws Exception {
        if (running) {
            logger.warn("服务器已在运行");
            return;
        }
        
        createLogDirectory();
        
        socket = new DatagramSocket(port, InetAddress.getByName("0.0.0.0"));
        running = true;
        
        String currentDohServer = dohResolver.getCurrentServer();
        String hostFileLocation = hostFileResolver != null ? hostFileResolver.getHostFileLocation() : "默认";
        
        // 修改调用，传入config参数
        LoggerUtil.logServerStart(port, currentDohServer, hostFileLocation, autoSwitchEnabled, config);
        
        // 显示详细的服务器启动信息
        logServerStartupInfo(currentDohServer);
        
        // 启动统计信息定时任务（包含服务器状态）
        startStatisticsLogger();
        
        // 启动服务器状态监控
        startServerStatusMonitor();
        
        // 启动配置重载检查
        startConfigReloadChecker();
        
        logger.info("DoH DNS 服务器已启动并准备就绪，监听端口: {}", port);
        
        while (running) {
            try {
                byte[] buffer = new byte[512];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                
                socket.receive(packet);

                DnsHandler handler = new DnsHandler(socket, packet, dohResolver,
                                    ptrResolver, hostFileResolver, domainBlocker, config);
                threadPool.execute(handler);
                
            } catch (Exception e) {
                if (running) {
                    logger.error("接收数据包时发生错误 [当前服务器: {}]", DnsHandler.getCurrentDohServer(), e);
                }
            }
        }
    }
	
	/**
     * 记录代理配置信息
     */
    private void logProxyConfiguration() {
        if (config.hasProxy()) {
            String proxyType = config.getProxyType().toUpperCase();
            String authInfo = config.hasProxyAuth() ? 
                String.format(" (认证用户: %s)", config.getProxyUsername()) : " (无认证)";
            
            logger.info("代理配置: {} {}:{}{}", 
                       proxyType, config.getProxyIP(), config.getProxyPort(), authInfo);
            logger.info("代理状态: 已启用");
        } else {
            logger.info("代理配置: 未启用");
        }
    }
	
	/**
     * 记录服务器统计信息
     */
    private void logServerStatistics() {
        try {
            List<String> servers = dohResolver.getAvailableServers();
            logger.info("可用DoH服务器: {} 个", servers.size());
            
            if (logger.isDebugEnabled() && !servers.isEmpty()) {
                for (int i = 0; i < servers.size(); i++) {
                    String status = (i == dohResolver.getCurrentServerIndex()) ? "[当前]" : "[备用]";
                    logger.debug("  {}. {} {}", i + 1, servers.get(i), status);
                }
            }
        } catch (Exception e) {
            logger.debug("无法获取服务器列表信息: {}", e.getMessage());
        }
    }
    
    /**
     * 记录服务器启动信息
     */
    private void logServerStartupInfo(String currentDohServer) {
        logger.info("================================================");
        logger.info("DoH DNS 服务器启动信息");
        logger.info("监听端口: {}", port);
        logger.info("当前DoH服务器: {}", currentDohServer);
        logger.info("自动切换: {}", autoSwitchEnabled ? "启用" : "禁用");
        logger.info("切换阈值: {} 个查询", switchThreshold);
        logger.info("Host文件域名数: {}", hostFileResolver.getDomainCount());
        logger.info("拦截域名数: {}", domainBlocker.getBlockedDomainCount());
        logger.info("配置文件: {}", config.getConfigFilePath());
        logger.info("日志级别: {}", config.getLogLevel());
        logger.info("线程池大小: {}", config.getThreadPoolSize());
        logger.info("缓存状态: {}", config.isCacheEnabled() ? "启用" : "禁用");
        
        // 新增代理信息显示
        logProxyConfiguration();
        
        // 显示服务器统计信息
        logServerStatistics();
        
        logger.info("服务器启动时间: {}", new java.util.Date(startTime));
        logger.info("================================================");
    }
	
    
    private void createLogDirectory() {
        try {
            java.nio.file.Files.createDirectories(java.nio.file.Paths.get("logs"));
            logger.debug("日志目录已创建：logs/");
        } catch (Exception e) {
            logger.warn("无法创建日志目录: {}", e.getMessage());
        }
    }
    
    private void startStatisticsLogger() {
        // 每5分钟记录一次统计信息（包含服务器信息）
        statsScheduler.scheduleAtFixedRate(() -> {
            if (running) {
                long total = DnsHandler.getTotalQueries();
                long success = DnsHandler.getSuccessfulQueries();
                long failed = DnsHandler.getFailedQueries();
                long duplicate = DnsHandler.getDuplicateQueries();
                String currentServer = DnsHandler.getCurrentDohServer();
                
                // 记录包含服务器信息的统计
                logStatisticsWithServerInfo(total, success, failed, duplicate, currentServer);
            }
        }, 5, 5, TimeUnit.MINUTES);
        
        logger.debug("统计信息记录器已启动（间隔：5分钟）");
    }
    
    /**
     * 启动服务器状态监控
     */
    private void startServerStatusMonitor() {
        // 每600秒检查一次服务器状态
        healthCheckScheduler.scheduleAtFixedRate(() -> {
            if (running) {
                try {
                    String currentServer = DnsHandler.getCurrentDohServer();
                    boolean isHealthy = healthChecker.isServerHealthy(currentServer);
                    
                    if (isHealthy) {
                        logger.debug("DoH服务器状态检查: {} [正常]", currentServer);
                    } else {
                        logger.warn("DoH服务器状态检查: {} [异常]", currentServer);
                    }
                    
                    // 记录服务器状态到单独的状态日志
                    LoggerUtil.logServerStatus(currentServer, isHealthy, DnsHandler.getDohQueryCount());
                    
                } catch (Exception e) {
                    logger.debug("服务器状态检查失败: {}", e.getMessage());
                }
            }
        }, 600, 600, TimeUnit.SECONDS);
        
        logger.debug("服务器状态监控器已启动（间隔：600秒）");
    }
    
    /**
     * 启动配置重载检查
     */
    private void startConfigReloadChecker() {
        // 每30秒检查一次配置更新
        configCheckScheduler.scheduleAtFixedRate(() -> {
            if (running && config.needsReload()) {
                logger.info("检测到配置文件修改，重新加载配置...");
                try {
                    config.loadConfig();
                    // 应用新的配置（需要实现动态配置更新）
                    applyConfigChanges(config);
                } catch (Exception e) {
                    logger.error("重新加载配置失败", e);
                }
            }
        }, 30, 30, TimeUnit.SECONDS);
        
        logger.debug("配置重载检查器已启动（间隔：30秒）");
    }
    
    /**
     * 应用配置变更（部分配置需要重启才能生效）
     */
    private void applyConfigChanges(DnsConfig newConfig) {
        // 可以动态更新的配置
        setLogLevel(newConfig.getLogLevel());
        logger.info("配置已重新加载（部分配置需要重启服务器才能生效）");
        
        // 记录配置变更
        LoggerUtil.logConfigReload("config.ini", newConfig.getAllProperties().size());
    }
    
    /**
     * 记录包含服务器信息的统计 - 修复百分比格式化问题
     */
    private void logStatisticsWithServerInfo(long total, long success, long failed, 
                                           long duplicate, String currentServer) {
        long uptime = System.currentTimeMillis() - startTime;
        long uptimeMinutes = uptime / (1000 * 60);
        long hostFileHits = DnsHandler.getHostFileHits();
        long ptrHits = DnsHandler.getPtrHits();
        long dohHits = DnsHandler.getDohHits();
        long blockedQueries = DnsHandler.getBlockedQueries();
        
        // 修复百分比计算
        double successRate = total > 0 ? (success * 100.0 / total) : 0.0;
        double failedRate = total > 0 ? (failed * 100.0 / total) : 0.0;
        double duplicateRate = total > 0 ? (duplicate * 100.0 / total) : 0.0;
        double hostFileRate = total > 0 ? (hostFileHits * 100.0 / total) : 0.0;
        double ptrRate = total > 0 ? (ptrHits * 100.0 / total) : 0.0;
        double dohRate = total > 0 ? (dohHits * 100.0 / total) : 0.0;
        double blockedRate = total > 0 ? (blockedQueries * 100.0 / total) : 0.0;
        
        // 修复：先格式化百分比字符串
        String successRateStr = String.format("%.2f", successRate);
        String failedRateStr = String.format("%.2f", failedRate);
        String duplicateRateStr = String.format("%.2f", duplicateRate);
        String hostFileRateStr = String.format("%.2f", hostFileRate);
        String ptrRateStr = String.format("%.2f", ptrRate);
        String dohRateStr = String.format("%.2f", dohRate);
        String blockedRateStr = String.format("%.2f", blockedRate);
        
        logger.info("════════════════ 服务器统计信息 ════════════════════");
        logger.info("运行时间: {} 分钟", uptimeMinutes);
        logger.info("当前DoH服务器: {}", currentServer);
        logger.info("总查询数: {}", total);
        logger.info("成功查询: {} ({}%)", success, successRateStr);
        logger.info("失败查询: {} ({}%)", failed, failedRateStr);
        logger.info("重复查询: {} ({}%)", duplicate, duplicateRateStr);
        logger.info("Host文件命中: {} ({}%)", hostFileHits, hostFileRateStr);
        logger.info("PTR解析命中: {} ({}%)", ptrHits, ptrRateStr);
        logger.info("DoH解析命中: {} ({}%)", dohHits, dohRateStr);
        logger.info("拦截查询: {} ({}%)", blockedQueries, blockedRateStr);
        logger.info("═══════════════════════════════════════════════");
        
        // 调用LoggerUtil的修复版本
        LoggerUtil.logDetailedStatistics(total, success, failed, duplicate, 
                                       hostFileHits, ptrHits, dohHits, 
                                       blockedQueries, currentServer);
    }
    
    public void stop() {
        running = false;
        
        // 记录关闭时的服务器信息
        String currentServer = DnsHandler.getCurrentDohServer();
        logger.info("正在关闭服务器... [当前服务器: {}]", currentServer);
        
        long total = DnsHandler.getTotalQueries();
        long success = DnsHandler.getSuccessfulQueries();
        long failed = DnsHandler.getFailedQueries();
        long duplicate = DnsHandler.getDuplicateQueries();
        
        logStatisticsWithServerInfo(total, success, failed, duplicate, currentServer);
        LoggerUtil.logServerStop();
        
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
        
        // 关闭线程池和服务
        shutdownExecutorService(threadPool, "线程池");
        shutdownExecutorService(statsScheduler, "统计调度器");
        shutdownExecutorService(healthCheckScheduler, "健康检查调度器");
        shutdownExecutorService(configCheckScheduler, "配置检查调度器");
        
        if (dohResolver != null) {
            dohResolver.close();
        }
        if (ptrResolver != null) {
            ptrResolver.close();
        }
        if (hostFileResolver != null) {
            hostFileResolver.shutdown();
        }
        if (domainBlocker != null) {
            domainBlocker.shutdown();
        }
        if (healthChecker != null) {
            healthChecker.close();
        }
        
        logger.info("DoH DNS 服务器已优雅关闭 [最终服务器: {}]", currentServer);
    }
    
    /**
     * 安全关闭执行器服务
     */
    private void shutdownExecutorService(ExecutorService executor, String serviceName) {
        if (executor != null && !executor.isShutdown()) {
            try {
                executor.shutdown();
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    logger.warn("{} 未及时关闭，强制关闭", serviceName);
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
    
    public static void main(String[] args) {
        // 创建配置实例
        DnsConfig config = new DnsConfig();
        
        // 使用命令行参数覆盖配置
        config = overrideConfigWithArgs(config, args);
        
        DohDnsServer server = new DohDnsServer(config);
        
        // 添加关闭钩子
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("接收到关闭信号，正在停止服务器...");
            server.stop();
        }));
        
        try {
            server.start();
        } catch (Exception e) {
            logger.error("服务器启动失败", e);
            System.exit(1);
        }
    }
    
    /**
     * 使用命令行参数覆盖配置
     */
    private static DnsConfig overrideConfigWithArgs(DnsConfig config, String[] args) {
        // 现有的命令行参数解析逻辑
        int port = config.getPort();
        String dohServer = null;
        boolean autoSwitchEnabled = config.isAutoSwitchEnabled();
        
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-p":
                case "--port":
                    if (i + 1 < args.length) {
                        try {
                            port = Integer.parseInt(args[++i]);
                            logger.info("命令行参数覆盖端口: {}", port);
                        } catch (NumberFormatException e) {
                            logger.warn("无效的端口号: {}, 使用默认值: {}", args[i], port);
                        }
                    }
                    break;
                case "--doh":
                    if (i + 1 < args.length) {
                        dohServer = args[++i];
                        logger.info("命令行参数指定DoH服务器: {}", dohServer);
                    }
                    break;
                case "--autoswitch-off":
                    autoSwitchEnabled = false;
                    logger.info("命令行参数禁用自动切换");
                    break;
                case "-h":
                case "--help":
                    printHelp();
                    System.exit(0);
                    break;
            }
        }
        
        // 创建新的配置实例来应用命令行参数
        // 注意：这里需要扩展DnsConfig以支持设置方法，或者创建新的配置
        // 由于DnsConfig当前是只读的，我们记录日志但保持配置不变
        // 实际应用中可以实现配置的setter方法
        
        return config;
    }
    
    private static void printHelp() {
        System.out.println("用法: java -jar doh-dns-server.jar [选项]");
        System.out.println("选项:");
        System.out.println("  -p, --port 端口    监听端口（默认: 53 或 config.ini中的设置）");
        System.out.println("  --doh URL         DoH服务器地址（可选，默认使用内置服务器或config.ini设置）");
        System.out.println("  --autoswitch-off  禁用DoH服务器自动切换功能（默认开启或根据config.ini设置）");
        System.out.println("  -h, --help        显示此帮助信息");
        System.out.println();
        System.out.println("配置文件:");
        System.out.println("  服务器会读取当前目录下的 config.ini 文件进行配置");
        System.out.println("  如果文件不存在，会自动创建默认配置文件");
        System.out.println();
        System.out.println("示例:");
        System.out.println("  java -jar doh-dns-server.jar -p 53");
        System.out.println("  java -jar doh-dns-server.jar --doh https://dns.google/dns-query");
        System.out.println("  java -jar doh-dns-server.jar --autoswitch-off");
        System.out.println("  java -jar doh-dns-server.jar -p 5353 --doh https://cloudflare-dns.com/dns-query");
    }
    
    // 向后兼容的构造函数
    public DohDnsServer(int port) {
        this(port, null, true);
    }
    
    public DohDnsServer(int port, String dohServerUrl) {
        this(port, dohServerUrl, true);
    }
    
    public DohDnsServer(int port, String dohServerUrl, boolean autoSwitchEnabled) {
        // 创建配置实例并设置参数
        this.config = new DnsConfig();
        
        this.port = port;
        this.dohServerUrl = dohServerUrl;
        this.autoSwitchEnabled = autoSwitchEnabled;
        
        // 根据参数创建解析器
        this.dohResolver = new DohResolver(dohServerUrl);
        this.ptrResolver = new PtrResolver();
        this.hostFileResolver = new HostFileResolver();
        this.domainBlocker = new DomainBlocker("BanDomain.txt");
        
        this.threadPool = Executors.newFixedThreadPool(50);
        this.statsScheduler = Executors.newScheduledThreadPool(1);
        this.healthChecker = new DohHealthChecker();
        this.healthCheckScheduler = Executors.newScheduledThreadPool(1);
        this.configCheckScheduler = Executors.newScheduledThreadPool(1);
        this.startTime = System.currentTimeMillis();
        
        if (autoSwitchEnabled) {
            logger.info("DoH服务器自动切换功能已启用 (阈值: {}个请求)", switchThreshold);
        } else {
            logger.info("DoH服务器自动切换功能已禁用");
        }
        
        logCurrentServerInfo();
    }
}