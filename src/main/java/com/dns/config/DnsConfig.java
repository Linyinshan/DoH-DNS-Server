package com.dns.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * DNS服务器配置文件解析器
 */
public class DnsConfig {
    private static final Logger logger = LoggerFactory.getLogger(DnsConfig.class);
    
    private final Properties properties;
    private final Path configPath;
    private long lastModifiedTime = 0;
    
    // 默认配置值
    private static final Map<String, String> DEFAULT_CONFIG;
    static {
        Map<String, String> config = new HashMap<>();
        config.put("port", "53");
        config.put("autoswitch", "on");
        config.put("DoHServer", "");
        config.put("HostFile", "");
        config.put("BanDomainFile", "");
        config.put("ProxyIP", "");
        config.put("ProxyPort", "");
        config.put("log_level", "INFO");
        config.put("thread_pool_size", "50");
        config.put("cache_enabled", "true");
        config.put("cache_ttl", "300");
		config.put("proxy_type", "http"); // http 或 socks
        config.put("proxy_username", "");
        config.put("proxy_password", "");
        DEFAULT_CONFIG = Collections.unmodifiableMap(config);
    }
    
    public DnsConfig() {
        this.properties = new Properties();
        this.configPath = getConfigPath(); // 修复：使用Path对象而不是String
        loadConfig();
    }
    
    /**
     * 获取配置文件路径（返回Path对象，内部使用）
     */
    private Path getConfigPath() {
        try {
            String jarDir = System.getProperty("user.dir");
            return Paths.get(jarDir, "config.ini");
        } catch (Exception e) {
            logger.warn("无法获取 jar 目录，使用当前目录");
            return Paths.get("config.ini");
        }
    }
    
    /**
     * 获取配置文件路径（字符串形式）
     */
    public String getConfigFilePath() {
        return configPath.toString();
    }
    
    /**
     * 加载配置文件
     */
    public synchronized void loadConfig() {
        try {
            Path path = configPath; // 直接使用成员变量
            if (!Files.exists(path)) {
                logger.info("配置文件不存在: {}", path);
                createDefaultConfig();
                return;
            }
            
            // 检查文件是否被修改
            long currentModifiedTime = Files.getLastModifiedTime(path).toMillis();
            if (currentModifiedTime <= lastModifiedTime) {
                return; // 文件未修改
            }
            
            Properties newProps = new Properties();
            try (var reader = Files.newBufferedReader(path)) {
                newProps.load(reader);
            }
            
            properties.clear();
            
            // 只加载已知的配置项，忽略未知项
            for (String key : DEFAULT_CONFIG.keySet()) {
                String value = newProps.getProperty(key);
                if (value != null) {
                    // 去除值的引号
                    value = value.replace("\"", "").trim();
                    properties.setProperty(key, value);
                } else {
                    properties.setProperty(key, DEFAULT_CONFIG.get(key));
                }
            }
            
            lastModifiedTime = currentModifiedTime;
            logger.info("配置文件加载成功: {}", path);
            logConfigSummary();
            
        } catch (IOException e) {
            logger.error("读取配置文件失败", e);
            createDefaultConfig();
        } catch (Exception e) {
            logger.error("加载配置文件时发生意外错误", e);
            createDefaultConfig();
        }
    }
    
    /**
     * 创建默认配置文件
     */
    private void createDefaultConfig() {
        logger.info("创建默认配置文件: {}", configPath);
        
        try {
            List<String> lines = new ArrayList<>();
            lines.add("# DNS服务器配置文件");
            lines.add("# 端口（留空默认53）");
            lines.add("port=\"53\"");
            lines.add("");
            lines.add("# 自动切换DoH服务器开关，默认开启 (on/off)");
            lines.add("autoswitch=\"on\"");
            lines.add("");
            lines.add("# 自定义DoH服务器，多个服务器使用逗号分隔，留空使用内置");
            lines.add("# 只提供1个时关闭自动切换并忽略autoswitch设置");
            lines.add("# 提供多个时开启自动切换并忽略autoswitch设置");
            lines.add("DoHServer=\"\"");
            lines.add("");
            lines.add("# 自定义Host文件位置，留空使用默认host.txt");
            lines.add("HostFile=\"\"");
            lines.add("");
            lines.add("# 自定义BanDomain文件位置，留空使用默认BanDomain.txt");
            lines.add("BanDomainFile=\"\"");
            lines.add("");
            lines.add("# 代理服务器IP，DoH解析使用的代理服务器，留空不使用");
            lines.add("ProxyIP=\"\"");
            lines.add("");
            lines.add("# 代理服务器端口，代理服务器留空或有误时会忽略该设置");
            lines.add("ProxyPort=\"\"");
            lines.add("");
            lines.add("# 代理服务器类型 (http 或 socks，默认: http)");
            lines.add("proxy_type=\"http\"");
            lines.add("");
            lines.add("# 代理服务器用户名（如需要认证）");
            lines.add("proxy_username=\"\"");
            lines.add("");
            lines.add("# 代理服务器密码（如需要认证）");
            lines.add("proxy_password=\"\"");
            lines.add("");
            lines.add("# 日志级别 (TRACE, DEBUG, INFO, WARN, ERROR)");
            lines.add("log_level=\"INFO\"");
            lines.add("");
            lines.add("# 线程池大小");
            lines.add("thread_pool_size=\"50\"");
            lines.add("");
            lines.add("# 是否启用缓存 (true/false)");
            lines.add("cache_enabled=\"true\"");
            lines.add("");
            lines.add("# 缓存TTL（秒）");
            lines.add("cache_ttl=\"300\"");
            
            // 确保目录存在
            if (configPath.getParent() != null) {
                Files.createDirectories(configPath.getParent());
            }
            
            Files.write(configPath, lines);
            logger.info("默认配置文件创建完成");
            
            // 设置默认值
            properties.clear();
            properties.putAll(DEFAULT_CONFIG);
            
        } catch (IOException e) {
            logger.error("创建默认配置文件失败", e);
            // 使用内存中的默认值
            properties.clear();
            properties.putAll(DEFAULT_CONFIG);
        }
    }
    
    /**
     * 记录配置摘要
     */
    private void logConfigSummary() {
        logger.info("=== 配置摘要 ===");
        logger.info("端口: {}", getPort());
        logger.info("自动切换: {}", isAutoSwitchEnabled() ? "开启" : "关闭");
        logger.info("DoH服务器数量: {}", getDohServers().size());
        logger.info("Host文件: {}", getHostFile());
        logger.info("BanDomain文件: {}", getBanDomainFile());
        logger.info("代理服务器: {}", hasProxy() ? getProxyIP() + ":" + getProxyPort() : "未启用");
        logger.info("日志级别: {}", getLogLevel());
        logger.info("线程池大小: {}", getThreadPoolSize());
        logger.info("缓存: {}", isCacheEnabled() ? "启用" : "禁用");
        logger.info("缓存TTL: {}秒", getCacheTtl());
        logger.info("=================");
    }
    
    // 配置获取方法
    public int getPort() {
        return getInt("port", 53);
    }
    
    public boolean isAutoSwitchEnabled() {
        return "on".equalsIgnoreCase(getString("autoswitch", "on"));
    }
    
    public List<String> getDohServers() {
        String servers = getString("DoHServer", "");
        if (servers == null || servers.trim().isEmpty()) {
            return Collections.emptyList();
        }
        
        List<String> serverList = new ArrayList<>();
        for (String server : servers.split(",")) {
            String trimmed = server.trim();
            if (!trimmed.isEmpty()) {
                serverList.add(trimmed);
            }
        }
        return serverList;
    }
    
    public String getHostFile() {
        return getString("HostFile", "");
    }
    
    public String getBanDomainFile() {
        return getString("BanDomainFile", "");
    }
    
    public String getProxyIP() {
        return getString("ProxyIP", "");
    }
    
    public int getProxyPort() {
        return getInt("ProxyPort", 0);
    }
    
    public boolean hasProxy() {
        String ip = getProxyIP();
        int port = getProxyPort();
        return ip != null && !ip.trim().isEmpty() && port > 0 && port <= 65535;
    }
    
    public String getLogLevel() {
        return getString("log_level", "INFO");
    }
    
    public int getThreadPoolSize() {
        return getInt("thread_pool_size", 50);
    }
    
    public boolean isCacheEnabled() {
        return getBoolean("cache_enabled", true);
    }
    
    public int getCacheTtl() {
        return getInt("cache_ttl", 300);
    }
	 public String getProxyType() {
        return getString("proxy_type", "http").toLowerCase();
    }
    
    public String getProxyUsername() {
        return getString("proxy_username", "");
    }
    
    public String getProxyPassword() {
        return getString("proxy_password", "");
    }
    
    public boolean isSocksProxy() {
        return "socks".equalsIgnoreCase(getProxyType());
    }
    
    public boolean isHttpProxy() {
        return "http".equalsIgnoreCase(getProxyType()) || getProxyType().isEmpty();
    }
    
    // 工具方法
    public boolean hasProxyAuth() {
        String username = getProxyUsername();
        String password = getProxyPassword();
        return username != null && !username.trim().isEmpty() && 
               password != null && !password.trim().isEmpty();
    }
    
    public String getString(String key, String defaultValue) {
        String value = properties.getProperty(key);
        return value != null ? value : defaultValue;
    }
    
    public int getInt(String key, int defaultValue) {
        try {
            String value = properties.getProperty(key);
            return value != null ? Integer.parseInt(value) : defaultValue;
        } catch (NumberFormatException e) {
            logger.warn("配置项 {} 的值不是有效的整数，使用默认值: {}", key, defaultValue);
            return defaultValue;
        }
    }
    
    public boolean getBoolean(String key, boolean defaultValue) {
        String value = properties.getProperty(key);
        if (value == null) return defaultValue;
        
        return "true".equalsIgnoreCase(value) || "on".equalsIgnoreCase(value) || "1".equals(value);
    }
    
    /**
     * 获取所有配置项
     */
    public Properties getAllProperties() {
        return new Properties(properties);
    }
    
    /**
     * 检查配置是否需要重新加载
     */
    public boolean needsReload() {
        try {
            if (!Files.exists(configPath)) {
                return false;
            }
            long currentModifiedTime = Files.getLastModifiedTime(configPath).toMillis();
            return currentModifiedTime > lastModifiedTime;
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * 获取配置文件最后修改时间
     */
    public long getLastModifiedTime() {
        return lastModifiedTime;
    }
    
    /**
     * 获取配置文件目录
     */
    public String getConfigDirectory() {
        Path parent = configPath.getParent();
        return parent != null ? parent.toString() : ".";
    }
    
    /**
     * 检查配置文件是否存在
     */
    public boolean configFileExists() {
        return Files.exists(configPath);
    }
    
    /**
     * 重新加载配置文件（强制）
     */
    public void reload() {
        loadConfig();
    }
}