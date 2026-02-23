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
    
    private static Properties properties;
    private static Path configPath;
    private long lastModifiedTime = 0;
    
    // 默认配置值
    private static final Map<String, String> DEFAULT_CONFIG;
    static {
        Map<String, String> config = new HashMap<>();
        config.put("port", "53");//端口
        config.put("autoswitch", "on");//自动切换开馆 on 或者 off
        config.put("DoHServer", "");//DoH服务器
        config.put("HostFile", "");//自定义Host文件位置
        config.put("BanDomainFile", "");//自定义BanDomain文件位置
        config.put("ProxyIP", "");//代理服务器IP
        config.put("ProxyPort", "");//代理服务器端口
        config.put("log_level", "INFO");//日志等级
        config.put("thread_pool_size", "50");//线程池大小
        config.put("cache_enabled", "true");//是否允许缓存
        config.put("cache_ttl", "300");//缓存ttl
        config.put("ptr_resolution_mode", "traditional_dns");  // 可选值: doh, traditional_dns, block
        config.put("ptr_traditional_dns_server", "8.8.8.8");  // 传统DNS服务器地址
        config.put("ptr_traditional_dns_port", "53");  // 传统DNS服务器端口
        config.put("ptr_timeout", "5000");  // PTR解析超时时间(毫秒)
		config.put("proxy_type", "http"); // 代理类型http 或 socks
        config.put("proxy_username", "");//代理认证用户名
        config.put("proxy_password", "");//代理认证密码
        config.put("admin_port", "18853");// 管理端口
        config.put("admin_key", ""); // 管理密钥
        config.put("admin_enabled", "true"); // 启用管理功能
        DEFAULT_CONFIG = Collections.unmodifiableMap(config);
    }
    
    public DnsConfig() {
        DnsConfig.properties = new Properties();
        DnsConfig.configPath = getConfigPath(); 
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
    public static void createDefaultConfig() {
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
            lines.add("DoHServer=\"\"");
            lines.add("");
            lines.add("# 自定义Host文件位置，留空使用默认host.txt");
            lines.add("HostFile=\"\"");
            lines.add("");
            lines.add("# 自定义BanDomain文件位置，留空使用默认BanDomain.txt");
            lines.add("BanDomainFile=\"\"");
            lines.add("");
            lines.add("# PTR解析模式:");
            lines.add("#   doh - 通过DoH服务器解析（默认）");
            lines.add("#   traditional_dns - 通过传统DNS服务器解析");
            lines.add("#   block - 屏蔽所有PTR查询");
            lines.add("ptr_resolution_mode=\"traditional_dns\"");
            lines.add("");
            lines.add("# 传统DNS服务器配置（当ptr_resolution_mode=traditional_dns时生效）");
            lines.add("ptr_traditional_dns_server=\"119.29.29.29\"");
            lines.add("ptr_traditional_dns_port=\"53\"");
            lines.add(" ptr_timeout=\"5000\"");
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
			lines.add("");
            lines.add("# 是否启动管理功能（ture or false）");
            lines.add("admin_enabled=\"true\"");
			lines.add("");
            lines.add("# 管理端口（留空默认18853）");
            lines.add("admin_port=\"\"");
			lines.add("");
            lines.add("# 管理鉴权key（留空则随机16位字母数字组合）");
            lines.add("admin_key=\"\"");
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
        logger.info("PTR处理方式：{}", getPtrResolutionMode());
        if(getString("ptr_resolution_mode", "").equals("traditional_dns")){
            logger.info("传统DNS服务器：{}",getptTraditionalDnsServer());
        }
        
        // 新增：管理功能配置信息
        boolean adminEnabled = isAdminEnabled();
        int adminPort = getAdminPort();
        String adminKey = getAdminKey();
        
        logger.info("远程管理功能: {}", adminEnabled ? "✅ 已启用" : "❌ 已禁用");
        if (adminEnabled) {
            logger.info("管理端口: {}", adminPort);
            if (adminKey != null && !adminKey.isEmpty()) {
                boolean isRandomKey = getString("admin_key", "").trim().isEmpty();
                String keyType = isRandomKey ? "随机生成" : "固定配置";
                logger.info("管理密钥: {}位字符 ({})", adminKey.length(), keyType);
                
                // 安全提示
                if (isRandomKey) {
                    logger.info("💡 提示: 随机生成的密钥将在每次重启时变化");
                } else {
                    logger.info("💡 提示: 使用固定配置密钥");
                }
            } else {
                logger.info("管理密钥: 未配置");
            }
        }
        
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
    
    public String getPtrResolutionMode() {
        //doh, traditional_dns, block
        if (getString("ptr_resolution_mode", "").equals("traditional_dns")) {
            return "通过传统DNS";
        } 
        else if (getString("ptr_resolution_mode", "").equals("doh")) {
            return "DoH服务器尝试解析";
        } 
        else if (getString("ptr_resolution_mode", "").equals("block")) {
            return "拦截";
        } 
        return getString("ptr_resolution_mode", "");
    }

    public String getptTraditionalDnsServer() {
        return getString("ptr_traditional_dns_server", "");
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
    public int getAdminPort() {
        return getInt("admin_port", 18853);
    }
    
    public String getAdminKey() {
        String key = getString("admin_key", "").trim();
        if (key.isEmpty()) {
            // 生成随机密钥
            key = generateRandomKey();
            // 可选：保存到配置文件
        }
        logger.warn("随机生成key: {}", key);
        return key;
    }
    
    public boolean isAdminEnabled() {
        return getBoolean("admin_enabled", true);
    }
    
    private String generateRandomKey() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder key = new StringBuilder(16);
        Random random = new Random();
        for (int i = 0; i < 16; i++) {
            key.append(chars.charAt(random.nextInt(chars.length())));
        }
        return key.toString();
    }
    
    public boolean validateAdminKey(String key) {
        if (key == null || key.trim().isEmpty()) {
            return false;
        }
        // 检查是否为英文或数字组合的16位以下字符串
        return key.matches("^[a-zA-Z0-9]{1,16}$");
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