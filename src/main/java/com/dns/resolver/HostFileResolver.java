package com.dns.resolver;

import com.dns.dns.DnsMessage;
import com.dns.dns.DnsQuestion;
import com.dns.dns.DnsRecord;
import com.dns.dns.DnsRecordType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 自定义hosts文件解析器
 * 支持自定义文件路径，从jar同目录下的host.txt文件或自定义路径加载自定义解析规则
 */
public class HostFileResolver {
    private static final Logger logger = LoggerFactory.getLogger(HostFileResolver.class);

    private final Map<String, List<String>> hostMap; // 域名 -> IP列表映射
    private final Map<String, List<String>> reverseHostMap; // IP -> 域名列表映射（用于PTR查询）
    private long lastModifiedTime = 0;
    private final Path hostFilePath;
    private final ScheduledExecutorService scheduler;
    private int validCount = 0;
    
    /**
     * 默认构造函数，使用默认host.txt文件
     */
    public HostFileResolver() {
        this(null);
    }
    
    /**
     * 带自定义文件路径的构造函数
     * @param customHostFilePath 自定义host文件路径，如果为null或空则使用默认路径
     */
    public HostFileResolver(String customHostFilePath) {
        this.hostMap = new ConcurrentHashMap<>();
        this.reverseHostMap = new ConcurrentHashMap<>();
        this.hostFilePath = getHostFilePath(customHostFilePath);
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
        
        logger.info("初始化Host文件解析器，文件路径: {}", hostFilePath);
        loadHostFile();
        scheduler.scheduleAtFixedRate(this::checkFileUpdate, 30, 30, TimeUnit.SECONDS);
    }
    
    /**
     * 获取host文件路径
     * @param customPath 自定义路径，如果为null或空则使用默认路径
     */
    private Path getHostFilePath(String customPath) {
        try {
            if (customPath != null && !customPath.trim().isEmpty()) {
                Path custom = Paths.get(customPath);
                if (Files.exists(custom)) {
                    logger.info("使用自定义Host文件路径: {}", customPath);
                    return custom;
                } else {
                    logger.warn("自定义Host文件不存在: {}, 将尝试创建默认文件", customPath);
                    // 继续使用默认路径
                }
            }
            
            // 使用默认路径
            String jarDir = System.getProperty("user.dir");
            Path defaultPath = Paths.get(jarDir, "host.txt");
            logger.info("使用默认Host文件路径: {}", defaultPath);
            return defaultPath;
            
        } catch (Exception e) {
            logger.warn("无法获取 jar 目录，使用当前目录下的host.txt文件", e);
            return Paths.get("host.txt");
        }
    }
    
    /**
     * 检查文件更新
     */
    private void checkFileUpdate() {
        try {
            if (Files.exists(hostFilePath)) {
                long currentModifiedTime = Files.getLastModifiedTime(hostFilePath).toMillis();
                if (currentModifiedTime > lastModifiedTime) {
                    logger.info("检测到Host文件已修改，正在重新加载...");
                    loadHostFile();
                }
            } else {
                // 文件被删除，清空映射
                if (!hostMap.isEmpty()) {
                    logger.info("Host文件已被删除，清空所有映射");
                    hostMap.clear();
                    reverseHostMap.clear();
                    lastModifiedTime = 0;
                    validCount = 0;
                }
            }
        } catch (Exception e) {
            logger.error("检查文件更新出错", e);
        }
    }
    
    /**
     * 加载hosts文件
     */
    private synchronized void loadHostFile() {
        try {
            if (!Files.exists(hostFilePath)) {
                logger.info("Host文件不存在: {}", hostFilePath);
                hostMap.clear();
                reverseHostMap.clear();
                lastModifiedTime = 0;
                validCount = 0;
                
                // 尝试创建空的host文件
                try {
                    Files.createDirectories(hostFilePath.getParent());
                    Files.createFile(hostFilePath);
                    logger.info("已创建空的Host文件: {}", hostFilePath);
                } catch (Exception e) {
                    logger.debug("创建Host文件失败: {}", e.getMessage());
                }
                return;
            }
            
            List<String> lines = Files.readAllLines(hostFilePath);
            Map<String, List<String>> newHostMap = new HashMap<>();
            Map<String, List<String>> newReverseHostMap = new HashMap<>();
            int newValidCount = 0;
            
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                
                // 跳过空行和注释
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                // 解析IP和域名
                String[] parts = line.split("\\s+");
                if (parts.length < 2) {
                    logger.warn("第 {} 行Host条目无效: {}", i + 1, line);
                    continue;
                }
                
                String ip = parts[0].trim();
                String domain = parts[1].trim().toLowerCase();
                
                // 验证IP格式
                if (!isValidIp(ip)) {
                    logger.warn("第 {} 行存在错误的IP格式: {}", i + 1, ip);
                    continue;
                }
                
                // 验证域名格式
                if (!isValidDomain(domain)) {
                    logger.warn("第 {} 行存在错误的域名格式: {}", i + 1, domain);
                    continue;
                }
                
                // 添加到正向映射
                newHostMap.computeIfAbsent(domain, k -> new ArrayList<>()).add(ip);
                
                // 添加到反向映射（用于PTR查询）
                String reverseDomain = getReverseLookupDomain(ip);
                if (reverseDomain != null) {
                    newReverseHostMap.computeIfAbsent(reverseDomain, k -> new ArrayList<>()).add(domain);
                }
                
                newValidCount++;
                
                if (logger.isDebugEnabled()) {
                    logger.debug("加载Host条目: {} -> {}", domain, ip);
                }
            }
            
            // 原子性更新映射
            hostMap.clear();
            hostMap.putAll(newHostMap);
            
            reverseHostMap.clear();
            reverseHostMap.putAll(newReverseHostMap);
            
            lastModifiedTime = Files.getLastModifiedTime(hostFilePath).toMillis();
            validCount = newValidCount;
            
            logger.info("成功从 {} 加载 {} 条有效的主机条目", hostFilePath, validCount);
            
            if (logger.isDebugEnabled()) {
                logger.debug("当前Host映射: {}", newHostMap);
                logger.debug("当前反向映射: {}", newReverseHostMap);
            }
            
        } catch (IOException e) {
            logger.error("读取Host文件失败: {}", hostFilePath, e);
        } catch (Exception e) {
            logger.error("加载Host文件时发生意外错误", e);
        }
    }
    
    /**
     * 验证IP地址格式
     */
    private boolean isValidIp(String ip) {
        // IPv4验证
        if (ip.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")) {
            String[] parts = ip.split("\\.");
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            }
            return true;
        }
        
        // IPv6验证（简化）
        if (ip.matches("^[0-9a-fA-F:]+$")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 验证域名格式
     */
    private boolean isValidDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        
        // 基本域名格式验证
        return domain.matches("^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$");
    }
    
    /**
     * 获取反向查找域名（用于PTR记录）
     */
    private String getReverseLookupDomain(String ip) {
        if (ip.contains(".")) {
            // IPv4反向域名
            String[] parts = ip.split("\\.");
            if (parts.length == 4) {
                return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa";
            }
        } else if (ip.contains(":")) {
            // IPv6反向域名（简化处理）
            try {
                // 将IPv6地址转换为反向查找格式
                String normalizedIp = normalizeIPv6(ip);
                StringBuilder reverse = new StringBuilder();
                for (int i = normalizedIp.length() - 1; i >= 0; i--) {
                    if (normalizedIp.charAt(i) != ':') {
                        reverse.append(normalizedIp.charAt(i)).append(".");
                    }
                }
                reverse.append("ip6.arpa");
                return reverse.toString();
            } catch (Exception e) {
                logger.warn("IPv6地址转换失败: {}", ip, e);
            }
        }
        return null;
    }
    
    /**
     * 标准化IPv6地址
     */
    private String normalizeIPv6(String ip) {
        // 简化处理，实际应该使用InetAddress
        return ip.replace("::", ":0:0:").replaceAll(":{2,}", ":");
    }
    
    /**
     * 解析DNS查询
     */
    public DnsMessage resolve(DnsMessage request) {
        if (request.getQuestions().isEmpty()) {
            return createNotFoundResponse(request);
        }
        
        DnsQuestion question = request.getQuestions().get(0);
        String domain = question.getName().toLowerCase();
        DnsRecordType type = question.getType();
        
        logger.debug("Host解析器处理查询: {} {}", domain, type);
        
        // 根据查询类型处理
        switch (type) {
            case A:
            case AAAA:
                return resolveForwardQuery(request, domain, type);
            case PTR:
                return resolveReverseQuery(request, domain);
            default:
                logger.debug("Host解析器不支持查询类型: {}", type);
                return createNotFoundResponse(request);
        }
    }
    
    /**
     * 解析正向查询（A/AAAA记录）
     */
    private DnsMessage resolveForwardQuery(DnsMessage request, String domain, DnsRecordType type) {
        List<String> ips = hostMap.get(domain);
        
        if (ips == null || ips.isEmpty()) {
            logger.debug("域名在Host文件中未找到: {}", domain);
            return createNotFoundResponse(request);
        }
        
        // 过滤符合查询类型的IP
        List<String> matchedIps = new ArrayList<>();
        for (String ip : ips) {
            if ((type == DnsRecordType.A && ip.contains(".")) ||
                (type == DnsRecordType.AAAA && (ip.contains(":") || "::".equals(ip)))) {
                matchedIps.add(ip);
            }
        }
        
        if (matchedIps.isEmpty()) {
            logger.debug("域名 {} 在Host文件中没有 {} 类型的记录", domain, type);
            return createNotFoundResponse(request);
        }
        
        logger.info("Host文件命中: {} {} -> {}", domain, type, matchedIps);
        return createSuccessResponse(request, domain, type, matchedIps);
    }
    
    /**
     * 解析反向查询（PTR记录）
     */
    private DnsMessage resolveReverseQuery(DnsMessage request, String reverseDomain) {
        List<String> domains = reverseHostMap.get(reverseDomain);
        
        if (domains == null || domains.isEmpty()) {
            logger.debug("反向域名在Host文件中未找到: {}", reverseDomain);
            return createNotFoundResponse(request);
        }
        
        logger.info("Host文件反向查询命中: {} -> {}", reverseDomain, domains);
        return createPtrResponse(request, reverseDomain, domains);
    }
    
    /**
     * 创建成功响应
     */
    private DnsMessage createSuccessResponse(DnsMessage request, String domain, 
                                           DnsRecordType type, List<String> ips) {
        DnsMessage response = new DnsMessage();
        response.setId(request.getId());
        response.setFlags(0x8180); // QR=1, RA=1, RD=1
        
        // 添加问题部分
        response.getQuestions().addAll(request.getQuestions());
        
        // 添加答案部分
        for (String ip : ips) {
            DnsRecord record = new DnsRecord(
                domain,
                type,
                1, // IN class
                300, // 5分钟TTL
                ip
            );
            response.getAnswers().add(record);
        }
        
        return response;
    }
    
    /**
     * 创建PTR响应
     */
    private DnsMessage createPtrResponse(DnsMessage request, String reverseDomain, List<String> domains) {
        DnsMessage response = new DnsMessage();
        response.setId(request.getId());
        response.setFlags(0x8180); // QR=1, RA=1, RD=1
        
        // 添加问题部分
        response.getQuestions().addAll(request.getQuestions());
        
        // 添加答案部分
        for (String domain : domains) {
            DnsRecord record = new DnsRecord(
                reverseDomain,
                DnsRecordType.PTR,
                1, // IN class
                300, // 5分钟TTL
                domain + "."
            );
            response.getAnswers().add(record);
        }
        
        return response;
    }
    
    /**
     * 创建未找到响应
     */
    private DnsMessage createNotFoundResponse(DnsMessage request) {
        DnsMessage response = new DnsMessage();
        response.setId(request.getId());
        response.setFlags(0x8183); // QR=1, RA=1, RD=1, RCODE=3 (NXDOMAIN)
        response.getQuestions().addAll(request.getQuestions());
        return response;
    }
    
    /**
     * 检查域名是否在hosts文件中存在
     */
    public boolean containsDomain(String domain) {
        if (domain == null) {
            return false;
        }
        return hostMap.containsKey(domain.toLowerCase());
    }
    
    /**
     * 获取hosts文件中的域名数量
     */
    public int getDomainCount() {
        return hostMap.size();
    }
    
    /**
     * 获取hosts文件路径
     */
    public String getHostFileLocation() {
        return hostFilePath.toString();
    }
    
    /**
     * 获取有效条目数量
     */
    public int getValidEntryCount() {
        return validCount;
    }
    
    /**
     * 手动重新加载host文件
     */
    public void reload() {
        logger.info("手动重新加载Host文件");
        loadHostFile();
    }
    
    /**
     * 添加临时主机条目（内存中，不持久化）
     */
    public void addTemporaryEntry(String domain, String ip) {
        if (!isValidDomain(domain) || !isValidIp(ip)) {
            logger.warn("无效的主机条目: {} -> {}", domain, ip);
            return;
        }
        
        String normalizedDomain = domain.toLowerCase();
        hostMap.computeIfAbsent(normalizedDomain, k -> new ArrayList<>()).add(ip);
        
        // 更新反向映射
        String reverseDomain = getReverseLookupDomain(ip);
        if (reverseDomain != null) {
            reverseHostMap.computeIfAbsent(reverseDomain, k -> new ArrayList<>()).add(normalizedDomain);
        }
        
        logger.info("添加临时主机条目: {} -> {}", normalizedDomain, ip);
    }
    
    /**
     * 删除临时主机条目
     */
    public void removeTemporaryEntry(String domain, String ip) {
        String normalizedDomain = domain.toLowerCase();
        List<String> ips = hostMap.get(normalizedDomain);
        if (ips != null) {
            ips.remove(ip);
            if (ips.isEmpty()) {
                hostMap.remove(normalizedDomain);
            }
            
            // 更新反向映射
            String reverseDomain = getReverseLookupDomain(ip);
            if (reverseDomain != null) {
                List<String> domains = reverseHostMap.get(reverseDomain);
                if (domains != null) {
                    domains.remove(normalizedDomain);
                    if (domains.isEmpty()) {
                        reverseHostMap.remove(reverseDomain);
                    }
                }
            }
            
            logger.info("删除临时主机条目: {} -> {}", normalizedDomain, ip);
        }
    }
    
    /**
     * 获取所有主机条目（只读）
     */
    public Map<String, List<String>> getAllEntries() {
        return new HashMap<>(hostMap);
    }
    
    /**
     * 关闭资源
     */
    public void shutdown() {
        if (scheduler != null) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
}