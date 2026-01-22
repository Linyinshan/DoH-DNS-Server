package com.dns.resolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 域名屏蔽器 - 支持自定义配置文件路径
 * 从指定文件加载被屏蔽的域名列表
 */
public class DomainBlocker {
    private static final Logger logger = LoggerFactory.getLogger(DomainBlocker.class);
    
    private final String blockFile;
    private final Set<String> blockedDomains;
    private final ScheduledExecutorService reloadScheduler;
    private volatile long lastModified;
    private volatile boolean enabled = true;
    
    public DomainBlocker() {
        this("BanDomain.txt");
    }
    
    public DomainBlocker(String blockFile) {
        this.blockFile = getBlockFilePath(blockFile);
        this.blockedDomains = Collections.synchronizedSet(new HashSet<>());
        this.reloadScheduler = Executors.newScheduledThreadPool(1);
        this.lastModified = 0;
        
        logger.info("初始化域名屏蔽器，使用文件: {}", this.blockFile);
        loadBlockedDomains();
        startAutoReload();
    }
    
    /**
     * 获取屏蔽文件路径（支持自定义路径和默认路径）
     */
    private String getBlockFilePath(String customPath) {
        try {
            if (customPath != null && !customPath.trim().isEmpty()) {
                Path custom = Paths.get(customPath);
                if (Files.exists(custom)) {
                    logger.info("使用自定义屏蔽文件: {}", custom.toAbsolutePath());
                    return customPath;
                } else {
                    logger.warn("自定义屏蔽文件不存在: {}, 尝试使用默认文件名", customPath);
                }
            }
            
            // 使用默认路径（jar所在目录）
            String jarDir = System.getProperty("user.dir");
            Path defaultPath = Paths.get(jarDir, "BanDomain.txt");
            
            if (Files.exists(defaultPath)) {
                logger.info("使用默认屏蔽文件: {}", defaultPath.toAbsolutePath());
                return defaultPath.toString();
            } else {
                // 创建默认空文件
                logger.info("创建默认屏蔽文件: {}", defaultPath.toAbsolutePath());
                Files.createFile(defaultPath);
                return defaultPath.toString();
            }
            
        } catch (Exception e) {
            logger.warn("无法获取 jar 目录，使用当前目录: {}", e.getMessage());
            return "BanDomain.txt";
        }
    }
    
    /**
     * 加载被屏蔽的域名列表
     */
    private void loadBlockedDomains() {
        try {
            Path path = Paths.get(blockFile);
            if (!Files.exists(path)) {
                logger.info("屏蔽文件不存在: {}, 创建空文件", blockFile);
                try {
                    Files.createFile(path);
                    // 添加示例内容
                    List<String> exampleLines = Arrays.asList(
                        "# 域名屏蔽列表",
                        "# 每行一个域名，支持通配符格式（如 *.example.com）",
                        "# 注释以#开头",
                        "",
                        "# 示例：",
                        "# .bad-domain.com",
                        "# .malicious-site.org",
                        "# ad.example.com"
                    );
                    Files.write(path, exampleLines);
                    logger.info("已创建示例屏蔽文件: {}", blockFile);
                } catch (IOException e) {
                    logger.error("创建屏蔽文件失败: {}", e.getMessage());
                }
                return;
            }
            
            List<String> lines = Files.readAllLines(path);
            Set<String> newDomains = new HashSet<>();
            int loadedCount = 0;
            
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                
                // 跳过空行和注释
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                // 规范化域名
                String domain = normalizeDomain(line);
                if (domain != null && !domain.isEmpty()) {
                    newDomains.add(domain);
                    loadedCount++;
                    if (logger.isDebugEnabled()) {
                        logger.debug("加载屏蔽域名: {} (原始: {})", domain, line);
                    }
                } else {
                    logger.warn("第 {} 行格式无效: {}", i + 1, line);
                }
            }
            
            // 原子性更新域名集合
            blockedDomains.clear();
            blockedDomains.addAll(newDomains);
            lastModified = Files.getLastModifiedTime(path).toMillis();
            
            logger.info("从 {} 加载了 {} 个屏蔽域名", blockFile, loadedCount);
            
            if (logger.isDebugEnabled() && !blockedDomains.isEmpty()) {
                logger.debug("当前屏蔽域名列表: {}", blockedDomains);
            }
            
        } catch (IOException e) {
            logger.error("读取屏蔽文件失败: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("加载屏蔽域名时发生意外错误", e);
        }
    }
    
    /**
     * 启动自动重新加载
     */
    private void startAutoReload() {
        // 每30秒检查一次文件变化
        reloadScheduler.scheduleAtFixedRate(() -> {
            try {
                if (checkFileUpdate()) {
                    logger.info("屏蔽文件已修改，重新加载...");
                    loadBlockedDomains();
                }
            } catch (Exception e) {
                logger.error("检查屏蔽文件变化时出错: {}", e.getMessage());
            }
        }, 30, 30, TimeUnit.SECONDS);
        
        logger.debug("屏蔽文件自动重载已启动（间隔：30秒）");
    }
    
    /**
     * 检查文件是否需要更新
     */
    private boolean checkFileUpdate() {
        try {
            Path path = Paths.get(blockFile);
            if (Files.exists(path)) {
                long currentModified = Files.getLastModifiedTime(path).toMillis();
                return currentModified > lastModified;
            }
        } catch (Exception e) {
            logger.debug("检查文件修改时间失败: {}", e.getMessage());
        }
        return false;
    }
    
    /**
     * 规范化域名（转换为小写，移除前后空格等）
     */
    private String normalizeDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return null;
        }
        
        domain = domain.trim().toLowerCase();
        
        // 移除可能的协议前缀
        if (domain.startsWith("http://")) {
            domain = domain.substring(7);
        } else if (domain.startsWith("https://")) {
            domain = domain.substring(8);
        }
        
        // 移除路径部分
        int slashIndex = domain.indexOf('/');
        if (slashIndex != -1) {
            domain = domain.substring(0, slashIndex);
        }
        
        // 移除端口号
        int colonIndex = domain.indexOf(':');
        if (colonIndex != -1) {
            domain = domain.substring(0, colonIndex);
        }
        
        // 处理通配符格式
        if (domain.startsWith("*.")) {
            domain = domain.substring(1); // 将 "*.example.com" 转换为 ".example.com"
        }
        
        // 确保域名以点开头，便于子域名匹配
        if (!domain.startsWith(".")) {
            domain = "." + domain;
        }
        
        // 验证域名格式
        if (!isValidDomainPattern(domain)) {
            logger.warn("无效的域名格式: {}", domain);
            return null;
        }
        
        return domain;
    }
    
    /**
     * 验证域名模式格式
     */
    private boolean isValidDomainPattern(String domain) {
        if (domain == null || domain.length() < 2) {
            return false;
        }
        
        // 通配符格式检查（如 ".example.com"）
        if (domain.startsWith(".")) {
            String withoutDot = domain.substring(1);
            if (withoutDot.isEmpty()) {
                return false;
            }
            // 验证剩余部分是否是有效域名格式
            return withoutDot.matches("^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$");
        }
        
        return false;
    }
    
    /**
     * 检查域名是否被屏蔽
     */
    public boolean isBlocked(String domain) {
        if (!enabled) {
            return false;
        }
        
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        
        String normalizedDomain = "." + domain.toLowerCase().trim();
        
        for (String blockedDomain : blockedDomains) {
            if (normalizedDomain.endsWith(blockedDomain)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("域名 {} 匹配屏蔽模式: {}", domain, blockedDomain);
                }
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 添加临时屏蔽域名（不保存到文件）
     */
    public void addTemporaryBlock(String domain) {
        if (domain == null || domain.isEmpty()) {
            return;
        }
        
        String normalized = normalizeDomain(domain);
        if (normalized != null && !normalized.isEmpty()) {
            blockedDomains.add(normalized);
            logger.info("已临时屏蔽域名: {} -> {}", domain, normalized);
        }
    }
    
    /**
     * 移除临时屏蔽域名
     */
    public void removeTemporaryBlock(String domain) {
        if (domain == null || domain.isEmpty()) {
            return;
        }
        
        String normalized = normalizeDomain(domain);
        if (normalized != null && blockedDomains.remove(normalized)) {
            logger.info("已移除临时屏蔽: {}", domain);
        }
    }
    
    /**
     * 永久添加到屏蔽文件
     */
    public boolean addPermanentBlock(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        
        String normalized = normalizeDomain(domain);
        if (normalized == null || normalized.isEmpty()) {
            return false;
        }
        
        try {
            Path path = Paths.get(blockFile);
            List<String> lines = new ArrayList<>();
            
            if (Files.exists(path)) {
                lines = Files.readAllLines(path);
            }
            
            // 检查是否已存在
            String domainToAdd = normalized.substring(1); // 移除开头的点
            if (normalized.startsWith(".")) {
                domainToAdd = "*" + normalized; // 转换为通配符格式
            }
            
            for (String line : lines) {
                if (line.trim().equals(domainToAdd) || line.trim().equals(normalized)) {
                    logger.info("域名已在屏蔽列表中: {}", domain);
                    return true;
                }
            }
            
            // 添加到文件
            lines.add(domainToAdd);
            Files.write(path, lines);
            
            // 更新内存中的列表
            blockedDomains.add(normalized);
            lastModified = Files.getLastModifiedTime(path).toMillis();
            
            logger.info("已永久屏蔽域名: {} -> {}", domain, domainToAdd);
            return true;
            
        } catch (IOException e) {
            logger.error("添加永久屏蔽失败: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 从屏蔽文件中移除域名
     */
    public boolean removePermanentBlock(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        
        String normalized = normalizeDomain(domain);
        if (normalized == null || normalized.isEmpty()) {
            return false;
        }
        
        try {
            Path path = Paths.get(blockFile);
            if (!Files.exists(path)) {
                return false;
            }
            
            List<String> lines = Files.readAllLines(path);
            List<String> newLines = new ArrayList<>();
            String domainToRemove = normalized.substring(1); // 移除开头的点
            if (normalized.startsWith(".")) {
                domainToRemove = "*" + normalized; // 转换为通配符格式
            }
            
            boolean removed = false;
            for (String line : lines) {
                String trimmed = line.trim();
                if (!trimmed.equals(domainToRemove) && !trimmed.equals(normalized) && !trimmed.isEmpty()) {
                    newLines.add(line);
                } else {
                    removed = true;
                }
            }
            
            if (removed) {
                Files.write(path, newLines);
                blockedDomains.remove(normalized);
                lastModified = Files.getLastModifiedTime(path).toMillis();
                logger.info("已从屏蔽列表移除域名: {}", domain);
                return true;
            }
            
            return false;
            
        } catch (IOException e) {
            logger.error("移除永久屏蔽失败: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 启用/禁用屏蔽功能
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        logger.info("域名屏蔽功能: {}", enabled ? "已启用" : "已禁用");
    }
    
    /**
     * 检查屏蔽功能是否启用
     */
    public boolean isEnabled() {
        return enabled;
    }
    
    /**
     * 获取被屏蔽的域名数量
     */
    public int getBlockedDomainCount() {
        return blockedDomains.size();
    }
    
    /**
     * 获取被屏蔽的域名列表（只读）
     */
    public List<String> getBlockedDomains() {
        List<String> domains = new ArrayList<>();
        for (String blocked : blockedDomains) {
            domains.add(blocked.substring(1)); // 移除开头的点
        }
        return Collections.unmodifiableList(domains);
    }
    
    /**
     * 获取屏蔽文件路径
     */
    public String getBlockFile() {
        return blockFile;
    }
    
    /**
     * 获取屏蔽文件最后修改时间
     */
    public long getLastModified() {
        return lastModified;
    }
    
    /**
     * 检查特定域名是否在屏蔽列表中
     */
    public boolean containsDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        
        String normalized = "." + domain.toLowerCase().trim();
        for (String blocked : blockedDomains) {
            if (normalized.endsWith(blocked)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 获取匹配的屏蔽模式
     */
    public String getMatchingPattern(String domain) {
        if (domain == null || domain.isEmpty()) {
            return null;
        }
        
        String normalized = "." + domain.toLowerCase().trim();
        for (String blocked : blockedDomains) {
            if (normalized.endsWith(blocked)) {
                return blocked;
            }
        }
        return null;
    }
    
    /**
     * 手动重新加载屏蔽列表
     */
    public void reload() {
        logger.info("手动重新加载屏蔽列表");
        loadBlockedDomains();
    }
    
    /**
     * 清空所有屏蔽规则（临时）
     */
    public void clearAll() {
        blockedDomains.clear();
        logger.info("已清空所有屏蔽规则（临时）");
    }
    
    /**
     * 导出当前屏蔽列表到文件
     */
    public boolean exportToFile(String exportPath) {
        try {
            Path path = Paths.get(exportPath);
            List<String> lines = new ArrayList<>();
            lines.add("# 导出的域名屏蔽列表");
            lines.add("# 导出时间: " + new Date());
            lines.add("");
            
            for (String blocked : getBlockedDomains()) {
                lines.add(blocked);
            }
            
            Files.write(path, lines);
            logger.info("已导出 {} 个屏蔽域名到: {}", getBlockedDomainCount(), exportPath);
            return true;
            
        } catch (IOException e) {
            logger.error("导出屏蔽列表失败: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 关闭资源
     */
    public void shutdown() {
        if (reloadScheduler != null) {
            reloadScheduler.shutdown();
            try {
                if (!reloadScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    reloadScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                reloadScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        logger.info("域名屏蔽器已关闭");
    }
    
    /**
     * 获取统计信息
     */
    public String getStatistics() {
        return String.format(
            "DomainBlocker统计 - 启用: %s, 屏蔽域名数: %d, 文件: %s, 最后修改: %tF %tT",
            enabled ? "是" : "否", 
            getBlockedDomainCount(), 
            blockFile,
            new Date(lastModified), 
            new Date(lastModified)
        );
    }
}