package com.dns.server;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 管理DNS解析的共享上下文状态（服务器列表、统计信息等）
 */
public class DnsResolutionContext {
    // 添加单例模式支持
    private static volatile DnsResolutionContext instance;
    
    private final CopyOnWriteArrayList<String> dohServerList = new CopyOnWriteArrayList<>();
    private volatile int currentServerIndex = 0;
    private volatile boolean autoSwitchEnabled = true;
    private volatile int switchThreshold = 20;
    
    // 统计信息
    private final AtomicLong totalQueries = new AtomicLong(0);
    private final AtomicLong successfulQueries = new AtomicLong(0);
    private final AtomicLong failedQueries = new AtomicLong(0);
    private final AtomicLong hostFileHits = new AtomicLong(0);
    private final AtomicLong ptrHits = new AtomicLong(0);
    private final AtomicLong dohHits = new AtomicLong(0);
    private final AtomicLong blockedQueries = new AtomicLong(0);
    private final AtomicLong dohQueryCount = new AtomicLong(0);
    private final AtomicLong duplicateQueries = new AtomicLong(0);
    private final AtomicLong configBasedSwitches = new AtomicLong(0);
    
    private volatile long lastSwitchQueryCount = 0;
    private volatile String currentDohServer = "UNKNOWN";
    
    // 私有构造函数
    private DnsResolutionContext() {}
    
    // 单例获取方法
    public static DnsResolutionContext getInstance() {
        if (instance == null) {
            synchronized (DnsResolutionContext.class) {
                if (instance == null) {
                    instance = new DnsResolutionContext();
                }
            }
        }
        return instance;
    }
    
    // 添加getDohQueryCount方法
    public long getDohQueryCount() {
        return dohQueryCount.get();
    }
    
    // 添加getLastSwitchQueryCount方法
    public long getLastSwitchQueryCount() {
        return lastSwitchQueryCount;
    }
    
    // 添加getSwitchThreshold方法
    public int getSwitchThreshold() {
        return switchThreshold;
    }
    
    // 添加所有统计信息的getter方法
    public long getTotalQueries() {
        return totalQueries.get();
    }
    
    public long getSuccessfulQueries() {
        return successfulQueries.get();
    }
    
    public long getFailedQueries() {
        return failedQueries.get();
    }
    
    public long getHostFileHits() {
        return hostFileHits.get();
    }
    
    public long getPtrHits() {
        return ptrHits.get();
    }
    
    public long getDohHits() {
        return dohHits.get();
    }
    
    public long getBlockedQueries() {
        return blockedQueries.get();
    }
    
    public long getDuplicateQueries() {
        return duplicateQueries.get();
    }
    
    public long getConfigBasedSwitches() {
        return configBasedSwitches.get();
    }
    
    // 添加getCurrentDohServer方法
    public String getCurrentDohServer() {
        return currentDohServer;
    }
    
    // 添加getter for autoSwitchEnabled
    public boolean isAutoSwitchEnabled() {
        return autoSwitchEnabled;
    }
    
    // 添加getter for dohServerList
    public List<String> getDohServerList() {
        return new ArrayList<>(dohServerList);
    }
    
    public void initializeServerList(List<String> servers, boolean autoSwitch) {
        dohServerList.clear();
        dohServerList.addAll(servers);
        this.autoSwitchEnabled = autoSwitch;
        currentServerIndex = 0;
        updateCurrentServer();
    }
    
    public synchronized void switchToNextServer(boolean isErrorSwitch) {
        if (dohServerList.size() <= 1) {
            return;
        }
        
        String oldServer = currentDohServer;
        currentServerIndex = (currentServerIndex + 1) % dohServerList.size();
        updateCurrentServer();
        
        if (isErrorSwitch) {
            configBasedSwitches.incrementAndGet();
        }
        
        lastSwitchQueryCount = dohQueryCount.get();
    }
    
    private void updateCurrentServer() {
        if (dohServerList.isEmpty()) {
            currentDohServer = "UNKNOWN";
            return;
        }
        currentDohServer = dohServerList.get(currentServerIndex);
    }
    
    // 统计方法
    public void incrementTotalQueries() { totalQueries.incrementAndGet(); }
    public void incrementSuccessfulQueries() { successfulQueries.incrementAndGet(); }
    public void incrementFailedQueries() { failedQueries.incrementAndGet(); }
    public void incrementHostFileHits() { hostFileHits.incrementAndGet(); }
    public void incrementPtrHits() { ptrHits.incrementAndGet(); }
    public void incrementDohHits() { dohHits.incrementAndGet(); }
    public void incrementBlockedQueries() { blockedQueries.incrementAndGet(); }
    public void incrementDohQueryCount() { dohQueryCount.incrementAndGet(); }
    public void incrementDuplicateQueries() { duplicateQueries.incrementAndGet(); }
    
    public String getDetailedStatistics() {
        return String.format(
            "Total: %d, Success: %d, Failed: %d, Duplicate: %d, Blocked: %d, " +
            "HostFile: %d, PTR: %d, DoH: %d, DoHQueryCount: %d, ConfigSwitches: %d, " +
            "AutoSwitch: %s, Servers: %d, Current: %s",
            totalQueries.get(), successfulQueries.get(), failedQueries.get(),
            duplicateQueries.get(), blockedQueries.get(),
            hostFileHits.get(), ptrHits.get(), dohHits.get(),
            dohQueryCount.get(), configBasedSwitches.get(),
            autoSwitchEnabled ? "ON" : "OFF", dohServerList.size(), currentDohServer
        );
    }
    
    public void resetStatistics() {
        totalQueries.set(0);
        successfulQueries.set(0);
        failedQueries.set(0);
        hostFileHits.set(0);
        ptrHits.set(0);
        dohHits.set(0);
        blockedQueries.set(0);
        dohQueryCount.set(0);
        duplicateQueries.set(0);
        configBasedSwitches.set(0);
        lastSwitchQueryCount = 0;
    }
}