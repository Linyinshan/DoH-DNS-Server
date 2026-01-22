package com.dns.admin;

import com.dns.config.DnsConfig;
import com.dns.resolver.HostFileResolver;
import com.dns.server.DnsHandler;
import com.dns.resolver.DomainBlocker;
import com.dns.doh.DohResolver;
import com.dns.util.LoggerUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AdminServer implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(AdminServer.class);
    
    private final int port;
    private final String adminKey;
    private final boolean enabled;
    private DatagramSocket serverSocket;
    private volatile boolean running = false;
    private final ExecutorService threadPool;
    
    // 依赖组件
    private final HostFileResolver hostResolver;
    private final DomainBlocker domainBlocker;
    private final DohResolver dohResolver;
    private final DnsConfig config;
    
    // 预定义操作列表（按部分数降序排列，优先匹配长的）
    private static final List<String> VALID_OPERATIONS = Arrays.asList(
        "add-host", "delete-host", "add-bandomain", "delete-bandomain", 
        "restart", "switchserver"
    );
    
    public AdminServer(DnsConfig config, HostFileResolver hostResolver, 
                      DomainBlocker domainBlocker, DohResolver dohResolver) {
        this.config = config;
        this.port = config.getAdminPort();
        this.adminKey = config.getAdminKey();
        this.enabled = config.isAdminEnabled();
        this.hostResolver = hostResolver;
        this.domainBlocker = domainBlocker;
        this.dohResolver = dohResolver;
        this.threadPool = Executors.newFixedThreadPool(10);
        
        logger.info("管理服务器初始化 - 端口: {}, 协议: UDP, 启用: {}", port, enabled);
        if (!adminKey.isEmpty()) {
            logger.info("管理密钥已配置: {}位", adminKey.length());
        } else {
            logger.info("使用随机生成的管理密钥");
        }
    }
    
    @Override
    public void run() {
        if (!enabled) {
            logger.info("管理功能已禁用");
            return;
        }
        
        try {
            serverSocket = new DatagramSocket(port);
            running = true;
            logger.info("管理服务器启动成功，监听UDP端口: {}", port);
            
            byte[] buffer = new byte[1024];
            
            while (running) {
                try {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    serverSocket.receive(packet);
                    threadPool.execute(new AdminHandler(packet));
                } catch (IOException e) {
                    if (running) {
                        logger.error("接收管理命令失败", e);
                    }
                }
            }
        } catch (IOException e) {
            logger.error("启动管理服务器失败", e);
        }
    }
    
    public void stop() {
        running = false;
        if (serverSocket != null) {
            serverSocket.close();
        }
        threadPool.shutdown();
        logger.info("管理服务器已停止");
    }
    
    private class AdminHandler implements Runnable {
        private final DatagramPacket packet;
        private final String clientIp;
        private final int clientPort;
        
        public AdminHandler(DatagramPacket packet) {
            this.packet = packet;
            this.clientIp = packet.getAddress().getHostAddress();
            this.clientPort = packet.getPort();
        }
        
        @Override
        public void run() {
            try {
                String command = new String(packet.getData(), 0, packet.getLength(), "UTF-8").trim();
                processCommand(command);
            } catch (Exception e) {
                logger.error("处理管理命令时发生错误", e);
                sendResponse("ERROR: 命令处理异常 - " + e.getMessage());
            }
        }
        
        private void processCommand(String command) {
            long startTime = System.currentTimeMillis();
            
            LoggerUtil.logAdminCommand(clientIp, command, "RECEIVED");
            
            try {
                CommandResult validation = validateCommand(command);
                if (!validation.success) {
                    LoggerUtil.logAdminCommand(clientIp, command, "INVALID_FORMAT", validation.message);
                    sendResponse("ERROR: " + validation.message);
                    return;
                }
                
                CommandResult result = executeCommand(validation.parsedCommand);
                
                String status = result.success ? "EXECUTED" : "EXECUTION_FAILED";
                LoggerUtil.logAdminCommand(clientIp, command, status, result.message);
                
                sendResponse(result.success ? "SUCCESS: " + result.message : "ERROR: " + result.message);
                
            } catch (Exception e) {
                String errorMsg = "命令处理异常: " + e.getMessage();
                LoggerUtil.logAdminCommand(clientIp, command, "EXCEPTION", errorMsg);
                sendResponse("ERROR: " + errorMsg);
            }
            
            long duration = System.currentTimeMillis() - startTime;
            logger.debug("管理命令处理完成，耗时: {}ms", duration);
        }
        
        private void sendResponse(String response) {
            try {
                byte[] responseData = response.getBytes("UTF-8");
                DatagramPacket responsePacket = new DatagramPacket(
                    responseData, responseData.length, 
                    packet.getAddress(), packet.getPort()
                );
                serverSocket.send(responsePacket);
            } catch (IOException e) {
                logger.error("发送管理响应失败", e);
            }
        }
        
        private CommandResult validateCommand(String command) {
            if (command == null || command.trim().isEmpty()) {
                return new CommandResult(false, "命令为空");
            }
            
            String[] parts = command.split("-");
            if (parts.length < 4) {
                return new CommandResult(false, "命令格式错误，字段数量不足");
            }
            
            // 修复：更宽松的数量检查
            if (parts.length < 2) {
                return new CommandResult(false, "命令格式错误，缺少时间部分");
            }
            String timePart = parts[0] + "-" + parts[1];
            if (!timePart.matches("\\d{4}\\.\\d{2}\\.\\d{2}-\\d{2}")) {
                return new CommandResult(false, "时间格式错误: " + timePart);
            }
            
            // 智能匹配操作类型（修复操作解析问题）
            OperationMatchResult matchResult = matchOperation(parts);
            if (!matchResult.success) {
                return new CommandResult(false, matchResult.errorMessage);
            }
            int minRequiredParts = 2 + matchResult.operationPartCount + 1; // 时间2 + 操作N + 鉴权1
            if (parts.length < minRequiredParts) {
                return new CommandResult(false, "命令格式错误，缺少必要字段");
            }
            
            // 验证鉴权MD5
            if (parts.length < matchResult.operationPartCount + 3) { // 时间2部分 + 操作部分 + 至少鉴权MD5
                return new CommandResult(false, "缺少鉴权信息");
            }
            
            // 重建不含鉴权MD5的命令部分（用于计算MD5）
            StringBuilder commandWithoutAuth = new StringBuilder();
            for (int i = 0; i < parts.length - 1; i++) {
                if (i > 0) commandWithoutAuth.append("-");
                commandWithoutAuth.append(parts[i]);
            }
            
            String receivedMd5 = parts[parts.length - 1];
            String expectedMd5 = calculateAuthMd5(commandWithoutAuth.toString());
            
            if (!receivedMd5.equals(expectedMd5)) {
                return new CommandResult(false, "鉴权失败");
            }
            
            // 构建解析后的命令对象
            ParsedCommand parsed = new ParsedCommand();
            parsed.timestamp = timePart;
            parsed.operation = matchResult.operation;
            
            // 参数从操作部分结束后开始到倒数第二
            int paramStartIndex = 2 + matchResult.operationPartCount;
            int paramCount = parts.length - 1 - paramStartIndex;
            if (paramCount > 0) {
                parsed.params = new String[paramCount];
                for (int i = 0; i < paramCount; i++) {
                    parsed.params[i] = parts[paramStartIndex + i];
                }
            } else {
                parsed.params = new String[0];
            }
            parsed.originalCommand = command;
            
            return new CommandResult(true, "验证成功", parsed);
        }
        
        /**
         * 智能匹配操作类型
         */
        private OperationMatchResult matchOperation(String[] parts) {
            // 按操作部分数降序尝试匹配（优先匹配长的操作如"add-host"）
            for (String operation : VALID_OPERATIONS) {
                String[] operationParts = operation.split("-");
                int operationPartCount = operationParts.length;
                
                // 修复：更宽松的数量检查，允许有参数
                if (parts.length >= 2 + operationPartCount + 1) { // 时间2 + 操作N + 鉴权1
                    StringBuilder candidate = new StringBuilder();
                    for (int i = 0; i < operationPartCount; i++) {
                        if (i > 0) candidate.append("-");
                        candidate.append(parts[2 + i]);
                    }
                    
                    if (operation.equals(candidate.toString())) {
                        return new OperationMatchResult(true, operation, operationPartCount, null);
                    }
                }
            }
            
            return new OperationMatchResult(false, null, 0, 
            "不支持的操作类型，可用操作: " + String.join(", ", VALID_OPERATIONS));
        }
        
        private CommandResult executeCommand(ParsedCommand command) {
            try {
                switch (command.operation) {
                    case "add-host":
                        if (command.params.length < 2) {
                            return new CommandResult(false, "参数不足，需要IP和域名");
                        }
                        return addHost(command.params[0], command.params[1]);
                        
                    case "delete-host":
                        if (command.params.length < 2) {
                            return new CommandResult(false, "参数不足，需要IP和域名");
                        }
                        return deleteHost(command.params[0], command.params[1]);
                        
                    case "add-bandomain":
                        if (command.params.length < 1) {
                            return new CommandResult(false, "参数不足，需要域名");
                        }
                        return addBanDomain(command.params[0]);
                        
                    case "delete-bandomain":
                        if (command.params.length < 1) {
                            return new CommandResult(false, "参数不足，需要域名");
                        }
                        return deleteBanDomain(command.params[0]);
                        
                    case "restart":
                        return restartServer();
                        
                    case "switchserver":
                        return switchServer();
                        
                    default:
                        return new CommandResult(false, "未知操作: " + command.operation);
                }
            } catch (Exception e) {
                return new CommandResult(false, "执行异常: " + e.getMessage());
            }
        }
        
        private CommandResult addHost(String ip, String domain) {
            try {
                hostResolver.addTemporaryEntry(domain, ip);
                return new CommandResult(true, "添加Host记录成功: " + domain + " -> " + ip);
            } catch (Exception e) {
                return new CommandResult(false, "添加Host记录失败: " + e.getMessage());
            }
        }
        
        private CommandResult deleteHost(String ip, String domain) {
            try {
                hostResolver.removeTemporaryEntry(domain, ip);
                return new CommandResult(true, "删除Host记录成功: " + domain + " -> " + ip);
            } catch (Exception e) {
                return new CommandResult(false, "删除Host记录失败: " + e.getMessage());
            }
        }
        
        private CommandResult addBanDomain(String domain) {
            try {
                domainBlocker.addTemporaryBlock(domain);
                return new CommandResult(true, "添加屏蔽域名成功: " + domain);
            } catch (Exception e) {
                return new CommandResult(false, "添加屏蔽域名失败: " + e.getMessage());
            }
        }
        
        private CommandResult deleteBanDomain(String domain) {
            try {
                domainBlocker.removeTemporaryBlock(domain);
                return new CommandResult(true, "删除屏蔽域名成功: " + domain);
            } catch (Exception e) {
                return new CommandResult(false, "删除屏蔽域名失败: " + e.getMessage());
            }
        }
        
        private CommandResult restartServer() {
            try {
                // 在实际实现中，这里应该触发服务器重启逻辑
                // 例如: Runtime.getRuntime().addShutdownHook(...) 或发送重启信号
                logger.warn("收到重启命令，实际重启逻辑需要与主服务器集成");
                return new CommandResult(true, "重启命令已接收，需要实现具体重启逻辑");
            } catch (Exception e) {
                return new CommandResult(false, "重启命令执行失败: " + e.getMessage());
            }
        }
        
        private CommandResult switchServer() {
            try {
                // 使用 DnsHandler 的静态方法确保一致性
                DnsHandler.manualSwitchToNextServer();
                String currentServer = DnsHandler.getCurrentDohServer();
                return new CommandResult(true, 
                    "切换DoH服务器成功，当前服务器: " + currentServer);
            } catch (Exception e) {
                return new CommandResult(false, "切换服务器失败: " + e.getMessage());
            }
        }
        
        private String calculateAuthMd5(String commandWithoutAuth) {
            try {
                String data = commandWithoutAuth + "-" + adminKey;
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] digest = md.digest(data.getBytes("UTF-8"));
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) {
                    sb.append(String.format("%02x", b));
                }
                return sb.toString();
            } catch (Exception e) {
                throw new RuntimeException("MD5计算失败", e);
            }
        }
    }
    
    // 内部辅助类
    private static class CommandResult {
        boolean success;
        String message;
        ParsedCommand parsedCommand;
        
        CommandResult(boolean success, String message) {
            this(success, message, null);
        }
        
        CommandResult(boolean success, String message, ParsedCommand parsed) {
            this.success = success;
            this.message = message;
            this.parsedCommand = parsed;
        }
    }
    
    private static class ParsedCommand {
        String timestamp;
        String operation;
        String[] params;
        String originalCommand;
    }
    
    private static class OperationMatchResult {
        boolean success;
        String operation;
        int operationPartCount;
        String errorMessage;
        
        OperationMatchResult(boolean success, String operation, int operationPartCount, String errorMessage) {
            this.success = success;
            this.operation = operation;
            this.operationPartCount = operationPartCount;
            this.errorMessage = errorMessage;
        }
    }
}