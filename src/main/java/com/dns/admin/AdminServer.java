package com.dns.admin;

import com.dns.config.DnsConfig;
import com.dns.resolver.HostFileResolver;
import com.dns.resolver.DomainBlocker;
import com.dns.doh.DohResolver;
import com.dns.util.LoggerUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AdminServer implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(AdminServer.class);
    
    private final int port;
    private final String adminKey;
    private final boolean enabled;
    private ServerSocket serverSocket;
    private volatile boolean running = false;
    private final ExecutorService threadPool;
    
    // 依赖组件
    private final HostFileResolver hostResolver;
    private final DomainBlocker domainBlocker;
    private final DohResolver dohResolver;
    private final DnsConfig config;
    
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
        
        logger.info("管理服务器初始化 - 端口: {}, 启用: {}", port, enabled);
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
            serverSocket = new ServerSocket(port);
            running = true;
            logger.info("管理服务器启动成功，监听端口: {}", port);
            
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    threadPool.execute(new AdminHandler(clientSocket));
                } catch (IOException e) {
                    if (running) {
                        logger.error("接受管理连接失败", e);
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
            try {
                serverSocket.close();
            } catch (IOException e) {
                logger.error("关闭管理服务器失败", e);
            }
        }
        threadPool.shutdown();
        logger.info("管理服务器已停止");
    }
    
    private class AdminHandler implements Runnable {
        private final Socket clientSocket;
        private final String clientIp;
        
        public AdminHandler(Socket socket) {
            this.clientSocket = socket;
            this.clientIp = socket.getInetAddress().getHostAddress();
        }
        
        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true)) {
                
                String command = reader.readLine();
                if (command != null) {
                    processCommand(command, writer);
                }
            } catch (IOException e) {
                logger.error("处理管理命令时发生IO错误", e);
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    logger.debug("关闭客户端连接时发生错误", e);
                }
            }
        }
        
        private void processCommand(String command, PrintWriter writer) {
            long startTime = System.currentTimeMillis();
            
            // 记录接收到的命令
            LoggerUtil.logAdminCommand(clientIp, command, "RECEIVED");
            
            try {
                // 验证命令格式
                CommandResult validation = validateCommand(command);
                if (!validation.success) {
                    LoggerUtil.logAdminCommand(clientIp, command, "INVALID_FORMAT", validation.message);
                    writer.println("ERROR: " + validation.message);
                    return;
                }
                
                // 执行命令
                CommandResult result = executeCommand(validation.parsedCommand);
                
                // 记录执行结果
                String status = result.success ? "EXECUTED" : "EXECUTION_FAILED";
                LoggerUtil.logAdminCommand(clientIp, command, status, result.message);
                
                writer.println(result.success ? "SUCCESS: " + result.message : "ERROR: " + result.message);
                
            } catch (Exception e) {
                String errorMsg = "命令处理异常: " + e.getMessage();
                LoggerUtil.logAdminCommand(clientIp, command, "EXCEPTION", errorMsg);
                writer.println("ERROR: " + errorMsg);
            }
            
            long duration = System.currentTimeMillis() - startTime;
            logger.debug("管理命令处理完成，耗时: {}ms", duration);
        }
        
        private CommandResult validateCommand(String command) {
            if (command == null || command.trim().isEmpty()) {
                return new CommandResult(false, "命令为空");
            }
            
            String[] parts = command.split("-");
            if (parts.length < 4) {
                return new CommandResult(false, "命令格式错误，字段数量不足");
            }
            
            // 验证时间格式 (yyyy.mm.dd-hh)
            if (!parts[0].matches("\\d{4}\\.\\d{2}\\.\\d{2}-\\d{2}")) {
                return new CommandResult(false, "时间格式错误");
            }
            
            // 验证操作类型
            String operation = parts[2];
            if (!isValidOperation(operation)) {
                return new CommandResult(false, "不支持的操作类型: " + operation);
            }
            
            // 验证鉴权MD5
            if (parts.length < 3) {
                return new CommandResult(false, "缺少鉴权信息");
            }
            
            String receivedMd5 = parts[parts.length - 1];
            String expectedMd5 = calculateAuthMd5(command.substring(0, command.lastIndexOf("-")));
            
            if (!receivedMd5.equals(expectedMd5)) {
                return new CommandResult(false, "鉴权失败");
            }
            
            ParsedCommand parsed = new ParsedCommand();
            parsed.timestamp = parts[0];
            parsed.operation = operation;
            parsed.params = java.util.Arrays.copyOfRange(parts, 3, parts.length - 1);
            parsed.originalCommand = command;
            
            return new CommandResult(true, "验证成功", parsed);
        }
        
        private CommandResult executeCommand(ParsedCommand command) {
            try {
                switch (command.operation) {
                    case "add-host":
                        return addHost(command.params);
                    case "delete-host":
                        return deleteHost(command.params);
                    case "add-bandomain":
                        return addBanDomain(command.params);
                    case "delete-bandomain":
                        return deleteBanDomain(command.params);
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
        
        private CommandResult addHost(String[] params) {
            if (params.length < 2) {
                return new CommandResult(false, "参数不足，需要IP和域名");
            }
            String ip = params[0];
            String domain = params[1];
            
            hostResolver.addTemporaryEntry(domain, ip);
            return new CommandResult(true, "添加Host记录成功: " + domain + " -> " + ip);
        }
        
        private CommandResult deleteHost(String[] params) {
            if (params.length < 2) {
                return new CommandResult(false, "参数不足，需要IP和域名");
            }
            String ip = params[0];
            String domain = params[1];
            
            hostResolver.removeTemporaryEntry(domain, ip);
            return new CommandResult(true, "删除Host记录成功: " + domain + " -> " + ip);
        }
        
        private CommandResult addBanDomain(String[] params) {
            if (params.length < 1) {
                return new CommandResult(false, "参数不足，需要域名");
            }
            String domain = params[0];
            
            domainBlocker.addTemporaryBlock(domain);
            return new CommandResult(true, "添加屏蔽域名成功: " + domain);
        }
        
        private CommandResult deleteBanDomain(String[] params) {
            if (params.length < 1) {
                return new CommandResult(false, "参数不足，需要域名");
            }
            String domain = params[0];
            
            domainBlocker.removeTemporaryBlock(domain);
            return new CommandResult(true, "删除屏蔽域名成功: " + domain);
        }
        
        private CommandResult restartServer() {
            // 在实际实现中，这里应该触发服务器重启逻辑
            logger.warn("收到重启命令，实际重启逻辑需要与主服务器集成");
            return new CommandResult(true, "重启命令已接收");
        }
        
        private CommandResult switchServer() {
            if (dohResolver != null) {
                dohResolver.switchToNextServer();
                return new CommandResult(true, "切换DoH服务器成功");
            }
            return new CommandResult(false, "DoH解析器不可用");
        }
        
        private boolean isValidOperation(String operation) {
            return java.util.Arrays.asList("add-host", "delete-host", "add-bandomain", 
                                         "delete-bandomain", "restart", "switchserver").contains(operation);
        }
        
        private String calculateAuthMd5(String commandWithoutAuth) {
            try {
                String data = commandWithoutAuth + "-" + adminKey;
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] digest = md.digest(data.getBytes());
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
    
    // 内部类定义
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
}