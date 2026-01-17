package com.dns.server;

import com.dns.dns.*;
import com.dns.util.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class DnsClient {
    private static final Logger logger = LoggerFactory.getLogger(DnsClient.class);
    
    public static DnsMessage decodeDnsMessage(byte[] data) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            
            // 验证数据长度
            if (data.length < 12) {
                throw new IllegalArgumentException("DNS报文过短：" + data.length + " 字节"); // 修复：使用字符串拼接替代格式化
            }
            
            // 读取头部
            int id = buffer.getShort() & 0xFFFF;
            int flags = buffer.getShort() & 0xFFFF;
            int questionCount = buffer.getShort() & 0xFFFF;
            int answerCount = buffer.getShort() & 0xFFFF;
            int authorityCount = buffer.getShort() & 0xFFFF;
            int additionalCount = buffer.getShort() & 0xFFFF;
            
            DnsMessage message = new DnsMessage(id, flags);
            
            // 验证问题数量
            if (questionCount < 0 || questionCount > 10) { // 合理限制
                throw new IllegalArgumentException("无效的问题数量：" + questionCount); // 修复：使用字符串拼接
            }
            
            // 读取问题部分
            for (int i = 0; i < questionCount; i++) {
                try {
                    String name = ByteUtils.readDomainName(buffer);
                    
                    // 验证名称有效性
                    if (name == null || name.isEmpty()) {
                        logger.warn("问题部分存在空的域名");
                        continue;
                    }
                    
                    // 检查是否有足够字节读取类型和类
                    if (buffer.remaining() < 4) {
                        throw new BufferUnderflowException();
                    }
                    
                    int type = buffer.getShort() & 0xFFFF;
                    DnsRecordType recordType = DnsRecordType.fromValue(type);
                    if (recordType == null) {
                        logger.warn("未知的DNS记录类型：" + type); // 修复：使用字符串拼接
                        recordType = DnsRecordType.A; // 默认值
                    }
                    int clazz = buffer.getShort() & 0xFFFF;
                    DnsQuestion question = new DnsQuestion(name, recordType, clazz);
                    message.addQuestion(question);
                    
                } catch (BufferUnderflowException e) {
                    logger.warn("解析问题记录{}时缓冲区不足", i);
                    throw e;
                } catch (Exception e) {
                    logger.warn("解析问题记录{}时出错：{}", i, e.getMessage());
                    // 继续处理其他问题（如果有）
                }
            }
            
            // 读取答案部分（如果存在）
            if (answerCount > 0) {
                for (int i = 0; i < answerCount; i++) {
                    try {
                        if (buffer.remaining() < 1) {
                            logger.debug("应答部分数据不足");
                            break;
                        }
                        
                        String name = ByteUtils.readDomainName(buffer);
                        
                        if (buffer.remaining() < 10) {
                            throw new BufferUnderflowException();
                        }
                        
                        int type = buffer.getShort() & 0xFFFF;
                        int clazz = buffer.getShort() & 0xFFFF;
                        long ttl = buffer.getInt() & 0xFFFFFFFFL;
                        int dataLength = buffer.getShort() & 0xFFFF;
                        
                        if (buffer.remaining() < dataLength) {
                            throw new BufferUnderflowException();
                        }
                        
                        DnsRecordType recordType = DnsRecordType.fromValue(type);
                        String recordData = readRecordData(buffer, recordType, dataLength);
                        
                        DnsRecord record = new DnsRecord(name, recordType, clazz, ttl, recordData);
                        message.addAnswer(record);
                        
                    } catch (BufferUnderflowException e) {
                        logger.warn("读取应答记录{}时缓冲区不足", i);
                        break;
                    } catch (Exception e) {
                        logger.warn("解析应答记录{}时出错：{}", i, e.getMessage());
                    }
                }
            }
            
            // 跳过权限和附加部分（简化处理）
            skipSection(buffer, authorityCount);
            skipSection(buffer, additionalCount);
            
            return message;
            
        } catch (Exception e) {
            logger.error("DNS报文解析失败：{}", e.getMessage());
            throw new RuntimeException("DNS解码错误", e);
        }
    }
    
    private static void skipSection(ByteBuffer buffer, int count) {
        for (int i = 0; i < count && buffer.remaining() > 0; i++) {
            try {
                // 跳过域名
                ByteUtils.skipDomainName(buffer);
                
                if (buffer.remaining() < 10) {
                    break;
                }
                
                // 跳过类型、类、TTL
                buffer.position(buffer.position() + 8);
                
                // 跳过数据长度和数据
                int dataLength = buffer.getShort() & 0xFFFF;
                if (buffer.remaining() < dataLength) {
                    break;
                }
                buffer.position(buffer.position() + dataLength);
                
            } catch (Exception e) {
                logger.debug("跳过记录段{}时出错：{}", i, e.getMessage());
                break;
            }
        }
    }
    
    public static byte[] encodeDnsMessage(DnsMessage message) {
        try {
            // 计算消息大小
            int size = 12; // 头部大小
            
            for (DnsQuestion question : message.getQuestions()) {
                size += calculateDomainNameLength(question.getName()) + 4; // 域名长度 + 类型 + 类
            }
            
            for (DnsRecord record : message.getAnswers()) {
                size += calculateDomainNameLength(record.getName()) + 10; // 域名 + 类型 + 类 + TTL + 数据长度
                size += getRecordDataLength(record);
            }
            
            ByteBuffer buffer = ByteBuffer.allocate(size);
            
            // 写入头部
            ByteUtils.writeUnsignedShort(buffer, message.getId());
            ByteUtils.writeUnsignedShort(buffer, message.getFlags());
            ByteUtils.writeUnsignedShort(buffer, message.getQuestions().size());
            ByteUtils.writeUnsignedShort(buffer, message.getAnswers().size());
            ByteUtils.writeUnsignedShort(buffer, 0); // 权限计数
            ByteUtils.writeUnsignedShort(buffer, 0); // 附加计数
            
            // 写入问题部分
            for (DnsQuestion question : message.getQuestions()) {
                ByteUtils.writeDomainName(buffer, question.getName());
                ByteUtils.writeUnsignedShort(buffer, question.getType().getValue());
                ByteUtils.writeUnsignedShort(buffer, question.getClazz());
            }
            
            // 写入应答部分
            for (DnsRecord record : message.getAnswers()) {
                ByteUtils.writeDomainName(buffer, record.getName());
                ByteUtils.writeUnsignedShort(buffer, record.getType().getValue());
                ByteUtils.writeUnsignedShort(buffer, record.getClazz());
                buffer.putInt((int) record.getTtl());
                
                byte[] recordDataBytes = getRecordDataBytes(record);
                ByteUtils.writeUnsignedShort(buffer, recordDataBytes.length);
                buffer.put(recordDataBytes);
            }
            
            return buffer.array();
            
        } catch (Exception e) {
            logger.error("DNS报文编码失败：{}", e.getMessage());
            throw new RuntimeException("DNS编码错误", e);
        }
    }
    
    private static String readRecordData(ByteBuffer buffer, DnsRecordType type, int length) {
        try {
            switch (type) {
                case A:
                    if (length != 4) {
                        throw new IllegalArgumentException("无效的A记录长度：" + length); // 修复：使用字符串拼接
                    }
                    byte[] ipv4 = new byte[4];
                    buffer.get(ipv4);
                    return String.format("%d.%d.%d.%d", 
                        ipv4[0] & 0xFF, ipv4[1] & 0xFF, ipv4[2] & 0xFF, ipv4[3] & 0xFF);
                        
                case AAAA:
                    if (length != 16) {
                        throw new IllegalArgumentException("无效的AAAA记录长度：" + length); // 修复：使用字符串拼接
                    }
                    byte[] ipv6 = new byte[16];
                    buffer.get(ipv6);
                    StringBuilder ipv6Str = new StringBuilder();
                    for (int i = 0; i < 16; i += 2) {
                        if (i > 0) ipv6Str.append(":");
                        int segment = ((ipv6[i] & 0xFF) << 8) | (ipv6[i+1] & 0xFF);
                        ipv6Str.append(Integer.toHexString(segment));
                    }
                    return ipv6Str.toString();
                    
                case CNAME:
						logger.debug("正在解析CNAME记录，长度：{}", length);
					try {
						String cname = ByteUtils.readDomainName(buffer);
						logger.debug("解析到CNAME记录：{}", cname);
						return cname;
					} catch (Exception e) {
						logger.warn("CNAME记录解析失败，尝试直接读取字节数据");
						// 如果域名解析失败，尝试直接读取原始字节
						byte[] cnameBytes = new byte[length];
						buffer.get(cnameBytes);
						return new String(cnameBytes, StandardCharsets.US_ASCII);
					}
                case NS:
                case PTR:
                    return ByteUtils.readDomainName(buffer);
                    
                default:
                    byte[] dataBytes = new byte[length];
                    buffer.get(dataBytes);
                    return new String(dataBytes);
            }
        } catch (Exception e) {
            logger.warn("解析记录数据时出错（类型：{}）：{}", type, e.getMessage());
            // 跳过数据
            if (buffer.remaining() >= length) {
                buffer.position(buffer.position() + length);
            }
            return "";
        }
    }
    
    private static byte[] getRecordDataBytes(DnsRecord record) {
        try {
            switch (record.getType()) {
                case A:
                    return ByteUtils.ipv4ToBytes(record.getData());
                    
                case AAAA:
                    return ByteUtils.ipv6ToBytes(record.getData());
                    
                case CNAME:
					logger.debug("编码CNAME记录：{}", record.getData());
					ByteBuffer cnameBuffer = ByteBuffer.allocate(record.getData().length() + 2);
					ByteUtils.writeDomainName(cnameBuffer, record.getData());
					byte[] cnameResult = new byte[cnameBuffer.position()];
					cnameBuffer.flip();
					cnameBuffer.get(cnameResult);
					return cnameResult;
                case NS:
                case PTR:
                    ByteBuffer nameBuffer = ByteBuffer.allocate(record.getData().length() + 2);
                    ByteUtils.writeDomainName(nameBuffer, record.getData());
                    byte[] result = new byte[nameBuffer.position()];
                    nameBuffer.flip();
                    nameBuffer.get(result);
                    return result;
                    
                default:
                    return record.getData().getBytes();
            }
        } catch (Exception e) {
            logger.error("获取记录数据时出错（类型：{}）：{}", record.getType(), e.getMessage());
            return new byte[0];
        }
    }
    
    private static int getRecordDataLength(DnsRecord record) {
        switch (record.getType()) {
            case A:
                return 4;
            case AAAA:
                return 16;
            case CNAME:
				return calculateDomainNameLength(record.getData());
            case NS:
            case PTR:
                return calculateDomainNameLength(record.getData());
            default:
                return record.getData().length();
        }
    }
    
    private static int calculateDomainNameLength(String domainName) {
        if (domainName == null || domainName.isEmpty()) {
            return 1; // 空标签
        }
        
        String[] labels = domainName.split("\\.");
        int length = 0;
        for (String label : labels) {
            length += 1 + label.length(); // 长度字节 + 标签内容
        }
        length += 1; // 结束字节
        return length;
    }
    
    public static DnsMessage decodeDnsMessageSafe(byte[] data) {
        try {
            return decodeDnsMessage(data);
        } catch (Exception e) {
            logger.warn("安全DNS解码失败，返回空消息：{}", e.getMessage());
            // 返回一个基本的错误响应消息
            DnsMessage errorMessage = new DnsMessage();
            errorMessage.setId(0);
            errorMessage.setFlags(0x8183); // 服务器故障标志
            return errorMessage;
        }
    }
    
    public static boolean isValidDnsMessage(byte[] data) {
        if (data == null || data.length < 12) {
            return false;
        }
        
        try {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            
            // 跳过ID和Flags
            buffer.position(buffer.position() + 4);
            
            int questionCount = buffer.getShort() & 0xFFFF;
            if (questionCount < 0 || questionCount > 10) {
                return false;
            }
            
            // 验证问题部分
            for (int i = 0; i < questionCount; i++) {
                if (!ByteUtils.hasEnoughBytesForDomainName(buffer)) {
                    return false;
                }
                
                // 跳过域名
                ByteUtils.skipDomainName(buffer);
                
                if (buffer.remaining() < 4) {
                    return false;
                }
                
                // 跳过类型和类
                buffer.position(buffer.position() + 4);
            }
            
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }
}
