package com.dns.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ByteUtils {
    private static final Logger logger = LoggerFactory.getLogger(ByteUtils.class);
    
    public static int readUnsignedShort(ByteBuffer buffer) {
        return buffer.getShort() & 0xFFFF;
    }
    
    public static void writeUnsignedShort(ByteBuffer buffer, int value) {
        buffer.putShort((short) (value & 0xFFFF));
    }
    
    public static String readDomainName(ByteBuffer buffer) {
        try {
            List<String> labels = new ArrayList<>();
            int length;
            
            while ((length = buffer.get() & 0xFF) != 0) {
                // 检查是否是压缩指针
                if ((length & 0xC0) == 0xC0) {
                    // 指针压缩 - 检查是否有足够的字节读取指针
                    if (buffer.remaining() < 1) {
                        throw new BufferUnderflowException();
                    }
                    
                    int pointer = ((length & 0x3F) << 8) | (buffer.get() & 0xFF);
                    int currentPosition = buffer.position();
                    
                    // 验证指针位置的有效性
                    if (pointer >= buffer.limit()) {
                        throw new IllegalArgumentException("Invalid pointer position: " + pointer);
                    }
                    
                    buffer.position(pointer);
                    String name = readDomainName(buffer);
                    buffer.position(currentPosition);
                    return name;
                } else {
                    // 普通标签 - 检查是否有足够字节读取标签
                    if (buffer.remaining() < length) {
                        throw new BufferUnderflowException();
                    }
                    
                    byte[] labelBytes = new byte[length];
                    buffer.get(labelBytes);
                    String label = new String(labelBytes, StandardCharsets.US_ASCII);
                    
                    // 验证标签长度（RFC 1035规定标签长度1-63字节）
                    if (label.length() > 63) {
                        throw new IllegalArgumentException("Label too long: " + label);
                    }
                    
                    labels.add(label);
                }
            }
            
            // 验证域名总长度（RFC 1035规定域名总长度不超过253字节）
            String domainName = String.join(".", labels);
            if (domainName.length() > 253) {
                throw new IllegalArgumentException("Domain name too long: " + domainName);
            }
            
            return domainName;
            
        } catch (BufferUnderflowException e) {
            logger.warn("Buffer underflow while reading domain name - remaining bytes: {}", buffer.remaining());
            throw e;
        } catch (Exception e) {
            logger.warn("Error reading domain name: {}", e.getMessage());
            throw new RuntimeException("Failed to read domain name", e);
        }
    }
    
    public static void writeDomainName(ByteBuffer buffer, String domainName) {
        try {
            if (domainName == null || domainName.isEmpty()) {
                buffer.put((byte) 0); // 空域名
                return;
            }
            
            String[] labels = domainName.split("\\.");
            for (String label : labels) {
                if (label.length() > 63) {
                    throw new IllegalArgumentException("Label too long: " + label);
                }
                buffer.put((byte) label.length());
                buffer.put(label.getBytes(StandardCharsets.US_ASCII));
            }
            buffer.put((byte) 0);
            
        } catch (Exception e) {
            logger.error("Error writing domain name '{}': {}", domainName, e.getMessage());
            throw e;
        }
    }
    
    public static byte[] ipv4ToBytes(String ip) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                throw new IllegalArgumentException("Invalid IPv4 address format: " + ip);
            }
            
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                int num = Integer.parseInt(parts[i]);
                if (num < 0 || num > 255) {
                    throw new IllegalArgumentException("Invalid IPv4 octet: " + num);
                }
                bytes[i] = (byte) num;
            }
            return bytes;
            
        } catch (Exception e) {
            logger.error("Error converting IPv4 address '{}': {}", ip, e.getMessage());
            throw new IllegalArgumentException("Invalid IPv4 address: " + ip, e);
        }
    }
    
    public static byte[] ipv6ToBytes(String ip) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            String[] parts = ip.split(":");
            
            // 处理IPv6缩写（::）
            int zeroCount = 0;
            for (String part : parts) {
                if (part.isEmpty()) {
                    zeroCount++;
                }
            }
            
            if (zeroCount > 1) {
                throw new IllegalArgumentException("Invalid IPv6 address format: " + ip);
            }
            
            for (String part : parts) {
                if (part.isEmpty()) {
                    // 处理 :: 缩写
                    int zeros = 8 - (parts.length - 1);
                    for (int i = 0; i < zeros; i++) {
                        outputStream.write(0);
                        outputStream.write(0);
                    }
                } else {
                    int value;
                    if (part.isEmpty()) {
                        value = 0;
                    } else {
                        value = Integer.parseInt(part, 16);
                    }
                    outputStream.write((value >> 8) & 0xFF);
                    outputStream.write(value & 0xFF);
                }
            }
            
            byte[] result = outputStream.toByteArray();
            if (result.length != 16) {
                throw new IllegalArgumentException("Invalid IPv6 address length: " + result.length);
            }
            
            return result;
            
        } catch (Exception e) {
            logger.error("Error converting IPv6 address '{}': {}", ip, e.getMessage());
            throw new IllegalArgumentException("Invalid IPv6 address: " + ip, e);
        }
    }
    
    /**
     * 安全读取域名，如果出错返回默认值
     */
    public static String readDomainNameSafe(ByteBuffer buffer, String defaultValue) {
        try {
            return readDomainName(buffer);
        } catch (Exception e) {
            logger.debug("Failed to read domain name, using default: {}", defaultValue);
            return defaultValue;
        }
    }
    
    /**
     * 检查缓冲区是否有足够字节读取域名
     */
    public static boolean hasEnoughBytesForDomainName(ByteBuffer buffer) {
        if (buffer == null || buffer.remaining() < 1) {
            return false;
        }
        
        try {
            // 保存当前位置
            int position = buffer.position();
            
            // 尝试读取域名但不实际移动位置
            int length;
            int bytesNeeded = 0;
            
            while (buffer.remaining() > 0) {
                if (buffer.remaining() < 1) return false;
                
                length = buffer.get() & 0xFF;
                bytesNeeded++;
                
                if (length == 0) {
                    break; // 域名结束
                }
                
                if ((length & 0xC0) == 0xC0) {
                    // 压缩指针，需要额外1字节
                    if (buffer.remaining() < 1) return false;
                    buffer.get(); // 跳过指针字节
                    bytesNeeded++;
                    break; // 指针指向的域名不在此处检查
                } else {
                    // 普通标签
                    if (buffer.remaining() < length) return false;
                    buffer.position(buffer.position() + length);
                    bytesNeeded += length;
                }
            }
            
            // 恢复位置
            buffer.position(position);
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 跳过域名（用于跳过无效的域名数据）
     */
    public static void skipDomainName(ByteBuffer buffer) {
        try {
            int length;
            while (buffer.remaining() > 0 && (length = buffer.get() & 0xFF) != 0) {
                if ((length & 0xC0) == 0xC0) {
                    // 压缩指针，跳过1字节
                    if (buffer.remaining() > 0) {
                        buffer.get();
                    }
                    break;
                } else {
                    // 普通标签，跳过标签内容
                    if (buffer.remaining() >= length) {
                        buffer.position(buffer.position() + length);
                    } else {
                        break;
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Error skipping domain name: {}", e.getMessage());
        }
    }
}