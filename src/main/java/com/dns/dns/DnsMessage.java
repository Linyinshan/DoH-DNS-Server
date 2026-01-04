package com.dns.dns;

import java.util.ArrayList;
import java.util.List;

public class DnsMessage {
    private int id;
    private int flags;
    private List<DnsQuestion> questions = new ArrayList<>();
    private List<DnsRecord> answers = new ArrayList<>();
    private List<DnsRecord> authorities = new ArrayList<>();
    private List<DnsRecord> additionals = new ArrayList<>();
    
    public DnsMessage() {}
    
    public DnsMessage(int id, int flags) {
        this.id = id;
        this.flags = flags;
    }
    
    // Getters and Setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    
    public int getFlags() { return flags; }
    public void setFlags(int flags) { this.flags = flags; }
    
    public List<DnsQuestion> getQuestions() { return questions; }
    public void setQuestions(List<DnsQuestion> questions) { this.questions = questions; }
    
    public List<DnsRecord> getAnswers() { return answers; }
    public void setAnswers(List<DnsRecord> answers) { this.answers = answers; }
    
    public List<DnsRecord> getAuthorities() { return authorities; }
    public void setAuthorities(List<DnsRecord> authorities) { this.authorities = authorities; }
    
    public List<DnsRecord> getAdditionals() { return additionals; }
    public void setAdditionals(List<DnsRecord> additionals) { this.additionals = additionals; }
    
    public void addQuestion(DnsQuestion question) {
        questions.add(question);
    }
    
    public void addAnswer(DnsRecord answer) {
        answers.add(answer);
    }
    
    // 新增方法 - 修复错误
    public void setQr(boolean qr) {
        // QR标志位在flags的第16位（最高位）
        if (qr) {
            flags |= 0x8000; // 设置第16位为1
        } else {
            flags &= 0x7FFF; // 设置第16位为0
        }
    }
    
    public int getOpcode() {
        // OPCODE在flags的第12-15位
        return (flags >> 11) & 0x0F;
    }
    
    public void setOpcode(int opcode) {
        // OPCODE在flags的第12-15位
        flags = (flags & 0x87FF) | ((opcode & 0x0F) << 11);
    }
    
    public void setAa(boolean aa) {
        // AA标志位在flags的第10位
        if (aa) {
            flags |= 0x0400; // 设置第10位为1
        } else {
            flags &= 0xFBFF; // 设置第10位为0
        }
    }
    
    public void setRa(boolean ra) {
        // RA标志位在flags的第7位
        if (ra) {
            flags |= 0x0080; // 设置第7位为1
        } else {
            flags &= 0xFF7F; // 设置第7位为0
        }
    }
    
    public void setRcode(int rcode) {
        // RCODE在flags的第0-3位
        flags = (flags & 0xFFF0) | (rcode & 0x0F);
    }
    
    // 可选：添加其他有用的标志位操作方法
    public boolean isQr() {
        return (flags & 0x8000) != 0;
    }
    
    public boolean isAa() {
        return (flags & 0x0400) != 0;
    }
    
    public boolean isRa() {
        return (flags & 0x0080) != 0;
    }
    
    public int getRcode() {
        return flags & 0x000F;
    }
}