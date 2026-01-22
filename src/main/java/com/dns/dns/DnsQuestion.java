package com.dns.dns;

public class DnsQuestion {
    private String name;
    private DnsRecordType type;
    private int clazz;
    
    public DnsQuestion(String name, DnsRecordType type, int clazz) {
        this.name = name;
        this.type = type;
        this.clazz = clazz;
    }
    
    // Getters and Setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public DnsRecordType getType() { return type; }
    public void setType(DnsRecordType type) { this.type = type; }
    
    public int getClazz() { return clazz; }
    public void setClazz(int clazz) { this.clazz = clazz; }
}