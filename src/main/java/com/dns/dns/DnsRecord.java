package com.dns.dns;

public class DnsRecord {
    private String name;
    private DnsRecordType type;
    private int clazz;
    private long ttl;
    private String data;
    
    public DnsRecord(String name, DnsRecordType type, int clazz, long ttl, String data) {
        this.name = name;
        this.type = type;
        this.clazz = clazz;
        this.ttl = ttl;
        this.data = data;
    }
    
    // Getters and Setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public DnsRecordType getType() { return type; }
    public void setType(DnsRecordType type) { this.type = type; }
    
    public int getClazz() { return clazz; }
    public void setClazz(int clazz) { this.clazz = clazz; }
    
    public long getTtl() { return ttl; }
    public void setTtl(long ttl) { this.ttl = ttl; }
    
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }
}