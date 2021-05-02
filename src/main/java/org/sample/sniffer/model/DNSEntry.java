package org.sample.sniffer.model;

import java.sql.Timestamp;

import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsPacket.DnsHeader;

public class DNSEntry {

    private short id;
    private DnsHeader query;
    private DnsHeader response;

    private DnsDomainName qName;

    private Timestamp queryTimestamp;
    private Timestamp responseTimestamp;

    public DNSEntry(short id, DnsHeader query, DnsHeader response) {
        this.id = id;
        this.query = query;
        this.response = response;
    }

    public DNSEntry(short id, DnsHeader query) {
        this.id = id;
        this.query = query;
    }

    public DNSEntry(short id, DnsHeader query, DnsDomainName qName, Timestamp queryTimestamp) {
        this.id = id;
        this.query = query;
        this.qName = qName;
        this.queryTimestamp = queryTimestamp;
    }

    public DNSEntry(short id) {
        this.id = id;
    }

    public short getId() {
        return id;
    }

    public void setId(short id) {
        this.id = id;
    }

    public DnsHeader getQuery() {
        return query;
    }

    public void setQuery(DnsHeader query) {
        this.query = query;
    }

    public DnsHeader getResponse() {
        return response;
    }

    public void setResponse(DnsHeader response) {
        this.response = response;
    }

    public Timestamp getQueryTimestamp() {
        return queryTimestamp;
    }

    public void setQueryTimestamp(Timestamp queryTimestamp) {
        this.queryTimestamp = queryTimestamp;
    }

    public Timestamp getResponseTimestamp() {
        return responseTimestamp;
    }

    public void setResponseTimestamp(Timestamp responseTimestamp) {
        this.responseTimestamp = responseTimestamp;
    }
    
    public DnsDomainName getqName() {
        return qName;
    }

    public void setqName(DnsDomainName qName) {
        this.qName = qName;
    }
}
