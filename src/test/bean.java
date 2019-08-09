package test;

import com.alibaba.fastjson.annotation.JSONField;

/**
 * @author ：YangChen
 * @date ：Created in 2019-08-05 10:39
 * @description：
 * @modified By：
 * @version:
 */
public class bean {
    private String srcIP;
    private String dstIP;
    private int dstPort;
    private int srcPort;
    private long high_time;
    private long low_time;
    private long seq;
    private long ack;
    private byte[] data;

    public String getSrcIP() {
        return srcIP;
    }

    public void setSrcIP(String srcIP) {
        this.srcIP = srcIP;
    }

    public String getDstIP() {
        return dstIP;
    }

    public void setDstIP(String dstIP) {
        this.dstIP = dstIP;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public long getHigh_time() {
        return high_time;
    }

    public void setHigh_time(long high_time) {
        this.high_time = high_time;
    }

    public long getLow_time() {
        return low_time;
    }

    public void setLow_time(long low_time) {
        this.low_time = low_time;
    }

    public long getSeq() {
        return seq;
    }

    public void setSeq(long seq) {
        this.seq = seq;
    }

    public long getAck() {
        return ack;
    }

    public void setAck(long ack) {
        this.ack = ack;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }
}
