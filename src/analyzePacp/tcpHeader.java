package analyzePacp;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-22 23:29
 * @description：The data structure of tcp header
 * @modified By：
 * @version:
 */
public class tcpHeader {
    private int srcPort; //2B,源端口
    private int dstPort; //2B，目的端口
    private long seq; //4B,序号
    private long ack; //4B,确认序号


    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
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
}
