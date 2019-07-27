package analyzePacp;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-24 15:36
 * @description：
 * @modified By：
 * @version:
 */
public class udpHeader {

    private short srcPort;  //2B,源端口
    private short dstPort;  //2B,目的端口
    private short udpLen;   //2B,udp长度
    private short checkSum; //2B，校验和


    public short getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(short srcPort) {
        this.srcPort = srcPort;
    }

    public short getDstPort() {
        return dstPort;
    }

    public void setDstPort(short dstPort) {
        this.dstPort = dstPort;
    }

    public short getUdpLen() {
        return udpLen;
    }

    public void setUdpLen(short udpLen) {
        this.udpLen = udpLen;
    }

    public short getCheckSum() {
        return checkSum;
    }

    public void setCheckSum(short checkSum) {
        this.checkSum = checkSum;
    }
}
