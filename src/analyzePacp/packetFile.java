package analyzePacp;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-23 10:11
 * @description：the data structure of pcap file
 * @modified By：
 * @version:
 */
public class packetFile {
    private packetHeader packetHeader; //获取该数据包的大小
    /**
     * 为了后续的包重组，一定要将packetHeader中的四个属性都得到
     */

    private ipHeader ipHeader; //获取源IP，目的IP
    private tcpHeader tcpHeader; //获取源端口，目的端口

    private byte[] data; //获取该数据包中的信息，主要存储packet包中的全部信息

    public analyzePacp.packetHeader getPacketHeader() {
        return packetHeader;
    }

    public void setPacketHeader(analyzePacp.packetHeader packetHeader) {
        this.packetHeader = packetHeader;
    }

    public analyzePacp.ipHeader getIpHeader() {
        return ipHeader;
    }

    public void setIpHeader(analyzePacp.ipHeader ipHeader) {
        this.ipHeader = ipHeader;
    }

    public analyzePacp.tcpHeader getTcpHeader() {
        return tcpHeader;
    }

    public void setTcpHeader(analyzePacp.tcpHeader tcpHeader) {
        this.tcpHeader = tcpHeader;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }


}
