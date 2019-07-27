package analyzePacp;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-22 23:19
 * @description：The data structure of ip header
 * @modified By：
 * @version:
 */
public class ipHeader {
    /**
     * IP数据报的头部
     */
    /**
     * 1B
     */
    private short ipVersion; // 1/2B,协议版本
    private short ipHeaderLen; // 1/2B,ip数据报长度


    /**
     *  间隔8B，其中包括1B服务类型，2B总长度，2B标识，2B标志加偏移，1B生存时间
     */

    private short protocol; // 1B,传输层协议
    /**
     * 间隔2B，2B的首部校验和
     */

    private String srcIP; //4B，源IP地址
    private String dstIP; //4B，目的IP地址

    /**
     * 后面是选项
     */

    public short getIpVersion() {
        return ipVersion;
    }

    public void setIpVersion(short ipVersion) {
        this.ipVersion = ipVersion;
    }

    public short getIpHeaderLen() {
        return ipHeaderLen;
    }

    public void setIpHeaderLen(short ipHeaderLen) {
        this.ipHeaderLen = ipHeaderLen;
    }

    public short getProtocol() {
        return protocol;
    }

    public void setProtocol(short protocol) {
        this.protocol = protocol;
    }

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

}
