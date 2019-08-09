package analyzePacp;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-22 21:56
 * @description： The data structur of pacp header
 * @modified By：
 * @version: 1
 */
public class pcapHeader {
    /**
     * pacp文件中pcap文件头的结构，共24B，在pcap中唯一，仅出现一次
     */
    private int Magic; //4B,用来标示pcap文件的开始
    private short Major; //2B,用来标示pcap文件的主要版本号
    private short Minor; //2B,用来标示pcap文件的次要版本号
    private int timeZone; //4B,用来标示当地时间标准
    private int sigFigs; //4B,用来标示时间戳的精度
    private int snapLen; //4B.用来标示最大存储长度
    private int linkType; //4B.链路类型


    public int getMagic() {
        return Magic;
    }

    public void setMagic(int magic) {
        Magic = magic;
    }

    public short getMajor() {
        return Major;
    }

    public void setMajor(short major) {
        Major = major;
    }

    public short getMinor() {
        return Minor;
    }

    public void setMinor(short minor) {
        Minor = minor;
    }

    public int getTimeZone() {
        return timeZone;
    }

    public void setTimeZone(int timeZone) {
        this.timeZone = timeZone;
    }

    public int getSigFigs() {
        return sigFigs;
    }

    public void setSigFigs(int sigFigs) {
        this.sigFigs = sigFigs;
    }

    public int getSnapLen() {
        return snapLen;
    }

    public void setSnapLen(int snapLen) {
        this.snapLen = snapLen;
    }

    public int getLinkType() {
        return linkType;
    }

    public void setLinkType(int linkType) {
        this.linkType = linkType;
    }


}