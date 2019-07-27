package analyzePacp;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-22 22:25
 * @description：the data structure of frame header
 * @modified By：
 * @version: 1
 */
public class frameHeader {
    /**
     * 数据区域中的数据帧头部，共14B
     */
    private long dstMAC; //6B，目的MAC地址
    private long srcMAC; //6B，源MAC地址
    private short frametyoe; //2B，数据帧类型

    public long getDstMAC() {
        return dstMAC;
    }

    public void setDstMAC(long dstMAC) {
        this.dstMAC = dstMAC;
    }

    public long getSrcMAC() {
        return srcMAC;
    }

    public void setSrcMAC(long srcMAC) {
        this.srcMAC = srcMAC;
    }

    public short getFrametyoe() {
        return frametyoe;
    }

    public void setFrametyoe(short frametyoe) {
        this.frametyoe = frametyoe;
    }
}
