package analyzePacp;

import beforeVersion.DataUtils;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-22 22:10
 * @description：The data structure of packet header
 * @modified By：
 * @version: 1
 */
public class packetHeader {
    /**
     * pcap文件中的packet的包头文件，共16B
     */

    private int timeHighStamp; //4B，时间戳高位
    private int timeLowStamp;  //4B，时间戳低位
    private int capLen; //4B，当前数据包的数据区长度，抓取到的数据帧的长度
    private int len; //4B，离线数据长度，网络中实际数据帧的长度，基本和capLen长度相等

    public packetHeader(){}

    public packetHeader(int timeHighStamp,int timeLowStamp,int capLen,int len){
        this.timeHighStamp = timeHighStamp;
        this.timeLowStamp = timeLowStamp;
        this.capLen = capLen;
        this.len = len;
    }

    public int getTimeHighStamp() {
        return timeHighStamp;
    }

    public void setTimeHighStamp(int timeHighStamp) {
        this.timeHighStamp = timeHighStamp;
    }

    public int getTimeLowStamp() {
        return timeLowStamp;
    }

    public void setTimeLowStamp(int timeLowStamp) {
        this.timeLowStamp = timeLowStamp;
    }

    public int getCapLen() {
        return capLen;
    }

    public void setCapLen(int capLen) {
        this.capLen = capLen;
    }

    public int getLen() {
        return len;
    }

    public void setLen(int len) {
        this.len = len;
    }

    public byte[] getPacketString(){
        byte[] bytes = new byte[16];
        byte[] byte_4 = new byte[4];

        byte_4 = DataUtils.IntToByte(getTimeHighStamp());
        bytes[0] = byte_4[0];
        bytes[1] = byte_4[1];
        bytes[2] = byte_4[2];
        bytes[3] = byte_4[3];

        byte_4 = DataUtils.IntToByte(getTimeLowStamp());
        bytes[4] = byte_4[0];
        bytes[5] = byte_4[1];
        bytes[6] = byte_4[2];
        bytes[7] = byte_4[3];

        byte_4 = DataUtils.IntToByte(getCapLen());
        bytes[8] = byte_4[0];
        bytes[9] = byte_4[1];
        bytes[10] = byte_4[2];
        bytes[11] = byte_4[3];

        byte_4 = DataUtils.IntToByte(getLen());
        bytes[12] = byte_4[0];
        bytes[13] = byte_4[1];
        bytes[14] = byte_4[2];
        bytes[15] = byte_4[3];

        return bytes;
    }

    public byte[] getPacketHeaderInfo(){
        byte[] bytes = new byte[16];
        byte[] byte_4 = new byte[4];

        byte_4 = DataTools.intToByte(getTimeHighStamp());
        bytes[0] = byte_4[3];
        bytes[1] = byte_4[2];
        bytes[2] = byte_4[1];
        bytes[3] = byte_4[0];

        byte_4 = DataTools.intToByte(getTimeLowStamp());
        bytes[4] = byte_4[3];
        bytes[5] = byte_4[2];
        bytes[6] = byte_4[1];
        bytes[7] = byte_4[0];

        byte_4 = DataTools.intToByte(getCapLen());
        bytes[8] = byte_4[3];
        bytes[9] = byte_4[2];
        bytes[10] = byte_4[1];
        bytes[11] = byte_4[0];

        byte_4 = DataTools.intToByte(getLen());
        bytes[12] = byte_4[3];
        bytes[13] = byte_4[2];
        bytes[14] = byte_4[1];
        bytes[15] = byte_4[0];

        return bytes;
    }


    public long getLowTime(){
        byte[] byte_4 = new byte[4];
        byte_4 = DataUtils.IntToByte(getTimeLowStamp());

        byte_4 = DataUtils.BytesConversion(byte_4);

        long time = DataUtils.getSeq(byte_4);

        return time;
    }

    public long getHighTime(){
        byte[] byte_4 = new byte[4];
        byte_4 = DataUtils.IntToByte(getTimeHighStamp());

        byte_4 = DataUtils.BytesConversion(byte_4);

        long time = DataUtils.getSeq(byte_4);

        return time;
    }

}
