package analyzePacp;

import org.junit.Test;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-29 16:20
 * @description：the tools of analyzing pcap
 * @modified By：
 * @version: 2
 */
public class analyzeTools {

    private byte[] pcapHeaderBuffer;
    private ArrayList<packetFile> packetFiles;
    private HashMap<String,Integer> streamInfoMap;

    private int errorPacketNum = 0;

    public packetHeader setPacketHeader(byte[] bytes){
        byte[] byte_4 = new byte[4];
        int off = 0;

        int timeHighStamp = DataTools.calIntNum(bytes,off,true);
        off+=4;
        int timeLowStamp = DataTools.calIntNum(bytes,off,true);
        off+=4;
        int capLen = DataTools.calIntNum(bytes,off,true);
        off+=4;
        int len = DataTools.calIntNum(bytes,off,true);

        packetHeader packetHeader =  new packetHeader(timeHighStamp,timeLowStamp,capLen,len);

        return packetHeader;

    }

    public ipHeader setIpHeader(byte[] bytes,int off){

        int offset = off;
        String IPOne = DataTools.byteTo2HexStr(bytes[offset]);
        offset += 1; //1B,   1/2B 协议版本    ,   1/2B ip数据报长度

        short ipVersion = (short) DataTools.hex2StrToInt(IPOne.substring(0,4));
        short ipHeaderLen = (short) DataTools.hex2StrToInt(IPOne.substring(4,8));

        offset += 1;   //间隔1B服务类型

        //此处获取total length  2B

        byte[] byte_4= new byte[4];
        byte_4[0] = 0;
        byte_4[1] = 0;
        for(int i=0;i<2;i++){
            byte_4[i+2] = bytes[i+offset];
        }

        int totalLen = DataTools.bytesToInt(byte_4);
        offset += 2;


        offset += 5;   //间隔5B，其中2B标识，2B标志加偏移，1B生存时间


        short protocl = bytes[offset];
        offset += 1;  //1B ,协议序号

        offset += 2; //间隔2B，2B的首部校验和

        int srcIPInt = DataTools.calIntNum(bytes,offset,false);
        byte[] srcIPInts = DataTools.intToByte(srcIPInt); //字节数组中，左高右低
        String srcIP = DataTools.getIP(DataTools.bytesTo2HexStr(srcIPInts));
        offset += 4;

        int dstIPInt = DataTools.calIntNum(bytes,offset,false);
        byte[] dstIPInts = DataTools.intToByte(dstIPInt);
        String dstIP = DataTools.getIP(DataTools.bytesTo2HexStr(dstIPInts));
        offset += 4;

        ipHeader ipHeader = new ipHeader();
        ipHeader.setDstIP(dstIP);
        ipHeader.setProtocol(protocl);
        ipHeader.setSrcIP(srcIP);
        ipHeader.setIpHeaderLen(ipHeaderLen);
        ipHeader.setTotalLen(totalLen);

        return ipHeader;

    }

    public tcpHeader setTcpHeader(byte[] bytes,int off){
        int offset = off;
        int i;

        byte[] byte_4 = new byte[4];
        byte[] byte_2 = new byte[2];

        for(i=0 ; i<2 ;i++){
            byte_2[i] = bytes[i+offset];
        }

        int srcPort = DataTools.getPort(byte_2);
        offset += 2;

        for(i=0 ; i<2 ;i++){
            byte_2[i] = bytes[i+offset];
        }

        int dstPort = DataTools.getPort(byte_2);
        offset += 2;

        for(i=0 ; i<4 ;i++){
            byte_4[i] = bytes[i+offset];
        }

        long seq = DataTools.getSeq(byte_4);
        offset += 4;

        for(i=0 ; i<4 ;i++){
            byte_4[i] = bytes[i+offset];
        }

        long ack = DataTools.getSeq(byte_4);
        offset += 4;

        tcpHeader tcpHeader = new tcpHeader();
        tcpHeader.setAck(ack);
        tcpHeader.setSeq(seq);
        tcpHeader.setDstPort(dstPort);
        tcpHeader.setSrcPort(srcPort);

        return tcpHeader;


    }

    public void readPcapFile(String fileName){
        FileInputStream fis = null;
        packetFiles = new ArrayList<>();

        try {
            fis = new FileInputStream(fileName);
            int offset = 0;
            int packetLen;
            int packet_real_len;
            pcapHeaderBuffer = new byte[24];
            byte[] packetHeaderBuffer = new byte[16];
            byte[] byteBuffer;

            packetFile packetFile;
            ipHeader ipHeader;
            tcpHeader tcpHeader;
            packetHeader packetHeader;
            int flag = 0;

            //pcap header
            flag = fis.read(pcapHeaderBuffer,0,24);
            offset += 24;
            int p = 0;
            while(flag != -1){
                flag = fis.read(packetHeaderBuffer,0,16);
                if(flag != -1){
                    offset += 16;
                    packetHeader = setPacketHeader(packetHeaderBuffer);

                    packetLen = packetHeader.getCapLen();

                    //--------------第一个数据报的包头-------------
                    offset += 14; //mac帧 14B
                    offset += 20; //ip头 20B
                    offset += 8;  //udp头 8B
                    offset += 8;  //标识符 8B
                    byteBuffer = new byte[50];
                    fis.read(byteBuffer,0,50);
                    //--------------第一个数据报的包头结束----------


                    //--------------第二个数据报的包头开始----------------
                    packet_real_len = packetLen - 50;

                    byteBuffer = new byte[packet_real_len]; //存储所有数据

                    //从data_start开始读取
                    flag = fis.read(byteBuffer,0,packet_real_len);

                    offset += packet_real_len;

                    int off = 0;
                    off += 14;

                    ipHeader = setIpHeader(byteBuffer,off);
                    if(ipHeader.getProtocol() == 6 ){

                        if(ipHeader.getTotalLen()+14 <= packet_real_len){
                            off += ipHeader.getIpHeaderLen()*4;

                            tcpHeader = setTcpHeader(byteBuffer,off);
                            packetHeader.setCapLen(packet_real_len);
                            packetFile = new packetFile();
                            packetFile.setIpHeader(ipHeader);
                            packetFile.setTcpHeader(tcpHeader);
                            packetFile.setPacketHeader(packetHeader);
                            packetFile.setData(byteBuffer);
                            //System.out.println(packetFile.getIpHeader().getSrcIP()+"/"+packetFile.getIpHeader().getDstIP()+"/"+packetFile.getTcpHeader().getSrcPort()+"/"+packetFile.getTcpHeader().getDstPort());

                            packetFiles.add(packetFile);
                        }else {
                            errorPacketNum ++;
                        }

                    }

                }

            }

            fis.close();

            System.out.println(packetFiles.size());
            System.out.println("畸形的包共有："+errorPacketNum);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public  void quickSort(int start,int end){
        packetFile packetFile_flag = packetFiles.get(start);
        long flag_high = DataTools.getTime(packetFile_flag.getPacketHeader().getTimeHighStamp());
        long flag_low = DataTools.getTime(packetFile_flag.getPacketHeader().getTimeLowStamp());

        int i = start;
        int j = end;

        while(i<j){
            while ((i<j) && DataTools.getTime(packetFiles.get(j).getPacketHeader().getTimeHighStamp())>= flag_high){
                if(DataTools.getTime(packetFiles.get(j).getPacketHeader().getTimeHighStamp()) == flag_high  && DataTools.getTime(packetFiles.get(j).getPacketHeader().getTimeLowStamp()) >= flag_low){
                    j--;
                }else if(DataTools.getTime(packetFiles.get(j).getPacketHeader().getTimeHighStamp()) == flag_high  && DataTools.getTime(packetFiles.get(j).getPacketHeader().getTimeLowStamp()) < flag_low){
                    break;
                }else {
                    j--;
                }
            }

            packetFiles.set(i,packetFiles.get(j));

            while ((i<j) && DataTools.getTime(packetFiles.get(i).getPacketHeader().getTimeHighStamp()) <= flag_high) {
                if (DataTools.getTime(packetFiles.get(i).getPacketHeader().getTimeHighStamp()) == flag_high && DataTools.getTime(packetFiles.get(i).getPacketHeader().getTimeLowStamp()) <= flag_low) {
                    i++;
                } else if (DataTools.getTime(packetFiles.get(i).getPacketHeader().getTimeHighStamp()) == flag_high && DataTools.getTime(packetFiles.get(i).getPacketHeader().getTimeLowStamp()) > flag_low) {
                    break;
                } else {
                    i++;
                }
            }

            packetFiles.set(j,packetFiles.get(i));

        }

        packetFiles.set(i,packetFile_flag);

        if((i-1) > start){
            quickSort(start,i-1);
        }

        if((i+1) < end){
            quickSort(i+1,end);
        }

    }


    public void writePcap(){
        FileOutputStream fos = null;
        BufferedOutputStream bos;
        int fileLable = 0;
        String fileName="";

        streamInfoMap = new HashMap<>();
        try{
            for(int i=0 ;i<packetFiles.size();i++) {
                String IP_1 = packetFiles.get(i).getIpHeader().getSrcIP();
                String IP_2 = packetFiles.get(i).getIpHeader().getDstIP();
                int port_1 = packetFiles.get(i).getTcpHeader().getSrcPort();
                int port_2 = packetFiles.get(i).getTcpHeader().getDstPort();

                String info_1 = IP_1 + "/" + IP_2 + "/" + port_1 + "/" + port_2; //info_1是正常的四元组信息
                String info_2 = IP_2 + "/" + IP_1 + "/" + port_2 + "/" + port_1;

                //判别是否在map里面
                if (!streamInfoMap.containsKey(info_1)) {
                    //如果不在的话，往map里面写
                    streamInfoMap.put(info_1, fileLable);
                    streamInfoMap.put(info_2, fileLable);

                    fileName = "sort/"+fileLable + ".pcap";
                    fos = new FileOutputStream(fileName,false);
                    bos = new BufferedOutputStream(fos);

                    bos.write(pcapHeaderBuffer);
                    bos.write(packetFiles.get(i).getPacketHeader().getPacketHeaderInfo());
                    bos.write(packetFiles.get(i).getData());

                    fileLable++;

                }else {
                    fileName = "sort/"+streamInfoMap.get(info_1) + ".pcap";
                    fos = new FileOutputStream(fileName,true);
                    bos = new BufferedOutputStream(fos);
                    bos.write(packetFiles.get(i).getPacketHeader().getPacketHeaderInfo());
                    bos.write(packetFiles.get(i).getData());
                }

                bos.close();
                fos.close();

            }

        }catch (FileNotFoundException e){
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("共有流："+streamInfoMap.size());

    }

    @Test
    public void test() throws IOException {
        String name = "1.pcap";
        readPcapFile(name);
        quickSort(0,packetFiles.size()-1);
        writePcap();

    }
}
