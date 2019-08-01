package analyzePacp;
import org.apache.hadoop.hdfs.net.TcpPeerServer;
import org.junit.Test;

import java.io.*;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * @author ：YangChen
 * @date ：Created in 2019-07-23 10:03
 * @description：Analyze the pcap file and get the information of the pcap
 * @modified By：
 * @version:
 *
 *      * 前期操作：获得pcap文件字节流，根据pcap文件特征，找到pacp文件头，packet包头中的capLen，以及packet包中的四元组信息
 *      * 故，我们需要创建一个pcapHeader的对象、以及各个头文件的对象，还要存储数据
 *      *
 *      * 1、需要获得：源IP，目的IP，源端口，目的端口四元组信息
 *      * 2、需要得到TCP头部的序号Seq，以及确认序号Ack
 *      * 3、按照Seq以及Ack排序
 *      *
 *      * 后期操作：涉及到排序的问题以及流重组的问题
 *      *
 *
 */
public class pcapAnalyze {


    private pcapHeader pcapHeader;
    private byte[] byteBuffer;
    private int offset = 0;


    public int getIntNum (ArrayList<Byte> bytes , int offset_flag,int length){
        int bytesLen = 0;

        bytesLen = length;

        byte[] byteTmp = new byte[bytesLen];
        byte[] byteRes;


        for(int i=0 ; i<length ; i++){
            byteTmp[i] = bytes.get(i + offset_flag);
        }

        if(length == 2){
            byteRes = DataUtils.mergeByte(DataUtils.BytesConversion(byteTmp),length);
        }else if(length == 4){
            byteRes = DataUtils.BytesConversion(byteTmp);
        }else {
            byteRes = DataUtils.mergeByte(byteTmp,length);
        }
        return DataUtils.ByteToInt(byteRes);

    }

    public void getPcapHeader(ArrayList<Byte> bytes){

        int offset_flag = 0;

        int magic = getIntNum(bytes,offset_flag,4);
        offset_flag = offset_flag+4;
        offset += 4;

        short major = (short) getIntNum(bytes,offset_flag,2);
        offset_flag = offset_flag + 2;
        offset += 2;

        short minor = (short) getIntNum(bytes,offset_flag,2);
        offset_flag = offset_flag + 2;
        offset += 2;

        int timeZone = getIntNum(bytes,offset_flag,4);
        offset_flag = offset_flag + 4;
        offset += 4;

        int sigFigs = getIntNum(bytes,offset_flag,4);
        offset_flag = offset_flag + 4;
        offset += 4;

        int snapLen = getIntNum(bytes,offset_flag,4);
        offset_flag = offset_flag + 4;
        offset += 4;

        int linkType = getIntNum(bytes,offset_flag,4);
        //offset_flag = offset_flag + 4;
        offset += 4;

        pcapHeader = new pcapHeader();
        pcapHeader.setLinkType(linkType);
        pcapHeader.setMagic(magic);
        pcapHeader.setMajor(major);
        pcapHeader.setMinor(minor);
        pcapHeader.setSigFigs(sigFigs);
        pcapHeader.setSnapLen(snapLen);
        pcapHeader.setTimeZone(timeZone);

        byteBuffer = new byte[24];
        for(int i=0 ; i<24; i++){
            byteBuffer[i] = bytes.get(i);
        }


    }

    public packetHeader getPacketHeader(ArrayList<Byte> bytes){
        int offset_flag = offset;

        int timeHighStamp = 0;
        int timeLowStamp = 0;
        int capLen = 0;
        int len = 0;

        timeHighStamp = getIntNum(bytes,offset_flag,4);
        offset_flag += 4;
        offset += 4;

        timeLowStamp = getIntNum(bytes,offset_flag,4);
        offset_flag += 4;
        offset += 4;

        capLen = getIntNum(bytes,offset_flag,4);
        offset_flag += 4;
        offset += 4;

        len = getIntNum(bytes,offset_flag,4);
        offset_flag += 4;
        offset += 4;

        packetHeader packetHeader = new packetHeader();
        packetHeader.setTimeHighStamp(timeHighStamp);
        packetHeader.setTimeLowStamp(timeLowStamp);
        packetHeader.setCapLen(capLen);
        packetHeader.setLen(len);
        packetFile packetFile = new packetFile();
        packetFile.setPacketHeader(packetHeader);


        return packetHeader;

    }

    public ipHeader getIPHeader(ArrayList<Byte> bytes){
        int offset_flag = offset;

       // System.out.println(offset_flag);

        int IPOne = getIntNum(bytes,offset_flag,1);
        offset += 1;
        offset_flag += 1;

        String IPOneStrTmp = DataUtils.ByteTo2HexStr(DataUtils.IntToByte(IPOne)[0]);

        String IPOneStr = "";
        if(IPOneStrTmp.length() < 8){
            for(int i=0 ; i< 8-IPOneStrTmp.length();i++){
                IPOneStr = IPOneStr + "0";
            }
        }

        IPOneStr = IPOneStr + IPOneStrTmp;

        String ipVersionStr = IPOneStr.substring(0,4);
        String ipHeaderLenStr = IPOneStr.substring(4,8);

        short ipVersion = (short) DataUtils.Hex2StrToInt(ipVersionStr);
        short ipHeaderLen = (short) DataUtils.Hex2StrToInt(ipHeaderLenStr);

        offset += 8;
        offset_flag = offset;

        short protocl = (short) getIntNum(bytes,offset_flag,1);
        offset += 1;
        offset_flag +=1;

        offset += 2;
        offset_flag = offset;

        int srcIPInt = getIntNum(bytes,offset_flag,4);
        offset += 4;
        offset_flag += 4;

        int dstIPInt = getIntNum(bytes,offset_flag,4);
        offset += 4;
        offset_flag += 4;

        byte[] srcIPInts = DataUtils.IntToByte(srcIPInt);
        byte[] dstIPInts = DataUtils.IntToByte(dstIPInt);

        String srcIPStr= DataUtils.BytesTo2HexStr(srcIPInts);
        String dstIPStr = DataUtils.BytesTo2HexStr(dstIPInts);


        String srcIP = DataUtils.getIP(srcIPStr);
        String dstIP = DataUtils.getIP(dstIPStr);

        int ipHeaderRes  = ipHeaderLen*4 - 20;

        offset += ipHeaderRes;

        ipHeader ipHeader = new ipHeader();
        ipHeader.setDstIP(dstIP);
        ipHeader.setProtocol(protocl);
        ipHeader.setSrcIP(srcIP);
        ipHeader.setIpHeaderLen(ipHeaderLen);

        return ipHeader;
    }

    public tcpHeader getTcpHeader(ArrayList<Byte> bytes){
        int offset_flag = offset;
        offset_flag = offset;


        byte[] byte_4 =  new byte[4];

        int srcPortTmp = getIntNum(bytes,offset_flag,2);
        byte_4 = DataUtils.IntToByte(srcPortTmp);
        int srcPort =  DataUtils.getPort(byte_4);
        offset_flag+=2;
        offset+=2;

        int dstPortTmp =  getIntNum(bytes,offset_flag,2);
        byte_4 = DataUtils.IntToByte(dstPortTmp);
        int dstPort = DataUtils.getPort(byte_4);
        offset_flag += 2;
        offset += 2;

        int seqtmp = getIntNum(bytes,offset_flag,4);
        byte_4 = DataUtils.IntToByte(seqtmp);
        long seq = DataUtils.getSeq(byte_4);
        offset_flag += 4;
        offset += 4;

        int acktmp = getIntNum(bytes,offset_flag,4);
        byte_4 = DataUtils.IntToByte(acktmp);
        long ack = DataUtils.getSeq(byte_4);
        offset_flag += 4;
        offset += 4;

        tcpHeader tcpHeader = new tcpHeader();
        tcpHeader.setSeq(seq);
        tcpHeader.setAck(ack);
        tcpHeader.setDstPort(dstPort);
        tcpHeader.setSrcPort(srcPort);
        return tcpHeader;
    }

    public udpHeader getUdpHeader(ArrayList<Byte> bytes){
        int offset_flat = offset;

        short srcPort = (short) getIntNum(bytes,offset_flat,2);
        offset_flat += 2;
        offset += 2;

        short dstPort = (short) getIntNum(bytes,offset_flat,2);
        offset_flat += 2;
        offset += 2;

        short udpLen = (short) getIntNum(bytes,offset_flat,2);
        offset_flat += 2;
        offset += 2;

        short checkSun = (short) getIntNum(bytes,offset_flat,2);
        offset_flat += 2;
        offset += 2;

        udpHeader udpHeader = new udpHeader();
        udpHeader.setCheckSum(checkSun);
        udpHeader.setDstPort(dstPort);
        udpHeader.setSrcPort(srcPort);
        udpHeader.setUdpLen(udpLen);

        return  udpHeader;
    }

    public ArrayList<packetFile> getPacketFileStream(String name){

        ArrayList<Byte> bytes = readPcapFile(name);
        //---------------此时得到了pcap文件的字节流-------------

        getPcapHeader(bytes);
        System.out.println("---------pcap头部-----------");
        System.out.println(pcapHeader.toString());
        //---------------已经得到了PcapHeader-----------------


        ArrayList<packetFile> packetFileArrayList = new ArrayList<>();
        packetHeader packetHeader = null;
        ipHeader ipHeader = null;
        tcpHeader tcpHeader = null;
        //udpHeader udpHeader = null;
        int packetLen = 0;
        packetFile packetFile = null;

        //----------进入到读取packet数据包的阶段--------
        while(offset < bytes.size()){
            //先读取到pacaket包头
            packetHeader = getPacketHeader(bytes);

            //此时得到下一个包的位置；
            int offset_tmp = offset + packetHeader.getCapLen();
            //----------此时得到了packet头------------------
            packetLen = packetHeader.getCapLen();

            //----------------此时为数据中第一个包头-------------------
            offset = offset+14; //加入mac帧的14个字节
            offset = offset+20; //加入ip的20个字节
            offset = offset+8;  //加入udp的8个字节
            offset = offset+8;  //加入8个字节的标示符号
            //----------------数据中第一个包头结束--------------------


            //----------------此时为数据中的第二个包头，我们需要的--------
            int data_start = offset;
            int packet_real_len = packetHeader.getCapLen() - 50;
            int data_end = offset + packet_real_len;

            offset = offset+14; //加入mac帧的14个字节

            //----------此时得到数据中的第二个IP包，我们需要的-----------
            ipHeader = getIPHeader(bytes);
            //offset = offset + ipHeader.getIpHeaderLen();


            if(ipHeader.getProtocol() == 6){
                tcpHeader = getTcpHeader(bytes);
                packetFile = new packetFile();

                packetHeader.setCapLen(packet_real_len);
                packetFile.setPacketHeader(packetHeader);
                packetFile.setTcpHeader(tcpHeader);
                packetFile.setIpHeader(ipHeader);

                byte[] data = new byte[packet_real_len];
                int j = 0;
                for(int i=data_start ; i<data_end ;i++){

                    data[j] = bytes.get(i);
                    j++;
                }
                packetFile.setData(data);
                packetFileArrayList.add(packetFile);

                //System.out.println(packetFile.toString());

            }

            offset = offset_tmp;

        }

        return packetFileArrayList;

    }

    public ArrayList<Byte> readPcapFile(String name){
        /**
         * 按字节流读取，首先读取pcap文件头存储，然后读取packet包头存储一下，然后读取packet中的数据读取协议只留下tcp相关；
         */

        FileInputStream fis = null;
        ArrayList<Byte> bytes = new ArrayList<>();



        try {
            fis = new FileInputStream(name);
            int byteRead;
            byte b;


            while((byteRead = fis.read()) != -1){
                b = (byte) byteRead;
                bytes.add(b);
            }

            fis.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return bytes;
    }

    public void writeArrToPcapFile(ArrayList<packetFile> packetFiles) throws FileNotFoundException {

        FileOutputStream fos = new FileOutputStream("1_sort.pcap");
        BufferedOutputStream bos = new BufferedOutputStream(fos);

        try{

            bos.write(byteBuffer);

            for(int i=0 ; i<packetFiles.size() ; i++){
                bos.write(packetFiles.get(i).getPacketHeader().getPacketString());
                bos.write(packetFiles.get(i).getData());
            }


            bos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    public ArrayList<packetFile> quickSortPcap(ArrayList<packetFile> packetFiles, int start, int end){
        /**
         * 对乱序的pcap进行排序
         * @param packetFiles
         * @param start
         * @param end
         * @return
         */

        packetFile packetFile_flag = packetFiles.get(start);
        long flag_high = packetFile_flag.getPacketHeader().getHighTime();
        long flag_low = packetFile_flag.getPacketHeader().getLowTime();
        int i = start;
        int j = end;

        while(i < j){
            while((i<j) && (packetFiles.get(j).getPacketHeader().getHighTime() >= flag_high )){
                if(packetFiles.get(j).getPacketHeader().getHighTime()==flag_high && packetFiles.get(j).getPacketHeader().getLowTime() >= flag_low){
                    j--;
                }else if(packetFiles.get(j).getPacketHeader().getHighTime()==flag_high && packetFiles.get(j).getPacketHeader().getLowTime() < flag_low){
                    break;
                }else {
                    j--;
                }

            }

            packetFiles.set(i,packetFiles.get(j));
            //packetFiles[i] = packetFiles[j];

            while((i<j) && (packetFiles.get(i).getPacketHeader().getHighTime() <= flag_high)){
                if(packetFiles.get(i).getPacketHeader().getHighTime() == flag_high  && packetFiles.get(i).getPacketHeader().getLowTime() <= flag_low){
                    i++;
                }else if (packetFiles.get(i).getPacketHeader().getHighTime() == flag_high  && packetFiles.get(i).getPacketHeader().getLowTime() > flag_low){
                    break;
                }else {
                    i++;
                }
            }

            packetFiles.set(j,packetFiles.get(i));
           // packetFiles[j] = packetFiles[i];

        }

        packetFiles.set(i,packetFile_flag);

        //packetFiles[i] = packetFile_flag;

        if((i-1) > start){
            packetFiles = quickSortPcap(packetFiles,start,i-1);
        }

        if((i+1) < end){
            packetFiles = quickSortPcap(packetFiles,i+1,end);
        }

        return packetFiles;

    }

//    public ArrayList<packetFile> quickSortLowPcap(ArrayList<packetFile> packetFiles,int start,int end){
//
//    }


    @Test
    public void test() throws FileNotFoundException {
//        ArrayList<packetFile> packetFiles = new ArrayList<>();
//
//        for(int i = 0 ; i < 10 ; i++){
//            int p = (int)(1+Math.random()*(20-1+1));
//            packetFile packetFile = new packetFile();
//            tcpHeader tcpHeader = new tcpHeader();
//            tcpHeader.setSeq(p);
//            System.out.println(p);
//            packetFile.setTcpHeader(tcpHeader);
//            packetFiles.add(packetFile);
//        }
//
//        packetFile packetFileArr[] = (packetFile[]) packetFiles.toArray(new packetFile[packetFiles.size()]);
//
//        packetFileArr = quickSortPcap(packetFileArr,0,9);
//
//        System.out.println("--------------");
//
//        for(packetFile packetFile : packetFileArr){
//            System.out.println(packetFile.getTcpHeader().getSeq());
//        }

        String file_name = "1.pcap";

        ArrayList<packetFile> packetFiles = new ArrayList<>();

        packetFiles = getPacketFileStream(file_name);

        packetFiles = quickSortPcap(packetFiles,0,packetFiles.size()-1);

//        ArrayList<packetFile> packetFilesTmp  = new ArrayList<>();
//        long tmp;
//
//        int offset = 0;
//        while(offset < packetFiles.size()){
//            tmp = packetFiles.get(offset).getPacketHeader().getHighTime();
//            packetFilesTmp.add(packetFiles.get(offset));
//            while(packetFiles.get(offset++).getPacketHeader().getHighTime() == tmp){
//                packetFilesTmp.add(packetFiles.get(offset));
//            }
//        }

        writeArrToPcapFile(packetFiles);

        //System.out.println(packetFiles.size());

    }

}
