package test;
import analyzePacp.DataTools;
import analyzePacp.analyzeTools;
import analyzePacp.packetFile;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.gson.Gson;


import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * @author ：YangChen
 * @date ：Created in 2019-08-04 22:15
 * @description：
 * @modified By：
 * @version:
 */
public class test {
    public static void main(String[] args) throws IOException {
        FileInputStream fis = new FileInputStream("1.pcap");

        analyzeTools analyzeTools = new analyzeTools();
        analyzeTools.readPcapFile(fis,false);

//        ArrayList<packetFile> packetFiles = analyzeTools.getPacketFiles();
//        //BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("p.json")));
//
//        FileOutputStream fos = new FileOutputStream("p.json");
//        BufferedOutputStream bos = new BufferedOutputStream(fos);
//        for(packetFile packetFile:packetFiles){
//            String srcIP = packetFile.getIpHeader().getSrcIP();
//            String dstIp = packetFile.getIpHeader().getDstIP();
//            int srcPort = packetFile.getTcpHeader().getSrcPort();
//            int dstPort = packetFile.getTcpHeader().getDstPort();
//            long high_time = DataTools.getTime(packetFile.getPacketHeader().getTimeHighStamp());
//            long low_time = DataTools.getTime(packetFile.getPacketHeader().getTimeLowStamp());
//            long seq = packetFile.getTcpHeader().getSeq();
//            long ack = packetFile.getTcpHeader().getAck();
//
//            byte[] bytes = new byte[packetFile.getPacketHeader().getPacketHeaderInfo().length+packetFile.getData().length];
//            System.arraycopy(packetFile.getPacketHeader().getPacketHeaderInfo(),0,bytes,0,packetFile.getPacketHeader().getPacketHeaderInfo().length);
//            System.arraycopy(packetFile.getData(),0,bytes,packetFile.getPacketHeader().getPacketHeaderInfo().length,packetFile.getData().length);
//
//            bean bean = new bean();
//            bean.setData(bytes);
//            bean.setHigh_time(high_time);
//            bean.setLow_time(low_time);
//            bean.setSrcIP(srcIP);
//            bean.setDstIP(dstIp);
//            bean.setDstPort(dstPort);
//            bean.setSrcPort(srcPort);
//            bean.setSeq(seq);
//            bean.setAck(ack);
//            Gson gson = new Gson();
//
//            String tmp  = gson.toJson(bean) + "\n";
//            bos.write(tmp.getBytes());
//        }
//        fos.close();


        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("p.json")));
        String tmp ="";
        StringBuilder res = new StringBuilder();
        FileOutputStream fos = new FileOutputStream("2.pcap");
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        bos.write(analyzeTools.getPcapHeaderBuffer());
        int i =0;
        while ((tmp=br.readLine())!= null){
            System.out.println(i++);
            Gson gson_tmp = new Gson();

            bean bean = gson_tmp.fromJson(tmp, bean.class);

            bos.write(bean.getData());
        }


        br.close();


    }
}
