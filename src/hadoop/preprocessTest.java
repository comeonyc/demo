package hadoop;

import analyzePacp.analyzeTools;
import com.google.gson.Gson;
import test.bean;

import java.io.*;

/**
 * @author ：YangChen
 * @date ：Created in 2019-08-08 01:51
 * @description：
 * @modified By：
 * @version:
 */
public class preprocessTest {

    public static void main(String[] args) throws IOException {

        analyzeTools analyzeTools = new analyzeTools();
        FileInputStream fis = new FileInputStream("1.pcap");
        analyzeTools.readPcapFile(fis,false);

        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream("part-r-00000")));

        FileOutputStream fos = null;
        BufferedOutputStream bos = null;

        long last = -1;

        String tmp = "";
        while ((tmp = br.readLine()) !=null){

            int flag = tmp.indexOf("{");

            long path = Long.parseLong(tmp.substring(0,flag).trim());

            String json =  tmp.substring(flag,tmp.length());
            Gson gson = new Gson();
            bean bean = gson.fromJson(json, test.bean.class);


            if(last!=path){
                fos = new FileOutputStream("psort/"+path+".pcap",false);
                bos = new BufferedOutputStream(fos);
                bos.write(analyzeTools.getPcapHeaderBuffer());
                bos.write(bean.getData());
                bos.close();
                fos.close();
            }else {
                fos = new FileOutputStream("psort/"+path+".pcap",true);
                bos = new BufferedOutputStream(fos);
                bos.write(bean.getData());
                bos.close();
                fos.close();
            }

            last = path;

        }

    }
}
