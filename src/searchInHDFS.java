import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.*;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-07 22:29
 * @description：TODO
 * @modified By：yangchen
 * @version: 1
 */
public class searchInHDFS {

    //判断五元组是否为空
    private int chooseFlag[] = new int[5];
    //保存五元组信息
    private String[] chooseStrings = null;

    private String datatime;

    public void openAndWrite(String filename,String choose){

        getJudgeCondition(choose);

        try{
            FileReader fileReader  = new FileReader(filename);
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            judgeString(bufferedReader);

            bufferedReader.close();
            fileReader.close();

        }catch (IOException e){
            e.printStackTrace();
        }


    }

    public void getJudgeCondition(String chooseStr){

        /**
         * create by: YangChen
         * description:
         *     统计出五元组的标记放在chooseFlag数组里，如果选择为空则为0，如果不为空则为1
         *     将五元组的信息放入到字符数组中
         * create time: 2019-07-08 00:18
         *
         * @Param: chooseStr
         * @return void
         */

        chooseStrings = chooseStr.split("\\|");

        chooseFlag[0] = (chooseStrings[0].trim().equals("")) ? 0 : 1;
        chooseFlag[1] = (chooseStrings[1].trim().equals("")) ? 0 : 1;
        chooseFlag[2] = (chooseStrings[2].trim().equals("")) ? 0 : 1;
        chooseFlag[3] = (chooseStrings[3].trim().equals("")) ? 0 : 1;
        chooseFlag[4] = (chooseStrings[4].trim().equals("")) ? 0 : 1;

    }

    public ArrayList<String> statisticsIPInfo(String IPStr){
        /**
         * create by: YangChen
         * description:
         *      统计出来payload下面的IP信息，只统计五元组的信息：
         *      源IP，目的IP，源端口，目的端口，开始时间
         * create time: 2019-07-08 00:19
         *
         * @Param: IPStr
         * @return java.util.ArrayList<java.lang.String>
         */
        String[] strings = IPStr.split("\\s");
        ArrayList<String> arrayList = new ArrayList<>();

        arrayList.add(strings[2]);
        arrayList.add(strings[3]);
        arrayList.add(strings[4]);
        arrayList.add(strings[5]);

        String dateString = strings[6] + " " + strings[7];
        arrayList.add(dateString);
        return arrayList;
    }

    public boolean judgeStrJoin(String string){
        /**
         * create by: YangChen
         * description:
         *      判断该IP信息是否符合五元组的信息
         * create time: 2019-07-08 00:21
         *
         * @Param: string
         * @return boolean
         */
        ArrayList<String> IPInfo = statisticsIPInfo(string);

        for(int i = 0 ;i < chooseFlag.length ; i++){
            if(chooseFlag[i] == 0){
                //此时代表五元组该选项为空,此时不用做任何操作
                continue;
            }else{
                //此时五元组该选项不为空
                if(chooseStrings[i].trim().equals(IPInfo.get(i))){
                    continue;
                }else{
                    return false;
                }
            }
        }
        return true;
    }

    public void writeFile(StringBuffer stringBuffer,String string){
        /**
         * create by: YangChen
         * description: TODO
         * create time: 2019-07-08 19:54
         *
         * @Param: stringBuffer
         * @Param: string
         * @return void
         */


        String filePath = "file_" + datatime + ".txt";
        try{
            File file = new File(filePath);
            FileOutputStream fos = null;
            if(!file.exists()){
                file.createNewFile();
                fos = new FileOutputStream(file);
            }else {
                fos = new FileOutputStream(file,true);
            }

            OutputStreamWriter osw = new OutputStreamWriter(fos,"UTF-8");
            osw.write(string);
            osw.write("\r\n");
            osw.write(stringBuffer.toString());
            osw.write("\r\n");
            osw.close();
        }catch (IOException e){
            e.printStackTrace();
        }

    }

    public void HDFSCat(Configuration conf,String remoteFile){

        try {
            FileSystem fs = FileSystem.get(conf);
            Path remotePath = new Path(remoteFile);
            FSDataInputStream in = fs.open(remotePath);
            BufferedReader br = new BufferedReader(new InputStreamReader(in));

            judgeString(br);

            br.close();
            in.close();
            fs.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void readHDFS(String remoteFilePath,String chooseStr){
        getJudgeCondition(chooseStr);

        Configuration configuration = new Configuration();
        configuration.set("fs.defaultFS","hdfs://Master:9000");
        configuration.set("fs.hdfs.iml","org.apache.hadoop.hdfs.DistributedFileSystem");
        HDFSCat(configuration,remoteFilePath);
    }

    public void executeIns(String insString){
        try {
            Runtime.getRuntime().exec(insString).waitFor();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void judgeString(BufferedReader bufferedReader) throws IOException{
        String line = null;

        StringBuffer stringBuffer = new StringBuffer();

        while((line=bufferedReader.readLine()) != null){

            if(line.startsWith("BIO")){
                //如果读取所在行以BIO为开始，则进行判断
                if(judgeStrJoin(line)){
                    //如果该IP信息是所需要的，则写入
                    writeFile(stringBuffer,line);
                    stringBuffer.delete(0,stringBuffer.length());
                }else{
                    stringBuffer.delete(0,stringBuffer.length());
                }
            }else {
                stringBuffer.append(line);
                stringBuffer.append("\r\n");
            }
        }
    }

    public void setTimeString(){
        LocalDateTime localDateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        datatime = localDateTime.format(formatter);

    }

}
