import org.junit.Test;

import java.io.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-10 18:46
 * @description：找到与正则表达式匹配的部分
 * @modified By：
 * @version: 1
 */
public class AnalyzeRes {

    public String judgeConditionAndGetString(String resInfo){
        int start = resInfo.indexOf("eth_payload");
        int end = resInfo.length();

        String analyzedPayloadString = resInfo.substring(start,end);
        String analyzedFile = resInfo.split("\\s")[0];
        String matchedString = " ";
        switch (analyzedFile){
            case "BIO001-GENE_BED" :
                matchedString = analyzedFile + " : " + getMatchedBedString(analyzedPayloadString);
                break;
            case "BIO001-GENE_BEDGRAPH" :
                matchedString = analyzedFile + " : "+ getMatchedBedGraphString(analyzedPayloadString);
                break;
            case "BIO001-GENE_CHAIN":
                matchedString = analyzedFile + " : " + getMatchedChainString(analyzedPayloadString);
                break;
            case "BIO001-GENE_NET" :
                matchedString = analyzedFile + " : " + getMatchedNetString(analyzedPayloadString);
                break;
            default:
                matchedString = analyzedFile + " : "+ "Now there is not regular of the gene file.";
                break;
        }

        return matchedString;
    }



    public void readAndWriteFile(String fileName){

        try {
            FileReader fileReader  = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            String resInfo = null;

            String matchedString = " ";

            while((resInfo = bufferedReader.readLine())!= null){
                matchedString = judgeConditionAndGetString(resInfo);
                writeFile(matchedString,resInfo,fileName);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e){
            e.printStackTrace();
        }


    }

    public String getMatchedBedString(String payloadInfo) {

        String RegExp = null;
        RegExp = "[cC]hr\\d{1,2}[\\s\\S]\\d{1,12}[\\s\\S]\\d{1,12}";
        String matchedString = null;
        if (!(matchedString = getMatchedString(RegExp, payloadInfo)).equals(" ")) {
            return matchedString;
        } else {
            RegExp = "[cC]hr[CLMRTWXY][\\s\\S]\\d{1,12}[\\s\\S]\\d{1,12}";
            if (!(matchedString = getMatchedString(RegExp, payloadInfo)).equals(" ")) {
                return matchedString;
            }
        }
        return matchedString;

    }

    public String getMatchedBedGraphString(String payloadInfo){
        String RegExp = null;
        RegExp = "[cC]hr\\d{1,2}[\\s\\S]\\d{1,12}[\\s\\S]\\d{1,12}[\\s(\\S\\d{1,2})]\\-{0,1}\\d{1,3}\\.\\d{1,19}";
        String matchedString = null;
        if(!(matchedString = getMatchedString(RegExp, payloadInfo)).equals(" ")) {
            return matchedString;
        }else {
            RegExp = "[cC]hr\\d{1,2}[CLMRTWXY][\\s\\S]\\d{1,12}[\\s\\S]\\d{1,12}[\\s(\\S\\d{1,2})]\\-{0,1}\\d{1,3}\\.\\d{1,19}";
            if (!(matchedString = getMatchedString(RegExp, payloadInfo)).equals(" ")) {
                return matchedString;
            }else{
                RegExp = "[cC]hr[CLMRTWXY][\\s\\S]\\d{1,12}[\\s\\S]\\d{1,12}[\\s(\\S\\d{1,2})]\\-{0,1}\\d{1,3}\\.\\d{1,19}";
                if(!(matchedString = getMatchedString(RegExp,payloadInfo)).equals(" ")){
                    return matchedString;
                }else{
                    RegExp = "track\\stype=bedGraph\\sname='[a-zA-z0-9 \\_]*'\\sdescription='[a-zA-z0-9 \\_]*'";
                    if(!(matchedString = getMatchedString(RegExp,payloadInfo)).equals(" ")) {
                        return matchedString;
                    }
                }

            }
        }
        return matchedString;

    }

    public String getMatchedChainString(String payloadInfo){
        String RegExp = null;
        RegExp = "chain\\s\\d{1,3}\\S\\d{1,12}chr\\d{1,2}\\S\\d{1,12}";
        String matchedString = null;
        if (!(matchedString = getMatchedString(RegExp, payloadInfo)).equals(" ")) {
            return matchedString;
        } else {
            RegExp = "chain\\s\\d{1,3}\\S\\d{1,12}chr[CLMRTWXY]\\S\\d{1,12}";
            if (!(matchedString = getMatchedString(RegExp, payloadInfo)).equals(" ")) {
                return matchedString;
            }else{
                RegExp = "chain\\s\\d{1,3}\\S\\d{1,12}chr\\d{1,2}[CLMRTWXY]\\S\\d{1,12}";
                if (!(matchedString = getMatchedString(RegExp, payloadInfo)).equals(" ")) {
                    return matchedString;
                }
            }
        }
        return matchedString;
    }

    public String getMatchedNetString(String payloadInfo){
        String RegExp = null;
        RegExp = "net\\schr[0-9LXY]{1,2}\\s\\d{1,12}";
        String matchedString = null;
        if (!(matchedString = getMatchedString(RegExp, payloadInfo)).equals(" ")) {
            return matchedString;
        }
        return matchedString;

    }

    public String getMatchedString(String RegExp,String payloadInfo){
        Pattern pattern = Pattern.compile(RegExp);
        Matcher matcher = pattern.matcher(payloadInfo);
        String matchedString = " ";
        if(matcher.find()){
            matchedString = matcher.group();
        }


        return matchedString;
    }

    public void writeFile(String matchedStr,String resInfo,String filename){


        String newResInfo  = resInfo + "\t" + matchedStr;

        String newFileName = "copy_" + filename+".txt";

        File file = new File(newFileName);
        FileWriter fileWriter = null;

        try {
            if(!file.exists()){
                file.createNewFile();
                fileWriter = new FileWriter(file);
                String title = "事件名\t源IP\t目的IP\t源端口\t目的端口\t协议\t时间\t返回值\t匹配串";
                fileWriter.write(title);
                fileWriter.write("\n");
            }else {
                fileWriter = new FileWriter(file,true);
                fileWriter.write("\n");
            }

            fileWriter.write(newResInfo);
            fileWriter.flush();
            fileWriter.close();

        }catch (IOException e){
            e.printStackTrace();
        }
    }




    @Test
    public void testFunc(){
        readAndWriteFile("data.res");
    }

    @Test
    public void test(){
        System.out.println("------------");
    }


}
