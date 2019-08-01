package analyzePacp;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-30 12:14
 * @description：
 * @modified By：
 * @version:
 */
public class DataTools {
    public static byte[] intToByte(int val){
        byte[] res = new byte[4];

        res[0] = (byte) (val >>> 24) ;//最高位；
        res[1] = (byte) ((val >> 16) & 0xff);//次高位
        res[2] = (byte) ((val >> 8) & 0xff);//次低位
        res[3] = (byte) (val & 0xff); //最低位
        return res;
    }

    public static int bytesToInt (byte[] bytes){
        int value=0;
        for(int i = 0; i < 4; i++) {
            int shift= (3-i) * 8;
            value +=(bytes[i] & 0xFF) << shift;
        }
        return value;
    }

    public static String byteTo2HexStr(byte b){
        String res = Long.toString(b & 0xff,2);
        int len;
        if((len= res.length()) < 8){
            for(int i=0; i< 8-len;i++){
                res = "0"+res;
            }
        }
        return res;
    }

    public static int hex2StrToInt(String string){
        int result = 0;
        int i ;
        for(i=0 ; i<string.length();i++){
            if(string.charAt(i) == '1'){
                result += Math.pow(2,string.length()-1-i);
            }
        }

        return result;
    }

    public static int calIntNum(byte[] bytes,int off,boolean flag){
        byte[] byte_4 = new byte[4];
        for(int i=0 ; i<4 ;i++){
            byte_4[i] = bytes[i+off];
        }
        //代表需要反序计算
        if(flag){
            byte_4 = bytesConver(byte_4);
        }

        int res = bytesToInt(byte_4);
        return res;
    }

    public static byte[] bytesConver(byte[] bytes){
        byte[] b = new byte[bytes.length];
        int j = bytes.length-1;
        for(int i=0; i<bytes.length;i++){
            b[i] = bytes[j];
            j--;
        }
        return b;
    }

    public static String bytesTo2HexStr(byte[] bytes){
        StringBuffer res = new StringBuffer();
        for(int i=0 ; i<bytes.length ; i++){
            res.append(Long.toString(bytes[i] & 0xff,2) + ".");
        }
        return res.toString().substring(0,res.length()-1);
    }

    public static String getIP(String str){
        String[] ipStr= str.split("\\.");
        StringBuffer ip = new StringBuffer();

        for(int i=0 ; i<ipStr.length ;i++){
            ip.append(hex2StrToInt(ipStr[i]));
            ip.append(".");
        }


        return ip.toString().substring(0,ip.length()-1);
    }

    public static int getPort(byte[] bytes){
        byte byte_1 = bytes[0];
        byte byte_2 = bytes[1];

        String byte_1_str = byteTo2HexStr(byte_1);
        String byte_2_str = byteTo2HexStr(byte_2);

        String tmp = byte_1_str + byte_2_str;

        int res = hex2StrToInt(tmp);
        return res;
    }

    public static long getSeq(byte[] bytes){
        long res;
        String tmp = "";

        for(int i=0 ; i<bytes.length;i++){
            tmp += byteTo2HexStr(bytes[i]);
        }

        res = hex2ToLong(tmp);
        return  res;
    }

    public static long hex2ToLong(String string){
        long result = 0;
        for(int i=0 ; i<string.length();i++){
            if(string.charAt(i) == '1'){
                result += Math.pow(2,string.length()-1-i);
            }
        }

        return result;
    }

    public static long getTime(int time){
        byte[] bytes = intToByte(time); //左高右低

        long res = getSeq(bytes);

        return res;
    }
}
