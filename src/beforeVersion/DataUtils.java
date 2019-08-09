package beforeVersion;

import org.junit.Test;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-24 12:54
 * @description：data tools
 * @modified By：
 * @version:
 */
public class DataUtils {
    public static byte[] IntToByte(int val){
        byte[] res = new byte[4];

        res[0] = (byte) (val & 0xff); //最低位
        res[1] = (byte) ((val >> 8) & 0xff);//次低位
        res[2] = (byte) ((val >> 16) & 0xff);//次高位
        res[3] = (byte) (val >>> 24) ;//最高位；
        return res;
    }

    public static byte[] mergeByte(byte[] bytes,int len){

        byte[] bytes1 = new byte[4-len];
        for(int i=0 ; i < bytes1.length ; i++){
            bytes1[i] = 0;
        }

        byte[] byteRes = new byte[bytes1.length + bytes.length];

        System.arraycopy(bytes1,0,byteRes,0,bytes1.length);

        System.arraycopy(bytes,0,byteRes,bytes1.length,bytes.length);

        return byteRes;
    }

    public static int ByteToInt(byte[] bytes){
        int value=0;
        for(int i = 0; i < 4; i++) {
            int shift= (3-i) * 8;
            value +=(bytes[i] & 0xFF) << shift;
        }
        return value;
    }

    public static int IntToUnByte(int val){

       Byte tmp = (byte) val;
       Integer i = tmp.intValue();

       int res = i & 0xFF;


       return res;
    }

    public static byte[] BytesConversion(byte[] bytes){
        byte[] bytes_res = new byte[bytes.length];
        int j=bytes.length-1;
        for(int i=0 ;i<bytes.length;i++){
            bytes_res[i] = bytes[j];
            j--;
        }

        return bytes_res;
    }

    public static short ByteToShort(byte[] bytes){
        short value = 0;
        for(int i = 0 ; i < 2 ;i++){
            int shift = (1-i) * 8;
            value += (bytes[i] & 0xFF) << shift;
        }

        return value;
    }

    public static String BytesTo2HexStr(byte[] bytes){
        StringBuffer res = new StringBuffer();
        for(int i=0 ; i<bytes.length ; i++){
            res.append(Long.toString(bytes[i] & 0xff,2) + ".");
        }
        return res.toString().substring(0,res.length()-1);
    }

    public static String ByteTo2HexStr(byte b){
        String res = Long.toString(b & 0xff,2);
        return res;
    }

    public static int Hex2StrToInt(String str){
        int res = 0;
        for(int i=0 ; i<str.length();i++){
            if(str.charAt(i) == '1'){
                res += Math.pow(2,str.length()-1-i);
            }
        }

        return res;
    }

    public static String getIP(String str){
        String[] ipStr = str.split("\\.");
        StringBuffer ip = new StringBuffer();
        for(int i=0 ; i<ipStr.length ; i++){
            ip.append(DataUtils.Hex2StrToInt(ipStr[i]));
            if(i<ipStr.length -1){
                ip.append(".");
            }

        }
        //ip.delete(ip.length()-2,ip.length()-1);
        return ip.toString();
    }

    public static int getPort(byte[] bytes){
        byte byte_1 = bytes[0];
        String byte_1_str = ByteTo2HexStr(byte_1);

        if(byte_1_str.length()<8){
            int len = 8-byte_1_str.length();
            for(int i=0;i<len;i++){
                byte_1_str = "0" + byte_1_str;
            }
        }

        byte byte_2 = bytes[1];
        String byte_2_str = ByteTo2HexStr(byte_2);

        if(byte_2_str.length()<8){
            int len_2 = 8-byte_2_str.length();
            for(int j=0;j<len_2;j++){
                byte_2_str = "0" + byte_2_str;
            }
        }

        String tmp = byte_1_str + byte_2_str;

        int res = Hex2StrToInt(tmp);

        return res;

    }

    public static short byteArrayToShort(byte[] b,int offset){
        return (short) (((b[offset] & 0xff) << 8) | (b[offset + 1] & 0xff));
    }

    public static int byteArrayToInt(byte[] bytes, int offset){
        int value= 0;
        //由高位到低位
        for (int i = 0; i < 4; i++) {
            int shift= (4 - 1 - i) * 8;
            value +=(bytes[i] & 0x000000FF) << shift;//往高位游
        }

        return value;
    }

    public static String completionByte(byte b){
        String tmp = ByteTo2HexStr(b);

        int length = tmp.length();
        if(length < 8){
            for(int i=0; i <8-length;i++){
                tmp = "0" + tmp;
            }
        }

        return tmp;
    }

    public static long Hex2ToLong(String str){
        long res = 0;
        for(int i=0 ; i<str.length();i++){
            if(str.charAt(i) == '1'){
                res += Math.pow(2,str.length()-1-i);
            }
        }

        return res;
    }

    public static long getSeq(byte[] bytes){
        long res;
        String tmp ="";
        for(int i=0 ; i<bytes.length;i++){
            tmp += completionByte(bytes[i]);
        }

        res = Hex2ToLong(tmp);

        return res;
    }
    @Test
    public void demoTest(){
//        byte[] bytes = new byte[1];
//
//        bytes[0] = 9;
//
//        byte[] bytes1 = DataUtils.mergeByte(bytes,1);
//
//        for(int i=0 ; i <bytes1.length ; i++){
//            System.out.println(bytes1[i]);
//        }

        int a = 200;

        System.out.println(DataUtils.IntToUnByte(a));

    }


}
