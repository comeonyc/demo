import java.util.Scanner;

/**
 * @author ：YangChen
 * @date ：Created in 2019-07-08 00:50
 * @description：TODO
 * @modified By：
 * @version: 1
 */
public class test {
    public static void main(String[] args) {
        searchInHDFS search = new searchInHDFS();
        String chooseStr = new String();
        //String insString = new String();

        String remoteFilePath = new String();

        Scanner scanner = new Scanner(System.in);
        System.out.println("enter the file path :");
        //insString = "hadoop dfs -cat " + scanner.nextLine() + " >./data.txt" ;
        remoteFilePath = scanner.nextLine();

        //search.executeIns(insString);

        System.out.println("enter source IP：");
        chooseStr = " "+scanner.nextLine();
        System.out.println("enter aim IP : ");
        chooseStr = chooseStr + "|" + " " + scanner.nextLine();
        System.out.println("enter source port:");
        chooseStr = chooseStr + "|" + " " + scanner.nextLine();
        System.out.println("enter aim port:");
        chooseStr = chooseStr + "|" + " " + scanner.nextLine();
        System.out.println("enter the start time : ");
        chooseStr = chooseStr + "|" + " " + scanner.nextLine();


        System.out.println(chooseStr);
        search.setTimeString();

        search.readHDFS(remoteFilePath,chooseStr);
        //search.openAndWrite("data.txt",chooseStr);
    }
}
