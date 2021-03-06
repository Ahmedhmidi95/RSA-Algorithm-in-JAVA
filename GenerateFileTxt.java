import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Random;

public class GenerateFileTxt {

/**
    ** Author: Ahmed HMIDI
    ** Generate a random file with given words number and return count value for size (octets)
    ** To test RSA algorithm on it !
**/
public static void main(String[] args) {

    long count=0;
    int WORDS_NUMBER=0;
    try{
            WORDS_NUMBER =Integer.parseInt(args[0]);
    }catch(Exception e){
            System.out.println("Enter a valid integer for words number !");
            System.out.println(e.toString());
            return;
    }

    try{

        File file = new File("bigfile.txt");
        PrintWriter writer = new PrintWriter(file, "UTF-8");


        Random random = new Random();
        for(int i = 0; i < WORDS_NUMBER; i++)
        {           
            char[] word = new char[random.nextInt(8)+3];
            count+=word.length;
            for(int j = 0; j < word.length; j++)
            {
                word[j] = (char)('a' + random.nextInt(26));

            }
            writer.print(new String(word) + ' ');
            count+=1;
            if (i % 10 == 0){
                writer.println();
                count+=2;

            }
        }


        writer.close();
    } catch (IOException e) {
       // do something
    }




    System.out.println(count);

}

}