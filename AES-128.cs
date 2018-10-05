/*
 In this program we encrypt a given source file using AES-128 algorithm and store the encrypted contents in another file
 * by calling the encode function. In order to test whether the encrypted version is correct we decrypt the encoded 
 * version in another file and check if the contents of the newly decoded and original source file are one and the same.
 * For the purpose of encryption and decryption we use a common secret key of 16 characters. Each character accounts for 8 bits 
 * when converted to its ASCII equivalent and hence 16 characters of key will occupy 128 bits. For the time being the user enters
 * the 16 character key in the console, but technically speaking the key shold be stored in a separate file stored in a secure 
 * location since it is a symmetric key algorithm. Otherwise, if the bank has its own public key then we can encrypt our key using
 * that public key using asymmetric cryptography. 
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace AES_128
{
    class Program
    {
        static string[] round_key = new string[11];
        static string[,] sbox ={
                               { "63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
                               { "ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
                               { "b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
                               { "04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
	                           { "09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
                               { "53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
                               { "d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
	                           { "51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
	                           { "cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
                               { "60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
	                           { "e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
	                           { "e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
	                           { "ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
                               { "70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
                               { "e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
	                           { "8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
    };

        static string[] key_schedule = { "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" };
        static string hex_to_ascii(string hex)
        {
            string str = "";
            int i;
            for (i = 0; i < hex.Length; i+=2)
            {
                string hexa = "";
                hexa += hex[i];
                hexa += hex[i + 1];
                char ch = (char)hex_to_int(hexa);
                str += ch;
            }
            return str;
        }
        static string int_to_hex(int a) //for 2 character hex
        {
            if (a == 0)
                return "00";
            string hex="";
            while (a != 0)
            {
                int rem = a % 16;
                char ch;
                
                if (rem >= 10)
                    ch = (char)(rem + 87);
                else
                    ch = (char)(rem + 48);

                hex += ch;
                a /= 16;

            }
            char[] arr = hex.ToCharArray();
            Array.Reverse(arr);
            hex = new string(arr);
            if (hex.Length == 1)
                hex = '0' + hex;
            return hex;
        }


        static string int_to_hex1(int a) //hex in 1 character ie for int values from 0 to 15
        {
            if (a == 0)
                return "0";
            string hex = "";
            while (a != 0)
            {
                int rem = a % 16;
                char ch;

                if (rem >= 10)
                    ch = (char)(rem + 87);
                else
                    ch = (char)(rem + 48);

                hex += ch;
                a /= 16;

            }
            char[] arr = hex.ToCharArray();
            Array.Reverse(arr);
            hex = new string(arr);
            
            return hex;
        }

        static int hex_to_int(string hex)
        {
            int val = 0;
            int i,n=hex.Length;
            for (i = 0; i < n; i++)
            {
                int ch;
                if (hex[i] >= '0' && hex[i] <= '9')
                    ch = hex[i] - '0';
                else
                    ch = hex[i] - 87;
                val += ch * (int)Math.Pow(16, n - i - 1);
            }
            return val;
        }



        static int[] hex_to_bin(string hex)
        {
            int[] bin = new int[hex.Length * 4];
            int i,k=0;
            for (i = 0; i < hex.Length; i++)
            {
                int ch,j;
                if (hex[i] >= '0' && hex[i] <= '9')
                    ch = hex[i] - 48;
                else
                    ch = hex[i] - 87;
                

                for ( j = 3; j >= 0; j--)
                {
                    if (ch >= (int)Math.Pow(2, j))
                    {
                        bin[k++] = 1;
                        ch -= (int)Math.Pow(2, j);
                    }
                    else
                        bin[k++] = 0;
                }


            }


            return bin;
        }

        static string bin_to_hex(int[] bin)
        {
            int i; 
            string hex = "";
            for (i = 0; i < bin.Length;)
            {
                int val=0,j;
                for (j = 3; j >= 0; j--)
                    val += bin[i++] * (int)Math.Pow(2, j);

                if (val >= 0 && val <= 9)
                    hex += (char)(val + '0');
                else
                    hex += (char)(val + 87);

            }
            if (hex.Length == 1)
                hex = '0' + hex;
            return hex;
        }

        static string[] circular_left_shift(string[] s,int t)
        {
            string[] str = new string[s.Length];
            int i,j;
            
            for (i = 0; (t + i) < s.Length; i++)
                str[i] = s[t + i];
            for (j = 0; j < t; j++)
                str[i++] = s[j];
            return str;
        }

        static string[] circular_right_shift(string[] s, int t)
        {
            string[] str = new string[s.Length];
            int i, j=0;
            for (i =(4-t); i < s.Length; i++)
                str[j++] = s[i];
            i = 0;
            for (; j < 4; j++)
                str[j] = s[i++];
         
            return str;
        }

        static int[] xor(int[] a, int[] b)//xor operation of 2 binary arrays
        {
            int[] c = new int[a.Length];
            int i;
            for (i = 0; i < a.Length; i++)
                c[i] = (a[i] + b[i]) % 2;
            return c;
        }

        static string[] g(string[] s,int pos)
        {
            int i;
            //circuar byte shifting
            string[] shifted = new string[s.Length];
                shifted=circular_left_shift(s,1);
                

            string[] sub = new string[s.Length];

            

            //byte substitution(s-box)
            for (i = 0; i < s.Length; i++)
            {
                int row,col;
                if (shifted[i][0] >= '0' && shifted[i][0] <= '9')
                    row = shifted[i][0] - 48;
                else
                    row = shifted[i][0] - 87;

                if (shifted[i][1] >= '0' && shifted[i][1] <= '9')
                    col = shifted[i][1] - 48;
                else
                    col = shifted[i][1] - 87;
                sub[i] = sbox[row, col];
                
            }

           

            // adding round constant(01,00,00,00)(hex) to sub
            sub[0] = bin_to_hex(xor(hex_to_bin(key_schedule[pos]), hex_to_bin(sub[0])));

            
            return sub;

        }


        static void key_gen(string key)
        {
            
            int round=0;
            int i, j;
            round_key[round] = "";
           for (i = 0; i < key.Length; i++) //key.Length=16 characters=(16*8=128 bits)
              round_key[round] += int_to_hex(key[i]);
            
            
            for(round=1;round<=10;round++)
            {
                
            round_key[round]= "";
            string[,] w=new string[8,4];

            j = 0;
                int row=0,col=0;
           
            for (i = 0; i < round_key[round - 1].Length; i += 2)
            {
                string hexa="";
                hexa+=round_key[round - 1][i];
                hexa+= round_key[round - 1][i + 1];
                w[row, col] = "";
                w[row, col] = hexa;
                col = (col + 1) % 4;
                if (col == 0) row++;

            }
           


            string[] temp1=new string[4];

           
            for (i = 0; i < 4; i++)
            {
                temp1[i] = w[3, i];
              
            }
            temp1 = g(temp1,round-1);

           

            for (i = 0; i < 4; i++)
            {
                w[4, i] = bin_to_hex(xor(hex_to_bin(temp1[i]), hex_to_bin(w[0, i])));
                w[5, i] = bin_to_hex(xor(hex_to_bin(w[4, i]), hex_to_bin(w[1, i])));
                w[6, i] = bin_to_hex(xor(hex_to_bin(w[5, i]), hex_to_bin(w[2, i])));
                w[7, i] = bin_to_hex(xor(hex_to_bin(w[6, i]), hex_to_bin(w[3, i])));
            }

            
            round_key[round] = "";
            for (i = 4; i < 8; i++)
                for (j = 0; j < 4; j++)
                {
                    round_key[round] += w[i, j];
                }
          

       }
           
            

        }

        static string mul(int a, string s)
        {
            int i;
            string str;
            if (a == 1)
                return s;
            int[] bin = hex_to_bin(s);
            
            int[] bin1 = new int[bin.Length];
            
            
            for (i = 1; i < bin.Length; i++)
                bin1[i - 1] = bin[i];
            
            bin1[i - 1] = 0;

           
            str = bin_to_hex(bin1);
            
            if (bin[0] == 1)
                str = bin_to_hex(xor(hex_to_bin(str),hex_to_bin("1b")));

            if(a==3)
                str = bin_to_hex(xor(hex_to_bin(str), bin));
           
            return str;
            
        }
        static string inverse_mul(int a, string s)
        {
            string str=mul(2,s);
            if (a == 9)
            {
                str = mul(2, str);
                str = mul(2, str);
                str = bin_to_hex(xor(hex_to_bin(str), hex_to_bin(s)));
            }
            else if (a == 11)
            {
                str = mul(2, str);
                str = bin_to_hex(xor(hex_to_bin(str), hex_to_bin(s)));
                str = mul(2, str);
                str = bin_to_hex(xor(hex_to_bin(str), hex_to_bin(s)));
            }
            else if (a == 13)
            {
                str = bin_to_hex(xor(hex_to_bin(str), hex_to_bin(s)));
                str = mul(2, str);
                str = mul(2, str);
                str = bin_to_hex(xor(hex_to_bin(str), hex_to_bin(s)));
                
            }
            else if (a == 14)
            {
                str = bin_to_hex(xor(hex_to_bin(str), hex_to_bin(s)));
                str = mul(2, str);
                str = bin_to_hex(xor(hex_to_bin(str), hex_to_bin(s)));
                str = mul(2, str);
            }

            return str;

        }

       static string[,] mix_col(string[,] state, int[,] matrix)
        {
            int i,j,k;
            string[,] next_state=new string[4,4];
           

           for(i=0;i<4;i++)
               for (j = 0; j < 4; j++)
               {
                   string result;
                   for (k = 0; k < 4; k++)
                   {
                       
                       result = mul(matrix[i, k], state[k, j]);
                       if(k==0)
                           next_state[i, j] = result;
                       else
                           next_state[i, j] = bin_to_hex(xor(hex_to_bin(result), hex_to_bin(next_state[i,j])));
                   }
                   
               }
            return next_state;
        }

       static string[,] inverse_mix_col(string[,] state, int[,] matrix)
       {
           int i, j, k;
           string[,] prev_state = new string[4, 4];
           for (i = 0; i < 4; i++)
               for (j = 0; j < 4; j++)
               {
                   string result;
                   for (k = 0; k < 4; k++)
                   {

                       result = inverse_mul(matrix[i, k], state[k, j]);
                       if (k == 0)
                           prev_state[i, j] = result;
                       else
                           prev_state[i, j] = bin_to_hex(xor(hex_to_bin(result), hex_to_bin(prev_state[i, j])));
                   }

               }
           return prev_state;

       }

        static string[,] transform(string[,] state, string[,] key,int round)
        {
            string[,] next_state = new string[4, 4];
            int i, j;
            


            //substitution
            for(i=0;i<4;i++)
                for (j = 0; j < 4; j++)
                {
                    int row, col;
                    string hexa=state[i,j];
                    if (hexa[0] >= '0' && hexa[0] <= '9')
                        row = hexa[0] - 48;
                    else
                        row = hexa[0] - 87;

                    if (hexa[1] >= '0' && hexa[1] <= '9')
                       col = hexa[1] - 48;
                    else
                        col = hexa[1] - 87;

                    next_state[i, j] = sbox[row, col];
         
                }

           
            //cyclic left shift
            for (i = 0; i < 4; i++)
            {
                string[] temp = new string[4];
                for (j = 0; j < 4; j++)
                    temp[j] = next_state[i, j];

                temp = circular_left_shift(temp, i);

                for (j = 0; j < 4; j++)
                    next_state[i, j] = temp[j];
            
            }

            
           

            //mix_col



            if (round != 10)
            {
                int[,] matrix ={
                                 {2,3,1,1},
                                 {1,2,3,1},
                                 {1,1,2,3},
                                 {3,1,1,2}
                          };
                next_state = mix_col(next_state, matrix);
            }
           

            //state xor key

            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                    next_state[i, j] = bin_to_hex(xor(hex_to_bin(next_state[i, j]), hex_to_bin(key[i, j])));

           
            return next_state;
        }

        static string[,] inverse_transform(string[,] state, string[,] key, int round)
        {
            string[,] prev_state= new string[4,4];
            int i,j;
         

            //state xor with key (inverse)

            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                    prev_state[i, j] = bin_to_hex(xor(hex_to_bin(state[i, j]), hex_to_bin(key[i, j])));

         

            //inverse mix col
            if (round != 10)
            {
                int[,] matrix ={
                                 {14,11,13,9},
                                 {9,14,11,13},
                                 {13,9,14,11},
                                 {11,13,9,14}
                          };
                prev_state = inverse_mix_col(prev_state, matrix);

                 
            
            }




            //inverse shift rows
            for (i = 0; i < 4; i++)
            {
                string[] temp = new string[4];
                for (j = 0; j < 4; j++)
                    temp[j] = prev_state[i, j];

                temp = circular_right_shift(temp, i);

                for (j = 0; j < 4; j++)
                    prev_state[i, j] = temp[j];

            }

            

            //inverse-substitute byte
            for(i=0;i<4;i++)
                for (j = 0; j < 4; j++)
                {
                    int row=0,col=0;

                    string hexa = "";
                    for (row = 0; row < 16; row++)
                    {
                        for (col = 0; col < 16; col++)
                            if (sbox[row, col] == prev_state[i, j])
                                break;
                        if (col != 16)
                            break;
                    }
                    hexa += int_to_hex1(row);
                    hexa += int_to_hex1(col);
                    prev_state[i, j] = hexa;
                    
                }

            

            return prev_state;
        }



        static string encrypt(string key, string plain) //plain text as normal ascii text
        {

            
            key_gen(key);
            string[,] state = new string[4, 4];
            string[,] roundkey_mat = new string[4, 4];

            int i,j,round;
            //populating state matrix
            int row=0,col=0;
            for (i = 0; i < plain.Length; i++) //plain.Length=16 characters=(16*8=128 bits)
            {
                state[row,col]= int_to_hex(plain[i]);
                row = (row + 1) % 4;
                if (row == 0)
                    col++;
            }

            
            //populating roundkey_mat
            row = 0; col = 0; round = 0;
            for (i = 0; i < round_key[round].Length; i += 2)
            {
                string hexa = "";
                hexa += round_key[round][i];
                hexa += round_key[round][i + 1];
                roundkey_mat[row, col] = hexa;
                row = (row + 1) % 4;
                if (row == 0)
                    col++;
            }
            //round 0 xor alone
            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                    state[i, j] = bin_to_hex(xor(hex_to_bin(state[i, j]), hex_to_bin(roundkey_mat[i, j])));

            
           

            for (round = 1; round < 11; round++)
            {

                

                //populating roundkey_mat
                row = 0; col = 0;
                for (i = 0; i < round_key[round].Length; i += 2)
                {
                    string hexa="";
                    hexa+= round_key[round][i];
                    hexa+= round_key[round][i+1];
                    roundkey_mat[row, col] = hexa;
                    row = (row + 1) % 4;
                    if (row == 0)
                        col++;
                }

                state = transform(state, roundkey_mat,round);
                


               
            }

            String cipher = "";
            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                    cipher += state[j, i];


            return hex_to_ascii(cipher);
         

        }

        static string decrypt(string key, string ciphertext) //ciphertext as normal ascii text
        {
            int i, j, round;
            string cipher = "";
            
            for (i = 0; i < ciphertext.Length;i++)
             cipher += int_to_hex(ciphertext[i]);
            
            string plain="";
            key_gen(key);
            string[,] state = new string[4, 4];
            string[,] roundkey_mat = new string[4, 4];
            
            //populating state matrix
            int row = 0, col = 0;
            for (i = 0; i < cipher.Length; i+=2) //cipher.Length=32 characters=(32*4=128 bits)
            {
                string hexa = "";
                hexa += cipher[i];
                hexa += cipher[i + 1];
                state[row, col] = hexa;
                row = (row + 1) % 4;
                if (row == 0)
                    col++;
            }
            
            for (round = 10; round >= 1; round--)
            {
                //populating roundkey_mat
                row = 0; col = 0;
                for (i = 0; i < round_key[round].Length; i += 2)
                {
                    string hexa = "";
                    hexa += round_key[round][i];
                    hexa += round_key[round][i + 1];
                    roundkey_mat[row, col] = hexa;
                    row = (row + 1) % 4;
                    if (row == 0)
                        col++;
                }

                state = inverse_transform(state, roundkey_mat, round);
                
            

            }

            //populating roundkey_mat
            row = 0; col = 0; round = 0;
            for (i = 0; i < round_key[round].Length; i += 2)
            {
                string hexa = "";
                hexa += round_key[round][i];
                hexa += round_key[round][i + 1];
                roundkey_mat[row, col] = hexa;
                row = (row + 1) % 4;
                if (row == 0)
                    col++;
            }

            //round 0 xor alone
            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                    state[i, j] = bin_to_hex(xor(hex_to_bin(state[i, j]), hex_to_bin(roundkey_mat[i, j])));


            

            plain=""; //plain text as ascii text
            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++)
                {
                    char ch = (char)hex_to_int(state[j, i]);
                    plain += ch;
         
                }

            

          return plain;
        }

        static void encode(string source,string encoded,string key)
        {
         
            string plain="";
            char ch; int i;
         StreamReader sr = new StreamReader(source);
         StreamWriter sw = new StreamWriter(encoded);
         
           
       
                while(!sr.EndOfStream)
                {
                ch=(char)sr.Read();
                
                plain+=ch;
                if(plain.Length==16)
                { 
        
                    string temp = encrypt(key, plain);
                    sw.Write(temp);
                    plain="";
                   
                }

                }
            
             if(plain.Length>0&&plain.Length<16)
                {
                    for(i=plain.Length;i<16;i++)
                        plain+=' ';
                    string temp = encrypt(key, plain);
                    sw.Write(temp);
                }

            

             sr.Close();
             sw.Close();

        }

        static void decode(string encoded,string decoded,string key)
        {
            string cipher = "";
             StreamReader sr = new StreamReader(encoded);
             StreamWriter sw = new StreamWriter(decoded);
            
            cipher = "";
             while (!sr.EndOfStream)
             {
                 char ch = (char)sr.Read();
                 cipher += ch;
                 if (cipher.Length == 16)
                 { 
                     string temp = decrypt(key, cipher);
                     sw.Write(temp);
                     cipher = "";
                 }

             }

             
             sr.Close();
             sw.Close();
           
         
            
        }



         static void Main(string[] args)
        {
            string source, encoded, decoded,key;
            Console.Write("\nEnter full path of source file to be encoded: ");
            source = Console.ReadLine();
            Console.Write("\nEnter full path of destination encoded file: ");
            encoded = Console.ReadLine();
            Console.Write("\nEnter full path of destination decoded file: ");
            decoded = Console.ReadLine();
            Console.Write("\nEnter the  key (16 characters): ");
            key = Console.ReadLine();
            encode(source, encoded,key);
            decode(encoded, decoded, key);
        }

    }
}

//reference: https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf