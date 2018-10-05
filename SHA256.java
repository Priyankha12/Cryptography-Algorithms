/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
// reference: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
package sha.pkg256;

/**
 *
 * @author Dell
 */
public class SHA256 {

    /**
     * @param args the command line arguments
     */
   
           
   static int[] int_to_bin(int a,int b)
   {
        int[] bin=new int[b];
        //initialize all b bits to zero
        int i=0;
        for(i=0;i<b;i++)
            bin[i]=0;
        for(i=b-1;i>=0&&a>0;i--)
        {
            bin[i]=a%2;
            a/=2;
        }
        return bin;
   }
   
   
   
   static char bin_to_hex(int[] bin)
   {
       int val=0,i;
       char ch;
       for(i=0;i<4;i++)
           val+=bin[i]*(int)Math.pow(2,3-i);
       if(val>=10)
           ch=(char)(val+87);
       else
           ch=(char)(val+48);
       return ch;
   }
   
   static int and(int a,int b)
   {
       if(a==0||b==0)return 0;
       return 1;
   }
   static int not(int a)
   {
       if(a==0)return 1;
       return 0;
   }
   
   static int[] Ch(int[] x, int[] y,int[] z)
   {
       int[] result=new int[32];
       int i;
       for(i=0;i<32;i++)
           result[i]=(and(x[i],y[i])+and(not(x[i]),z[i]))%2;
       return result;
   }
   
   static int[] Maj(int[] x, int[] y,int[] z)
   {
       int[] result=new int[32];
       int i;
       for(i=0;i<32;i++)
           result[i]=(and(x[i],y[i])+and(x[i],z[i])+and(y[i],z[i]))%2;
        return result;
   }
   
   static int[] R(int[] x, int n)
   {
       int[] result=new int[32];
       int i;
       for(i=0;i<n;i++)
           result[i]=0;
       
      for(int j=0;j<(32-n);j++) 
          result[i++]=x[j];
      return result;
   }
   
    static int[] S(int[] x, int n)
   {
       int[] result=new int[32];
       int i;
       for(i=0;i<n;i++)
           result[i]=x[32-(n-i)];
      for(int j=0;j<(32-n);j++) 
          result[i++]=x[j];
      return result;
   }
    
    static int[] Sig0(int[] x)
    {
        int[] result=new int[32];
        int[] S2=S(x,2);
        int[] S13=S(x,13);
        int[] S22=S(x,22);
        for(int i=0;i<32;i++)
            result[i]=(S2[i]+S13[i]+S22[i])%2;
        return result;
    }
    
    static int[] Sig1(int[] x)
    {
        int[] result=new int[32];
        int[] S6=S(x,6);
        int[] S11=S(x,11);
        int[] S25=S(x,25);
        for(int i=0;i<32;i++)
            result[i]=(S6[i]+S11[i]+S25[i])%2;
        return result;
    }
   
   static int[] S0(int[] x)
    {
        int[] result=new int[32];
        int[] S7=S(x,7);
        int[] S18=S(x,18);
        int[] R3=R(x,3);
        for(int i=0;i<32;i++)
            result[i]=(S7[i]+S18[i]+R3[i])%2;
        return result;
    }
   static int[] S1(int[] x)
    {
        int[] result=new int[32];
        int[] S17=S(x,17);
        int[] S19=S(x,19);
        int[] R10=R(x,10);
        for(int i=0;i<32;i++)
            result[i]=(S17[i]+S19[i]+R10[i])%2;
        return result;
    }
   
   static int[] add32(int[] a,int[] b)
   {
       int i,c=0;
       int[] result=new int[32];
       for(i=31;i>=0;i--)
       {
           result[i]=(a[i]+b[i]+c)%2;
           c=(int)((a[i]+b[i]+c)/2);
       }
       return result;
   }
    
    
        
        public static String SHA256(String plain)
        {
        int[] M=new int[512];
        int i,j=0,k,l;
        
        
        
        //pre-processing
        for(i=0;i<plain.length();i++)
        {
            int[] bin=int_to_bin((int)plain.charAt(i),8); //ascii
            for(k=0;k<8;k++)
                M[j++]=bin[k];
        }
        l=j;
        //padding 1
        M[j++]=1;
        
        //padding zeroes
        //assuming we don't get a l>447
        for(k=1;k<=(447-l);k++)
            M[j++]=0;
        
        int[] temp1=int_to_bin(l,64);
        for(k=0;k<64;k++)
            M[j++]=temp1[k];
        
        
        
        
        //initiallization of intermediate hash values
        //these 8 values represent the fractional part(1st 32 bits) of square roots of first 8 primes
        
        String[] Hash={
            "6a09e667","bb67ae85","3c6ef372","a54ff53a","510e527f","9b05688c","1f83d9ab","5be0cd19"
        };
        
        //these 64 values represent the fractional part(1st 32 bits) of cube roots of first 64 primes
        String[] Keys={"428a2f98","71374491","b5c0fbcf","e9b5dba5","3956c25b","59f111f1","923f82a4","ab1c5ed5",
        "d807aa98","12835b01","243185be","550c7dc3", "72be5d74", "80deb1fe","9bdc06a7","c19bf174",
        "e49b69c1","efbe4786","0fc19dc6","240ca1cc","2de92c6f","4a7484aa","5cb0a9dc","76f988da",
        "983e5152","a831c66d","b00327c8","bf597fc7","c6e00bf3","d5a79147","06ca6351","14292967",
        "27b70a85","2e1b2138","4d2c6dfc","53380d13","650a7354","766a0abb","81c2c92e","92722c85",
        "a2bfe8a1","a81a664b","c24b8b70","c76c51a3","d192e819","d6990624","f40e3585","106aa070",
        "19a4c116","1e376c08","2748774c","34b0bcb5","391c0cb3","4ed8aa4a","5b9cca4f","682e6ff3",
        "748f82ee","78a5636f","84c87814","8cc70208","90befffa","a4506ceb","bef9a3f7","c67178f2"
        };
        
        
        //main algo
        int[][] reg=new int[8][32]; //8 registers for a-h
      
        //init reg
        for(i=0;i<8;i++)
        { 
            k=0;
            for(j=0;j<8;j++)
            {
              int value;
              if(Hash[i].charAt(j)>='a'&&Hash[i].charAt(j)<='f')
                  value=Hash[i].charAt(j)-87;
              else
                  value=Hash[i].charAt(j)-48;
              
            int[] bin=int_to_bin(value,4);
            for(int m=0;m<4;m++)
                reg[i][k++]=bin[m];
                    
            }
        }
        
        
     
        
        
        //compression
        j=0;
        int[][] W= new int[64][32];  
        for(i=0;i<16;i++)
         for(k=0;k<32;k++)
                {
                   W[i][k]=M[j++];
                }
        
        for(i=16;i<64;i++)
        {
            
                W[i]=add32(S1(W[i-2]),W[i-7]);
                W[i]=add32(W[i],S0(W[i-15]));
                W[i]=add32(W[i],W[i-16]);
        }
            
        
        j=0;
        
        for(i=0;i<64;i++)
        {
            int[] T1=new int[32];
            int[] T2=new int[32];
            int[] ch=Ch(reg[4],reg[5],reg[6]);
            int[] maj=Maj(reg[0],reg[1],reg[2]);
            int[] sig0=Sig0(reg[0]);
            int[] sig1=Sig1(reg[4]);
            int[] w=new int[32];
            w=W[i];
            
            
            int[] K=new int[32];
            k=0;
            for(int m=0;m<8;m++)
            {
                int value;
                if(Keys[i].charAt(m)>='a'&&Keys[i].charAt(m)<='f')
                    value=Keys[i].charAt(m)-87;
                else
                    value=Keys[i].charAt(m)-48;
               int[] bin=int_to_bin(value,4);
                 
                 for(value=0;value<4;value++)
                     K[k++]=bin[value];
            }
            
            
            T1=add32(reg[7],sig1);
            T1=add32(T1,ch);
            T1=add32(T1,K);
            T1=add32(T1,w);
            T2=add32(sig0,maj);
            
           
           reg[7]=reg[6];
           reg[6]=reg[5];
           reg[5]=reg[4];
           
           reg[4]=add32(reg[3],T1);
           
           reg[3]=reg[2];
           reg[2]=reg[1];
           reg[1]=reg[0];
           reg[0]=add32(T1,T2);
           
          
           
            
        }
        
        
        int[] H=new int[32];
        String Sha="";
        for(i=0;i<8;i++)
        {
           k=0;
            for(int m=0;m<8;m++)
            {
                int value;
                if(Hash[i].charAt(m)>='a'&&Hash[i].charAt(m)<='f')
                    value=Hash[i].charAt(m)-87;
                else
                    value=Hash[i].charAt(m)-48;
                 int[] bin=int_to_bin(value,4);
                 
                 for(value=0;value<4;value++)
                     H[k++]=bin[value];
            }
        H=add32(reg[i],H);
        String hash="";
        for(j=0;j<32;)
        {
            int[] bin=new int[4];
            for(k=0;k<4;k++)
                bin[k]=H[j++];
            hash+=bin_to_hex(bin);
       
        }
        
        Sha+=hash;
        }
        
    return Sha;
        
    }
        
}