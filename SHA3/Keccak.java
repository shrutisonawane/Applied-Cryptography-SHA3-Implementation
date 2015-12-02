import java.util.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.BitSet;


public class Keccak 
{
	//Converts a given string of English language characters to a string of 0's and 1's  
	static String ConvertStringToBinary(String s)
	{
		String binary="";
		try
		{
			byte[] encoded=s.getBytes("US-ASCII");
			for(int i=0;i<s.length();i++)
			{
			  binary += Integer.toBinaryString(s.charAt(i));
			}
			
			//Secure coding rule: EXP00-J followed
			//binary=new BigInteger(s.getBytes("US-ASCII")).toString(2);
			return binary;
		}
		catch(Exception e)
		{
			
		}
		return binary;
	}
	
	static String ConvertBinaryToString(String s)
	{
		//String textString="";
		byte[] bval= new BigInteger(s,2).toByteArray();	
		
		String textString= "";//bval,"UTF_8");
		
		int stringLimit=s.length()-7;
		for(int i=0;i<=stringLimit;i+=7)
		{
          int charCode = Integer.parseInt(s.substring(i, (i+7)), 2);
		  textString += (char)charCode;
		}
		return textString;
	}
	
	//Converts a given string of 0's and 1's to a new BitSet
	static BitSet ConvertBinaryStringToBitSet(String s)
	{
		BitSet B= new BitSet(s.length());
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int i=0;i<s.length();i++)
		{
			//Secure coding rule: EXP52-J followed
			if(s.charAt(i)=='1')
			{
				B.set(i,true);
			}
			else
			{
				B.set(i,false);
			}
		}	
		return B;
	}
	
	//Converts a given BitSet to a string of 0's and 1's
	static String ConvertBitSetToBinaryString(BitSet b)
	{
		String s="";
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int i=0;i<b.size();i++)
		{
			//Secure coding rule: EXP52-J followed
			if(b.get(i)==true){
				s+="1";
			}
			else{
				s+="0";
			}
		}
		return s;
	}
	
	//Creates a new 3D BitSet and returns the BitSet object
	static BitSet[][] Create3DBitSet()
	{
		BitSet[][] X= new BitSet[5][5];
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int x=0;x<5;x++)
		{
			for(int y=0;y<5;y++)
			{
				X[x][y]= new BitSet(64);
			}
		}
		return X;
	}
	
	//Copies given 3D BitSet into another a new BitSet object 
	static BitSet[][] Copy3DBitSet(BitSet A[][])
	{
      BitSet NewBitSet[][]=Create3DBitSet();
      //Secure coding rule: DCL53-J, NUM09-J followed
		for(int x=0;x<5;x++)
		{
			for(int y=0;y<5;y++)
			{
			  for(int z=0;z<64;z++)
			  {
				//Secure coding rule: EXP52-J followed
			    if(A[x][y].get(z)==true){
			    	NewBitSet[x][y].set(z,true);
			    }
			    else{
			    	NewBitSet[x][y].set(z,false);
			    }
			  }
			}
		}
		return NewBitSet;
	}
	
	//Function to perform single bit xoring within a BitSet
	static boolean SingleBitXOR(BitSet B,int i,int j)
	{
		//Secure coding rule: EXP52-J followed
		if(B.get(i)==B.get(j)){
			return false;
		}
		else {
			return true;
		}
		
	}
		
	//Step 1 of the Keccak round function
	static BitSet[][] ThetaStep(BitSet[][] A)
	{
		BitSet OrigA[][]=Copy3DBitSet(A);
		//Secure coding rule: DCL52-J followed
		BitSet[]C= new BitSet[5];
		BitSet[]D= new BitSet[5];
		for(int a=0;a<5;a++)
		{
		  C[a]= new BitSet(64);
		  D[a]= new BitSet(64);
		}
		//Step 1 of theta
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int x=0;x<5;x++)
		{	
			A[x][0].xor(A[x][1]);
			A[x][0].xor(A[x][2]);
			A[x][0].xor(A[x][3]);
			A[x][0].xor(A[x][4]);
			C[x]=A[x][0];			
		} 
		Boolean a=false;
		//copying bitset C into D
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int x=0;x<5;x++)
		{
			for(int z=0;z<64;z++)
			{
			if(C[x].get(z)==true){
				D[x].set(z,true);
			}
			else{
				D[x].set(z,false);
			}
			}
		}
		
		//rotate each lane in C by 1
		for(int x=0;x<5;x++)
		{
			//Secure coding rule: DCL53-J, NUM09-J followed
			for (int z=0;z<64;z++)
			{	
				//Secure coding rule: EXP53-J, NUM02-J, NUM51-J followed
				int i = (((z-1)%64)+64)%64;
				a= D[x].get(i);
				if(a==true){
					C[x].set(z,true);
				}
				else{
					C[x].set(z,false); 
				}
			}
		}
		
	   for(int x=0;x<5;x++)
	   {
		 //Secure coding rule: EXP53-J, NUM02-J, NUM51-J followed
		  D[(((x-1)%5)+5)%5].xor(C[(x+1)%5]); 
	   }
	 //Secure coding rule: DCL53-J, NUM09-J followed
		for(int x=0;x<5;x++) 
		{
			for(int y=0;y<5;y++)
			{
				//Secure coding rule: EXP53-J, NUM02-J, NUM51-J followed
				OrigA[x][y].xor(D[(((x-1)%5)+5)%5]);            
			}		
		}
		return OrigA;
	}
	
	//Step 2 of the Keccak round function
	static BitSet[][] RhoStep(BitSet[][] A)
	{
      BitSet OrigRho[][]=Copy3DBitSet(A);
      //Secure coding rule: DCL52-J followed
		int x=1;
		int y=0;
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int t=0;t<24;t++)
		{
			for(int z=0;z<64;z++)
			{
				//Secure coding rule: EXP53-J, NUM02-J, NUM51-J followed
				int i= (((z-((t+1)*(t + 2))/2)%64)+64)%64;
				if(A[x][y].get(i)==true){
				   OrigRho[x][y].set(z,true);
				}
				else{
					OrigRho[x][y].set(z,false);
				}
				int temp=x;
				x=y;
				//Secure coding rule: EXP53-J, NUM02-J followed
				y=(((2*temp)+(3*y))%5);
			}
		}
				
		return OrigRho;
	}
	
	//Step 3 of the Keccak round function
	static BitSet[][] PiStep(BitSet[][] A)
	{
      BitSet OrigPi[][]=Copy3DBitSet(A);
      //Secure coding rule: DCL53-J, NUM09-J followed	
		for(int x=0;x<5;x++)
		{
			for(int y=0;y<5;y++)
			{
				//Secure coding rule: NUM02-J followed
				OrigPi[x][y]=A[(x+(3*y))%5][x];		
			}
		}					
		return OrigPi;
	}
	
	//Step 4 of the Keccak round function
	static BitSet[][] ChiStep(BitSet[][] A)
	{
        BitSet OrigChi[][]=Copy3DBitSet(A);
        BitSet AllOnes[][]= Create3DBitSet();
        
        //Initializing all values of 3D BitSet to true
        //Secure coding rule: DCL53-J, NUM09-J followed
        for(int x=0;x<5;x++)
		{
			for(int y=0;y<5;y++)
			{  
				for(int z=0;z<64;z++)
				{
        	       AllOnes[x][y].set(z,true);
				}
			}
        }
        
        //NOT operation
        //Secure coding rule: DCL53-J followed
		for(int x=0;x<5;x++)
		{
			for(int y=0;y<5;y++)
			{
				A[x][y].xor(AllOnes[x][y]);
			}
		}
		//AND operation
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int x=0;x<5;x++)
		{
			for(int y=0;y<5;y++)
			{
				//Secure coding rule: NUM02-J followed
				A[(x+1)%5][y].and(OrigChi[(x+2)%5][y]);
			}
		}
		//XOR operation
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int x=0;x<5;x++)
		{
			for(int y=0;y<5;y++)
			{
				//Secure coding rule: NUM02-J followed
				OrigChi[x][y].xor(A[(x+1)%5][y]);
			}
		}		
		return OrigChi;
	}
	
	
	//Round constant function for Step 5: Iota
	static boolean rc(int t)
	{
		if((t%255)==0)
			return true;
		else
		{
			String R="10000000";
			BitSet R1;
			//Secure coding rule: DCL53-J, NUM09-J followed
			for(int i=1;i<(t%255);i++)
			{
				R="0"+R;
				R1=ConvertBinaryStringToBitSet(R);
				R1.set(0,SingleBitXOR(R1,0,8));
				R1.set(4,SingleBitXOR(R1,4,8));
				R1.set(5,SingleBitXOR(R1,5,8));
				R1.set(6,SingleBitXOR(R1,6,8));
				R=ConvertBitSetToBinaryString(R1);
				R=R.substring(0, 8);
			}
			char retValue;
			retValue=R.charAt(0);
			if(retValue=='1'){
			  return true;
			}
			else{ 
				return false;
			}
		}
	}
	
	//Step 5 of the Keccak round function
	static BitSet[][] IotaStep(BitSet[][] A, int iR)
	{
		BitSet[][] OrigIota= Copy3DBitSet(A);
		BitSet RC= new BitSet(64);
		int l=0;
		//Secure coding rule: NUM02-J followed
		l=(int)Math.floor(Math.log(64)/Math.log(2));
		
		for(int j=0;j<l;j++)
		{
			//Secure coding rule: EXP53-J followed
			int temp=(int)((Math.pow(2, j))-1);
			RC.set(temp,(rc(j+(7*iR))));
		}
		OrigIota[0][0].xor(RC);
		return OrigIota;
	}
	
	static BitSet KeccakFunction(BitSet X)
	{
		BitSet S[][]= new BitSet[5][5];
		S=ConvertBitSetTo3DState(X);
		//24 rounds of all 5 steps of Keccak permutation!
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int i=0;i<25;i++)
		{
			S=ThetaStep(S);
			S=RhoStep(S);
			S=PiStep(S);
			S=ChiStep(S);
			S=IotaStep(S,i);
		}
		//convert 3D bitset back to 1D
		return (Convert3DStateToBitSet(S));
	}
	
	static BitSet Convert3DStateToBitSet(BitSet[][] X)
	{
		BitSet S= new BitSet(1600);
		String interimS="";
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int x=0;x<5;x++)
		{
			for(int y=0;y<5;y++)
			{
			  interimS+=ConvertBitSetToBinaryString(X[x][y]);
			}
		}
		S=ConvertBinaryStringToBitSet(interimS);
		return S;
	}
	
	
	static BitSet[][] ConvertBitSetTo3DState(BitSet X)
	{
		BitSet S[][]= Create3DBitSet();
		//Secure coding rule: DCL53-J, NUM09-J followed
		for(int x=0;x<5;x++)
		{
			for(int y=0;y<5;y++)
			{				
				for(int z=0;z<64;z++)
				{
					//Secure coding rule: EXP53-J followed
					int i=(64*((5*y)+x))+z;
					boolean a= X.get(i);
					if(a==true){
					 S[x][y].set(z,true);
					}
					else{
						S[x][y].set(z,false);
					}
				}
			}
		}
		return S;
	}
	
	static String KeccakPad(int r, int m)
	{
		//Secure coding rule: EXP53-J, NUM02-J, NUM51-J followed
		int j=((((-m-2)%r)+r)%r);
		String zeroPad="";
		for(int i=0;i<j;i++)
		{
			zeroPad+="0";
		}
		String P="1"+zeroPad+"1";
		//System.out.println("Pad: "+P);
        return P;
	}
	
	static String SPONGE(String N,int d)
	{
	  int r=576, b=1600;	
	  String P=N+KeccakPad(r,N.length());    //value of r is hardcoded here
	  //int n= (P.length()/r);                 //n= number of input message blocks
	  int c=b-r;
	  BitSet S= new BitSet(1600);             //state array of 'b' bits, here b=1600
	  BitSet C= new BitSet(c);
	  	  
	  for(int x=0;x<P.length();x+=r)
	  {
		  //BitSet P0=new BitSet(r);
		  String P0=(P.substring(x,r));
		  BitSet B0= new BitSet(b);
		  B0=ConvertBinaryStringToBitSet(P0+ConvertBitSetToBinaryString(C));
		  S.xor(B0);
          S=KeccakFunction(S);
	  }
	 //Secure coding rule: DCL52-J followed
	  String z="";
	  String S1="";
	  while(z.length()<d)
	  {
		  S1= ConvertBitSetToBinaryString(S);
		  z = z + S1.substring(0, r);
		  if(z.length()>d)
		  {
			  break;
		  }
		  S=KeccakFunction(S);
	  }
	  return (z.substring(0, d));	  
	}
		
	public static void main (String args[]) throws IOException
	{
		Scanner kbd= new Scanner(System.in);
		System.out.println("\nEnter the text message: ");
		String input=kbd.nextLine();
		//Secure coding rule: EXP03-J followed
		if(input.equals(""))
		{
			System.out.println("Invalid input!");
		}
		else
		{
		  String binary=ConvertStringToBinary(input);	
		  String output="";
		  System.out.println("Entered text in binary: "+"\n"+binary);
		  output=SPONGE(binary,256);
		  String messageDigest1="";
		  messageDigest1=ConvertBinaryToString(output);
		  System.out.println("Final hash value: "+messageDigest1);
		}
		System.out.println("Bye!");
	}//end of main

	
}
















