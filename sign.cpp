#include <string.h>
#include <iostream>
#include <fstream>
#include <math.h>
#include "sha256.h"
#include "BigIntegerLibrary.hh"

using std::string;
using std::cout;
using std::endl;

//Fermat test to be used with bigUnsigned integers
bool Fermat(BigUnsigned big) {
   //if the bigUnsigned value is 1, return false
   if (big == 1)
      return false;
   //test three random values to see if the number is mostly prime
   for (int i = 0; i < 3; i++) {
      BigUnsigned a = (rand()%4000);
      if (modexp(a, (big - 1), big) != 1)
         return false;
   }
   return true;
}

int main(int argc, char *argv[])
{
   if (argc != 3 || (argv[1][0]!='s' && argv[1][0]!='v'))
      cout << "wrong format! should be \"sign.exe s filename\" or \"sign.exe v filename\"\n";
   else {
      //generate rsa values
//////////////////////////////////////////////////////////////////////////////

      //attempt to open the files containing p, q, e, d, and n
      std::fstream filepq, fileen, filedn;
      filepq.open("p_q.txt");
      fileen.open("e_n.txt");
      filedn.open("d_n.txt");
      //if they do not exist, generate them
      if (filepq.fail() || fileen.fail() || filedn.fail()) {
         //generate p
         BigUnsigned p = BigUnsigned(1);
         for (int i = 0; i < 400; i++) {
            p = p * 10 + rand();
         }
         //use Fermat test if p is prime
         //if it is not then re-generate p until it is
         while(!(Fermat(p))) {
            cout << "Working...\n";
            p = 0;
            for (int i = 0; i < 400; i++) {
               p = p * 10 + rand();
            }
         }
         cout << "Generated prime p... \n";

         //generate initial q
         BigUnsigned q = BigUnsigned(1);
         for (int i = 0; i < 400; i++) {
            q = q * 10 + rand();
         }
         //use Fermat test if q is prime
         //if it is not, then re-generate q until it is
         while (!(Fermat(q))){
            cout << "Working...\n";
            q = 0;
            for (int i = 0; i < 400; i++) {
               q = q * 10 + rand();
            }
         }
         cout << "Generated prime q... \n";

         //generate n
         BigUnsigned n = BigUnsigned(p * q);
         cout << "Generated n...\n";
         //generate nPhi
         BigUnsigned nPhi = BigUnsigned((p - 1) * (q - 1));
         cout << "Generated nPhi...\n";

         //generate initial e
         BigUnsigned e = BigUnsigned(3);
         //test if e is relatively prime to nPhi
         //if it is not, try the next odd number
         while (gcd(nPhi, e) != 1) {
            e = e + 2;
         }
         cout << "Generated e...\n";

         //generate d as the multiplicative inverse of e, modulo nPhi
         BigUnsigned d = modinv(e, nPhi);
         cout << "Generated d...\nGeneration completed!\n";

//output rsa values to files

         //turn p and q into strings
         string pval = bigUnsignedToString(p);
         string qval = bigUnsignedToString(q);
         //output p and q into a text file
         std::ofstream pqfile("p_q.txt");
         pqfile << pval << endl << qval;
         pqfile.close();

         //turn n into a string
         string nval = bigUnsignedToString(n);
         //turn e and d into strings
         string eval = bigUnsignedToString(e);
         string dval = bigUnsignedToString(d);
         //output e and n into a text file
         std::ofstream enfile("e_n.txt");
         enfile << eval << endl << nval;
         enfile.close();
         //output d and n into a text file
         std::ofstream dnfile("d_n.txt");
         dnfile << dval << endl << nval;
         dnfile.close();

         cout << "File generation Completed!\n\n";
      }

//create a signature and encrypt it
////////////////////////////////////////////////////////////////////////////////////////////////

      if (argv[1][0]=='s') {
         //set the filename to the string stored in argv[2]
         string filename = argv[2];
         //output the filename
         cout << "filename: " << filename << endl;

         //read the file
         std::streampos begin,end;
         std::ifstream myfile (filename.c_str(), std::ios::binary);
         //calculate the size of the file
         begin = myfile.tellg();
         myfile.seekg (0, std::ios::end);
         end = myfile.tellg();
         std::streampos size = end-begin;
         //output the size of the file
         cout << "\nsize of the file: " << size << " bytes.\n\n"; //size of the file

         myfile.seekg (0, std::ios::beg);
         char * memblock = new char[size];
         myfile.read (memblock, size); //read file; it's saved in the char array memblock
         myfile.close();

         //create a copy of the file
         string copyOFfile = filename+".Copy";
         std::ofstream myfile2 (copyOFfile.c_str(), std::ios::binary);
         myfile2.write (memblock, size); //write to a file
         myfile2.close();

         //read d_n file
         std::ifstream dnfile("d_n.txt");
         //create BigUnsigned objects to store d, and n
         BigUnsigned d, n;
         //create temporary strings to transition d and n from the file to BigUnsigned
         string tempd, tempn;
         //bring in the values to the temporary strings
         dnfile >> tempd >> tempn;
         //move the values from strings to BigUnsigned
         d = stringToBigUnsigned(tempd);
         n = stringToBigUnsigned(tempn);
         dnfile.close();

         //generate a hash value for memblock
         string hash = sha256(memblock);
         //change the hash from hex to base 10 so that it can be stored as a BigUnsigned
         BigUnsigned tempHash = BigUnsignedInABase(hash, 16);
         //create the signature by raising tempHash^d mod n
         BigUnsigned signature = BigUnsigned(modexp(tempHash, d, n));

         //create a filename for the signature file
         string SignedFileName = filename + ".signed";
         //create a file to store the signature
         std::ofstream signedFile (SignedFileName);
         //put the signature into the file
         signedFile << signature;
         signedFile.close();

         //delete the values saved in memblock
         delete[] memblock;
      }


//decrypt a signature and verify it
////////////////////////////////////////////////////////////////////////////////////////////////

      else {
         //set the string filename to be the value sttored in argv[2]
         string filename = argv[2];
         //we want to see what is stored in the text file, not the signature file
         //we must remove the .signed from the end of filename
         const string ext(".signed");
         //remove the .signed end of the filename
         if (filename != ext && filename.size() > ext.size() && filename.substr(filename.size() - ext.size()) == ".signed") {
            filename = filename.substr(0, filename.size() - ext.size());
         }
         //output the filename
         cout << "filename: " << filename << endl;
         //read the file
         std::streampos begin,end;
         std::ifstream myfile (filename.c_str(), std::ios::binary);
         //calculate the size of the file
         begin = myfile.tellg();
         myfile.seekg (0, std::ios::end);
         end = myfile.tellg();
         std::streampos size = end-begin;
         //output the size of the file
         cout << "\nsize of " << filename << ": " << size << " bytes.\n\n"; //size of the file

         myfile.seekg (0, std::ios::beg);
         char * memblock = new char[size];
         myfile.read (memblock, size); //read file; it's saved in the char array memblock
         myfile.close();

         //create a copy of the file
         string copyOFfile = filename+".Copy";
         std::ofstream myfile2 (copyOFfile.c_str(), std::ios::binary);
         myfile2.write (memblock, size); //write to a file
         myfile2.close();

         //read e_n file
         std::ifstream enfile("e_n.txt");
         //create BigUnsigned objects to store e, and n
         BigUnsigned e, n;
         //create temporary strings to move e and n from the file to BigUnsigned
         string tempe, tempn;
         //bring in the values to the temporary strings
         enfile >> tempe >> tempn;
         //move the values from strings to BigUnsigned
         e = stringToBigUnsigned(tempe);
         n = stringToBigUnsigned(tempn);
         enfile.close();

         //generate ahashe value for memblock
         string hash = sha256(memblock);
         //change the hash from hex to base 10 so that it can be stored as a BigUnsigned
         BigUnsigned tempHash = BigUnsignedInABase(hash, 16);

         //create a BigUnsigned object to store the encrypted signature
         BigUnsigned sig;
         //create a string to move the signature from the file to the BigUnsigned
         string signature;
         //read the signature file
         std::ifstream sigfile(filename + ext);
         //bring in the signature to the string
         sigfile >> signature;
         //move the signature from the string to the BigUnsigned
         sig = stringToBigUnsigned(signature);
         sigfile.close();

         //decrypt the signature using e and n from the file
         sig = modexp(sig, e, n);

         //compare the signature and the hash.
         //if they are the same, then the file is authentic
         //if they are different, then the file has been edited
         if (sig == tempHash) {
            cout << "The file is authentic. no changes have been made.\n";
         }
         else {
            cout << "This file has been edited. It is not authentic.\n";
         }
         delete[] memblock;
      }
    }
    return 0;
}
