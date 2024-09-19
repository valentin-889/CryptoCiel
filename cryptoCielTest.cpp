#include <iostream>
#include "RsaGestion.h"
#include "Hashgestion.h"
#include "AesGestion.h"
#include <fstream>

int main()
{
    HashGestion LM;
    std::string File = "fichier.txt";
    std::cout << "SHA256 Hash: " << LM.CalculateSHA256(File) << std::endl;
    return(0);


}