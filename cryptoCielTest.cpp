#include <iostream>
#include "RsaGestion.h"
#include "Hashgestion.h"
#include "AesGestion.h"

int main()
{


	std::string monMessageHash = "OUAAAA";



	HashGestion LM;
	std::cout << LM.CalculateSHA256(monMessageHash) << std::endl;

	AesGestion monAES;
	monAES.GenerateAESKey();
	monAES.SaveAESKeyToFile("1clef_aes.txt");
	monAES.LoadAESKeyFromFile("1clef_aes.txt");
	monAES.EncryptFileAES256("1clef_aes.txt", "2sortie.txt");
	monAES.DecryptFileAES256("2sortie.txt", "3decryptage.txt");
}
