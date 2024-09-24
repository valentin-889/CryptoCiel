#include <iostream>
#include "RsaGestion.h"
#include "Hashgestion.h"
#include "AesGestion.h"


int main()
{

	RsaGestion RSA;
	
	RSA.generationClef("RSAPublicKey", "RSAPrivateKey", 2048);
	RSA.chargementClefs("RSAPublicKey", "RSAPrivateKey");
	RSA.chiffreDansFichier("RSASortie.txt", "RSAChiffre.txt");
	RSA.dechiffrementFichier("RSASortie.txt", "RSADechiffre.txt", 2048);
	
	
	

}
/*


std::string MessageEncrypt = "voiture sportive ";
		std::string MessageCrypt = RSA.chiffrementRsa(MessageEncrypt);
		std::cout << MessageCrypt << std::endl;
		std::string MessageDecrypt = RSA.dechiffrementRsa(MessageCrypt);
		std::cout << MessageDecrypt << std::endl;

	std::string monMessageHash = "OUAAAA";

	HashGestion LM;
	std::cout << LM.CalculateSHA256(monMessageHash) << std::endl;

	AesGestion monAES;
	monAES.GenerateAESKey();
	monAES.SaveAESKeyToFile("1clef_aes.txt");
	monAES.LoadAESKeyFromFile("1clef_aes.txt");
	monAES.EncryptFileAES256("1clef_aes.txt", "2sortie.txt");
	monAES.DecryptFileAES256("2sortie.txt", "3decryptage.txt");

	RsaGestion RSA;
	RSA.generationClef("RSAPublic", "RSAPrive", 2048)
	std
*/

