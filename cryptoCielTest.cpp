// RsaCiel.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include "RsaGestion.h"
#include "Hashgestion.h"
#include "AesGestion.h"

int main()
{
	HashGestion LM;
	std::string monMessageHash = "Super message superchouette";
	std::cout << LM.CalculateSHA256(monMessageHash) << std::endl;

}


