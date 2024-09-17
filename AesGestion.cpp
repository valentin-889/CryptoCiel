#include "AesGestion.h"


using namespace CryptoPP;

void printHex(std::string const& str)
{
    for (size_t i = 0;i < str.size();++i)
        std::cout << std::hex << (short)str[i] << std::endl;
    
}


AesGestion::AesGestion()
{
	
}


/**
 * \brief generation d'une clef AES 
 * Le resultat est mid dans un tbl octet privee
 * 
 */
void AesGestion::GenerateAESKey()
{
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(this->aesKey, sizeof(this->aesKey));
    //std::cout << "Generation de clef OK" << std::endl;
}


/** 
 * \brief Sauvegarde de la clef dans un fichier
 * 
 * \param filename : nom du fichier qui va contenir la clef
 */
void AesGestion::SaveAESKeyToFile(const std::string& filename)
{
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs)
    {
        std::cerr << "Erreur lors de l'ouverture du fichier de sortie." << std::endl;
        return;
    }

    ofs.write(reinterpret_cast<const char*>(this->aesKey), sizeof(this->aesKey));

    ofs.close();

    //std::cout << "Sauvegarde clef AES dans : " << filename << std::endl;
}

/**
 * \brief Chargement de la clef depuis un fichier
 * 
 * \param filename nom du ficheir contenant la clef
 */
void AesGestion::LoadAESKeyFromFile(const std::string& filename)
{
    std::ifstream ifs(filename, std::ios::binary);
    if (!ifs)
    {
        std::cerr << "Erreur lors de l'ouverture du fichier d'entrée." << std::endl;
        return;
    }

    ifs.read(reinterpret_cast<char*>(this->aesKey), sizeof(this->aesKey));

    ifs.close();

    //std::cout << "Chargement clef AES depuis " << filename << std::endl;
}



/**
 * \brief Chiffre un fichier et met le resultat dans un autre
 *
 * \param inputFile fichier contenant les donnees a chiffrer
 * \param outputFile ficheir contenant les donnes chiffrees
 */
void AesGestion::EncryptFileAES256(const std::string& inputFile, const std::string& outputFile)
{
    // Générez un IV aléatoire
    AutoSeededRandomPool rng;
    rng.GenerateBlock(this->iv, sizeof(this->iv));

    // IV BASE 64
    // A COMMENTER
    std::string ivBase64;
    StringSource(this->iv, sizeof(this->iv), true,
        new Base64Encoder(
            new StringSink(ivBase64),
            false // ne pas ajouter de saut de ligne
        )
    );
    //std::cout << "E+++++++" << ivBase64 << std::endl;
    //std::cout << "E+++++++" << std::hex << reinterpret_cast<const short*>(this->iv) << std::endl;


    // Initialisez le chiffreur avec la clé et l'IV
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(this->aesKey, sizeof(this->aesKey), this->iv);

    // Lisez le contenu du fichier dans une chaîne de caractères
    std::string fileContent;
    FileSource(inputFile.c_str(), true,
        new StringSink(fileContent)
    );

    // Chiffre le fichier
    std::string encryptedContent;
    StringSource(fileContent, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(encryptedContent)
        )
    );

    // Ouvrez le fichier de sortie en mode binaire
    std::ofstream file(outputFile.c_str(), std::ios::binary);

    // IV en préfixe
    file.write(reinterpret_cast<const char*>(this->iv), sizeof(this->iv));

    //Donnee chiffre apres
    file.write(encryptedContent.c_str(), encryptedContent.size());

    //std::cout << "Fichier chiffre avec IV en prefixe : " << outputFile << std::endl;
}


/**
 * \brief Dechiffre les donnees d'un fichier
 *
 * \param inputFile Fichier a dechiffrer
 * \param outputFile Resultat du dechiffrement
 */
void AesGestion::DecryptFileAES256(const std::string& inputFile, const std::string& outputFile)
{
    // Ouvrez len binaire
    std::ifstream input(inputFile.c_str(), std::ios::binary);

    //on enelvee l'IV
    input.read(reinterpret_cast<char*>(this->iv), sizeof(this->iv));

    // IV BASE 64
    // A COMMENTER
    std::string ivBase64;
    StringSource(this->iv, sizeof(this->iv), true,
        new Base64Encoder(
            new StringSink(ivBase64),
            false // ne pas ajouter de saut de ligne
        )
    );
    //std::cout << "D+++++++" << ivBase64 << std::endl;

    //Deplacement curseur
    input.seekg(sizeof(this->iv));

    // Initialiser
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(this->aesKey, sizeof(this->aesKey), this->iv);

    // Ouvrer le fichier de sortie en mode binaire
    //std::ofstream output(outputFile.c_str(), std::ios::binary);

    //Lire le reste et dechiffre
    FileSource(input, true,
        new StreamTransformationFilter(decryptor,
            new FileSink(outputFile.c_str()), BlockPaddingSchemeDef::PKCS_PADDING)
    );

    //std::cout << "Fin Déchiffrement AES-256" << std::endl;
}


/**
 * Chiffre une string en AES256 PLace l'IV en preambulet et converti le tout en base64.
 * 
 * \param plaintext : message a chiffre
 * \return : message chiffre (syring) en base64
 */
std::string AesGestion::encrypt_aes256_to_base64(const std::string& plaintext) {
    AutoSeededRandomPool rng;
    rng.GenerateBlock(this->iv, sizeof(this->iv));
    // Initialiser le chiffreur avec la clé et l'IV
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(this->aesKey, sizeof(this->aesKey), this->iv);

    // Ajouter le padding PKCS7 aux données
    std::string paddedData;
    StringSource(plaintext, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(paddedData),
            BlockPaddingSchemeDef::PKCS_PADDING
        )
    );



    // Concaténer l'IV avec les données rembourrées
    std::string ivAndPaddedData = std::string(reinterpret_cast<const char*>(this->iv), AES::BLOCKSIZE) + paddedData;

    // Convertir les données concaténées en base64
    std::string base64Cipher;
    StringSource(ivAndPaddedData, true,
        new Base64Encoder(
            new StringSink(base64Cipher),
            false  // ne pas ajouter de saut de ligne
        )
    );

    return base64Cipher;

}
/**
 * Dechiffrer de l'AES256 avec l'IV en préambule le tout au format base64.
 * 
 * \param base64_encoded_data : string en base 64 contenant l'IV + message chiffre
 * \return message déchiffre
 */
std::string AesGestion::decrypt_aes256_from_base64(const std::string& base64_encoded_data) {
    // Décoder la chaîne base64
     // Décoder la chaîne base64
    std::string decoded;
    //std::cout << "----  base64_encoded_data " << base64_encoded_data << std::endl;

    StringSource(base64_encoded_data, true, new Base64Decoder(new StringSink(decoded)));


    

    // Extraire l'IV et le message chiffré
    std::string iv = decoded.substr(0, AES::BLOCKSIZE);  


    std::string ciphertext = decoded.substr(AES::BLOCKSIZE,decoded.size());
    
   /// std::cout << decoded << std::endl;
    //std::cout << ciphertext << std::endl;

    std::copy(iv.begin(), iv.end(), this->iv);

    /** Debug *************************************************************************************/
    std::string encodedString;
    CryptoPP::StringSource(iv, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encodedString),
            false  // ne pas ajouter de saut de ligne
        )
    );
    //std::cout << "---- IV " << encodedString << std::endl;
    std::string encodedChiffre;
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encodedChiffre),
            false  // ne pas ajouter de saut de ligne
        )
    );
    //std::cout << "---- ciphertext " << encodedChiffre << std::endl;
    /** Fin debug******************************************************************************************************/

    // Initialiser le déchiffreur avec la clé et l'IV
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(this->aesKey, sizeof(this->aesKey), this->iv);

    // Déchiffrer les données
    std::string decryptedData;
    StringSource(ciphertext, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(decryptedData)
        )
    );
    //std::cout << " -----------> decryptedData " << decryptedData << std::endl;
    // Supprimer le padding PKCS7
    //size_t padSize = decryptedData[decryptedData.length() - 1];
    //decryptedData.resize(decryptedData.length() - padSize);

    return decryptedData;

}


