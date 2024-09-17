/*! \mainpage
* Cette classe dediee au BTS CIEL/SNIR doit permettre
* \li D'pprendre a installer et utiliser une librairie sur Visual Studio
* \li De comprendre l'utilisation de l'algorothme de chiffrement RSA
*
*/



/*****************************************************************//**
 * \file   RsaGestion.cpp
 * \brief  Definition des methodes de la classe RsaGestion
 *
 * \author Pierre
 * \date   June 2023
 *********************************************************************/
#include "RsaGestion.h"



 /**
  * Brief Constructeur de la classe RsaGestion
  *
  * Ne fait aucune acction
  *
  */
RsaGestion::RsaGestion()
{
    std::cout << "Construction de la classe" << std::endl;

}

/**
 * \brief Desctruteur de la classe RsaGEstion
 * Ne fait aucune action
 *
 */
RsaGestion::~RsaGestion()
{
    std::cout << "Destruction de la classe" << std::endl;
}

/**
 * \brief Operateur de copie
 *
 * \param rsagestion : objet de type RsaGestion
 */
RsaGestion::RsaGestion(const RsaGestion& rsagestion)
{
    std::cout << "Operateur de copie " << std::endl;
    this->clefPrive = rsagestion.clefPrive;
    this->clefPublic = rsagestion.clefPublic;
}

/**
 * \brief Operateur d'affectation
 *
 * \param rsagestion : objet de type RsaGestion
 * \return objet de type RsaGestion
 */
RsaGestion& RsaGestion::operator=(const RsaGestion& rsagestion)
{
    std::cout << "Affectation de la gestion RSA" << std::endl;
    if (this != &rsagestion)
    {
        this->clefPrive = rsagestion.clefPrive;
        this->clefPublic = rsagestion.clefPublic;
    }
    return *this;
}

/**
 * \brief Generateur d'une paire de clefs (public et privee)
 *
 * \param nomCheminPublic nom et chemin du fichier qui va contenir la clef public (au format PEM)
 * \param nomCheminPrive nom et chemin du fichier qui va contenir la clef privee (au format PEM)
 * \param taile Taille de la clef a generer (souvant 1024 ou 2048)
 * \return
 */
int RsaGestion::generationClef(std::string nomCheminPublic, std::string nomCheminPrive, unsigned int taille)
{

    std::ios_base::sync_with_stdio(false);
    AutoSeededRandomPool rng;
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, taille);
    RSA::PrivateKey privateKey(parameters);
    RSA::PublicKey publicKey(parameters);

    FileSink fsPrivate(nomCheminPrive.c_str(), false);
    PEM_Save(fsPrivate, privateKey);
    std::cout << "Ecriture clef privee dans " << nomCheminPrive << std::endl;

    FileSink fsPublic(nomCheminPublic.c_str(), false);
    PEM_Save(fsPublic, publicKey);
    std::cout << "Ecriture clef public dans " << nomCheminPublic << std::endl;
    this->clefPrive = privateKey;
    this->clefPublic = publicKey;

    return 0;
}

/**
 * \brief Chiffre des donnees a partir de la clef public de l'objet
 *
 * \param donneClaire : string correspondant aux donnees a chiffrer
 * \return string correspondant aux donnees chiffrees
 */
std::string RsaGestion::chiffrementRsa(std::string donneClaire)
{
    std::string donneeChiffree;
    AutoSeededRandomPool rng;

    RSAES_OAEP_SHA_Encryptor e(this->clefPublic);

    StringSource(donneClaire, true,
        new PK_EncryptorFilter(rng, e,
            new StringSink(donneeChiffree)
        ) // PK_EncryptorFilter
    ); // StringSource

    std::cout << donneeChiffree << std::endl;
    std::string chiffreBase64 = this->base64_encode(donneeChiffree);

    return chiffreBase64;
}

/**
 * \brief  Dechiffre des donnees a partir de la clef privee de l'objet.
 *
 * \param messageChiffre string correspondant aux donnees chiffrees
 * \return string correspondant aux donnees dechiffree
 */
std::string RsaGestion::dechiffrementRsa(std::string messageChiffre)
{
    AutoSeededRandomPool rng;
    std::string messagedechiffre = "";
    std::string messageChiffreBrute = this->base64_decode(messageChiffre);


    RSAES_OAEP_SHA_Decryptor d(this->clefPrive);

    StringSource(messageChiffreBrute, true,
        new PK_DecryptorFilter(rng, d,
            new StringSink(messagedechiffre)
        ) // PK_EncryptorFilter
    );

    return messagedechiffre;
}

/**
 * \brief Decode une string en base 64
 *
 * \param encoded_message string codee en base 64
 * \return string decode
 */
std::string RsaGestion::base64_decode(std::string& encoded_message) {
    Base64Decoder decoder;
    decoder.Put((const byte*)encoded_message.data(), encoded_message.size());
    decoder.MessageEnd();

    std::string decoded_message;
    decoded_message.resize(decoder.MaxRetrievable());
    decoder.Get((byte*)decoded_message.data(), decoded_message.size());

    return decoded_message;
}

/**
 * \brief Code une string en base 64
 *
 * \param message string a coder
 * \return string code en base 64
 */
std::string RsaGestion::base64_encode(const std::string& message) {
    std::string encoded_message;
    CryptoPP::StringSource(message, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded_message)));

    return encoded_message;
}

/**
 * \brief Charge une paire de clefs depuis un fichier
 *
 * \param nomFicherPrive chemin et nom du fichier conetenant  la clef privee
 * \param NomFichierPublic chemin et nom du fichier contenant la clef public
 */
void RsaGestion::chargementClefs(std::string nomFichierPublic, std::string nomFicherPrive)
{
    this->chargementClefsPrive(nomFicherPrive);
    this->chargementClefsPublic(nomFichierPublic);
}

/**
 *\brief Charge une clef privee dans l'objet depuis un fichier.
 *
 * \param nomFicherPrive chemin et nom du fichier conetenant  la clef privee
 */
void RsaGestion::chargementClefsPrive(std::string nomFicherPrive)
{

    FileSource fsPrivate_Load(nomFicherPrive.c_str(), true);
    PEM_Load(fsPrivate_Load, this->clefPrive);
}

/**
 * \brief  Charge une clef public dans l'objet depuis un fichier.
 *
 * \param nomFicherPublic
 */
void RsaGestion::chargementClefsPublic(std::string nomFicherPublic)
{

    FileSource fsPublic_Load(nomFicherPublic.c_str(), true);
    PEM_Load(fsPublic_Load, this->clefPublic);
}

/**
 * \brief Dechiffre les donnes au format Base 64 contenu dans un fichier
 *
 * \param nomFichier string contenant le nom et le chmein du fichier
 * \return string donnee decodee
 */
std::string RsaGestion::dechiffreFichier(std::string nomFichier)
{
    std::string textChiffre = "";
    std::ifstream input_file(nomFichier);
    if (input_file.is_open())
    {
        std::string ligne;
        while (std::getline(input_file, ligne))  // tant que l'on peut mettre la ligne dans "contenu"
        {
            textChiffre = textChiffre + ligne;
        }

        input_file.close();
        std::cout << textChiffre << std::endl;
    }
    else
    {
        std::cerr << "Erreur lors de la lecture du fichier." << std::endl;
    }
    return this->dechiffrementRsa(textChiffre);

}

/**
 * \briefChiffre les donnees et met le resutlat dans un fichier
 *
 * \param donnee donnee a chiffrer
 * \param nomFichier nom du fichier accueillant les donnees chiffrees
 */
void RsaGestion::chiffreDansFichier(std::string donnee, std::string nomFichier)
{

    std::string donneeChiffre = this->chiffrementRsa(donnee);
    std::ofstream file(nomFichier, std::ios::binary);
    if (file.is_open())
    {

        file << donneeChiffre;
        file.close();

        std::cout << "Fichier enregistre avec succes." << std::endl;
    }
    else
    {
        std::cout << "Impossible d'ouvrir le fichier." << std::endl;
    }
}


/**
 * \brief Chiffre en RSA un fichier et mais le resultats dans un fichier le format base64 peut être seclectionne 
 *
 * Le fichier peut-etre un fichier binaire. ATTENTION : la taille du fichier est limitee.
 * Ce type de chiffrement est utilise pour chiffrer des clefs ou des hash
 *
 * \param fichierEntree chemin/nom fichier d'entree (a chiffrer)
 * \param fichierSortie chemin/nom fichier chiffre
 * \param format des fichiers true : base64 (lisible par l'homme)
 */
void RsaGestion::chiffrementFichier(const std::string fichierEntree, const std::string  fichierSortie, bool format64)
{
    if (format64 == true)
    {
        std::string textAchiffre = "";
        std::ifstream input_file(fichierEntree);
        if (input_file.is_open())
        {
            std::string ligne;
            while (std::getline(input_file, ligne))  // tant que l'on peut mettre la ligne dans "contenu"
            {
                textAchiffre = textAchiffre + ligne;
            }

            input_file.close();
            std::cout << textAchiffre << std::endl;
        }
        this->chiffreDansFichier(textAchiffre, fichierSortie);
    }
    else
    {
        AutoSeededRandomPool rng;

        FileSource(fichierEntree.c_str(), true,
            new PK_EncryptorFilter(rng, RSAES_OAEP_SHA_Encryptor(this->clefPublic), new FileSink(fichierSortie.c_str()))
        );
    }

}

/**
 * \brief Dechiffrement de fichier a fichier.
 * 
 * \param fichierEntree fichier chiffre 
 * \param fichierSortie fichier dechiffre
 * \param format64 selection du format true : base 64
 */
void RsaGestion::dechiffrementFichier(const std::string fichierEntree, const std::string fichierSortie, bool format64)
{
    if (format64 == true)
    {
        std::string donneClaire = this->dechiffreFichier(fichierEntree);
        std::ofstream file(fichierSortie, std::ios::binary);
        if (file.is_open())
        {

            file << donneClaire;
            file.close();

            std::cout << "Fichier enregistre avec succes." << std::endl;
        }
        else
        {
            std::cout << "Impossible d'ouvrir le fichier." << std::endl;
        }
    }
    else
    {
        AutoSeededRandomPool rng;

        FileSource(fichierEntree.c_str(), true,
            new PK_DecryptorFilter(rng, RSAES_OAEP_SHA_Decryptor(this->clefPrive), new FileSink(fichierSortie.c_str()))
        );
    }
}



