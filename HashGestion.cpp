#include "HashGestion.h"

HashGestion::HashGestion()
{
	std::cout << "Constructeur par defautl du Hash" << std::endl;
}

HashGestion::~HashGestion()
{
    std::cout << "Desctructeur par defautl du hasg" << std::endl;
}


std::string HashGestion::CalculateSHA256(const std::string& input)
{
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    return digest;
}

std::string  HashGestion::CalculateFileSHA256(const std::string& filename)
{
    CryptoPP::SHA256 hash;
    std::string hashFile;

    std::ifstream file(filename, std::ios::binary);

    if (!file)
    {
        std::cerr << "Impossible d'ouvrir le fichier." << std::endl;
        return "";
    }

    CryptoPP::HashFilter filter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashFile)));

    const size_t bufferSize = 4096; // Taille du bloc de lecture
    CryptoPP::byte buffer[bufferSize]{};

    while (file.good())
    {
        file.read(reinterpret_cast<char*>(buffer), bufferSize);
        const std::streamsize bytesRead = file.gcount();

        if (bytesRead > 0)
        {
            filter.Put(buffer, bytesRead);
        }
    }

    filter.MessageEnd();
    return hashFile;
}
