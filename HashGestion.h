#pragma once

#include <iostream>
#include <sha.h>
#include <hex.h>
#include <fstream>


class HashGestion
{

public : 

	

	HashGestion();
	~HashGestion();

	std::string CalculateSHA256(const std::string& input);
	std::string CalculateFileSHA256(const std::string& filename);

	
};

