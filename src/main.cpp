#include <iostream>

#include "aes.h"
using namespace aes;

// Driver code
int main()
{
    // Custom utilites for file operations, printing defined in aes.h
    Utilities utilities;
    // 1 Round Aes implemenation defined in aes.h
    AesImplementation aes;
    int input;
    std::cout<<__cplusplus;
    std::cout << "Enter 1 or 2 for the following" << std::endl
              << "1. One Round of AES" << std::endl
              << "2. Generate SubKeys" << std::endl;
    std::cin >> input;
    std::string encryptionKey;
    if (input == 1)
    {
        std::string plainText = utilities.ReadFromFile("../data/plaintext.txt", 1);
        std::cout << "Plain text from plaintext.txt file: " << std::endl
                  << plainText << std::endl
                  << std::endl;
        std::cout << "Please enter 128 - bit encryption key. Enter blank for default key from text file.: " << std::endl;
        std::getline(std::cin, encryptionKey);

        if (encryptionKey == "")
        {
            encryptionKey = utilities.ReadFromFile("../data/subkey_example.txt", 1);
        }

        aes.Encrypt(plainText, encryptionKey);
    }
    else if (input == 2)
    {
        std::cout << "Reading Sub Key 0 from text file.." << std::endl;
        std::string key = utilities.ReadFromFile("../data/subkey_example.txt", 1);
        int subKey0[4][4], subKey1[4][4];
        std::string key0 = aes.GetSubKey(key, subKey0);

        std::cout << "Sub Key 1: " << std::endl
                  << key0 << std::endl;
    }
    else
    {
        std::cout << "Invalid Input. Exiting..";
    }
    int temp;

    // To prevent console from closing
    std::cin >> temp; 
    return 0;
}
