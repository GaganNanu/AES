#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>

namespace aes
{
    /**
     * @brief Class for reusable functions like fileoperations, print, format conversions.
     */
    class Utilities
    {
    public:
        std::string ReadFromFile(std::string fileNameWithPath, int lineNumber);
        void WriteToFile(std::string fileNameWithPath, std::string text);
        std::string DecimalArrayToHexString(int arr[4][4]);
        void HexStringToMatrix(std::string hexString, int outputArray[4][4], int orientation);
        void PrintAsMatrix(std::string message, int arr[4][4]);
        void RotateArrayToLeft(int arr[4], int shiftLength);
    };

    /**
     * @brief Class to wrap all AES functions.
     * The entry point should be Encrypt and it does 1 round of AES.
     * It also contains subkey generating function.
     */
    class AesImplementation
    {
    public:
        void Encrypt(std::string plainText, std::string publicKey);
        void SetInitialState(std::string plainText, int initialState[4][4]);
        void SubBytes(int currentState[4][4]);
        void ShiftRows(int currentState[4][4]);
        void MixColumns(int currentState[4][4], int newState[4][4]);
        void AddKey(int roundKey[4][4], int initialState[4][4], int currentState[4][4]);
        std::string GetSubKey(std::string encryptionKey, int subKey1[4][4]);
        void G(int word[4], int roundConstant, int output[4]);

    private:
        // SBox values for all 256 characters.
        int sbox[256] = {99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22};
        // Matrix used for multiplication in Mix Column Step.
        int mixColumnMatrix[4][4] = {
            {02, 03, 01, 01},
            {01, 02, 03, 01},
            {01, 01, 02, 03},
            {03, 01, 01, 02},
        };
        Utilities utilities;
    };

    /**
     * @brief Returns the text by line number from the given file.
     * @param fileNameWithPath: Name of the file with path
     * @param lineNumber Line number to retrieve starting from 1
     * @return string value in the given line
     */
    std::string Utilities::ReadFromFile(std::string fileNameWithPath, int lineNumber)
    {
        std::ifstream fileToRead(fileNameWithPath);
        if (fileToRead.is_open())
        {
            int i = 1;
            std::string line;
            while (i <= lineNumber)
            {
                getline(fileToRead, line);
                i++;
            }
            fileToRead.close();
            return line;
        }
        else
        {
            std::cout << "Unable to open file: " << fileNameWithPath << std::endl;
        }

        return NULL;
    }

    /**
     * @brief Opens a file without append mode, so clears all contents and then writes the input text to file.
     * @param fileNameWithPath
     * @param lineNumber
     * @return string
     */
    void Utilities::WriteToFile(std::string fileNameWithPath, std::string text)
    {
        std::ofstream fileToWrite;
        fileToWrite.open(fileNameWithPath, std::ofstream::out);
        fileToWrite << text;
        fileToWrite.close();
    }

    /**
     * @brief Function to print a 2D array in decimal as hexadecimal matrix and input message on top.
     * @param arr 4X4 Array
     */
    void Utilities::PrintAsMatrix(std::string message, int arr[4][4])
    {
        std::cout << "----   " << message << "   ----" << std::endl
                  << std::endl;
        for (int i = 0; i < 4; i++)
        {
            std::cout << "    ";
            for (int j = 0; j < 4; j++)
            {
                std::cout << std::hex << std::setfill('0') << std::setw(2) << arr[i][j] << " ";
            }
            std::cout << std::endl
                      << std::endl;
        }
        std::cout << std::endl;
    }

    /**
     * @brief Converts 4X4 Decimal Array to hex string, prepends padding 0's for 0-9 and returns it
     *
     * @param arr Input array
     * @return std::string Hexadecimal string
     */
    std::string Utilities::DecimalArrayToHexString(int arr[4][4])
    {
        std::stringstream mystream;

        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                mystream << std::hex << std::setfill('0') << std::setw(2) << arr[j][i];
            }
        }
        return mystream.str();
    }

    /**
     * @brief Converts the input hexstring into a matrix
     *
     * @param hexString Input string in hexadecimal format of 16 bytes.
     * @param outputArray Output array of 4X4 to store hex string as matrix.
     * @param orientation 0 for vertical and 1 for horizontal. This is needed because we needs words for subkey generation.
     */
    void Utilities::HexStringToMatrix(std::string hexString, int outputArray[4][4], int orientation)
    {
        for (int i = 0, k = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                if (orientation == 0)
                {
                    outputArray[j][i] = (int)strtol(hexString.substr(k, 2).c_str(), NULL, 16);
                }
                else
                {
                    outputArray[i][j] = (int)strtol(hexString.substr(k, 2).c_str(), NULL, 16);
                }
                k += 2;
            }
        }
    }

    void Utilities::RotateArrayToLeft(int arr[4], int shiftLength)
    {
        int newRow[4];

        for (int j = 0; j < 4; j++)
        {
            newRow[j] = arr[(j + shiftLength) % 4];
        }

        for (int k = 0; k < 4; k++)
        {
            arr[k] = newRow[k];
        }
    }

    /**
     * @brief The base function that performs 1 round of AES by reading plain text from plaintext.txt and Encryption Key
     * from first line of subkey_example.txt
     * It then generates subkey1, creates Initial State, performs SubBytes, ShiftRows, MixColumns and AddKey steps.
     * @param plainText
     * @param publicKey
     * @return string
     */
    void AesImplementation::Encrypt(std::string plainText, std::string encryptionKey)
    {
        // cout << "hex: "<< initialState[j][i] << endl;
        // const char* plainTextArray = plainText.c_str();
        int initialState[4][4], subKey0[4][4];

        SetInitialState(plainText, initialState);
        utilities.PrintAsMatrix("Intial State", initialState);

        // Subkey0
        std::string subKey0String = encryptionKey;

        utilities.HexStringToMatrix(subKey0String, subKey0, 0);
        utilities.PrintAsMatrix("SubKey 0", subKey0);

        // Add Key
        int currentState[4][4];
        AddKey(subKey0, initialState, currentState);
        utilities.PrintAsMatrix("Current State", currentState);

        // SubBytes
        SubBytes(currentState);
        utilities.PrintAsMatrix("SubBytes", currentState);

        // Shift Rows
        ShiftRows(currentState);
        utilities.PrintAsMatrix("After Shift Rows", currentState);

        // Mix Columns
        int newStateArray[4][4];
        MixColumns(currentState, newStateArray);
        utilities.PrintAsMatrix("Mix Columns", newStateArray);

        // Generate Subkey 1
        int subKey1[4][4];
        std::string subKey1HexString = GetSubKey(subKey0String, subKey1);
        utilities.WriteToFile("../data/result_subkey.txt", subKey1HexString);

        utilities.PrintAsMatrix("Sub Key 1", subKey1);

        // Add Key with SubKey 1
        AddKey(subKey1, newStateArray, newStateArray);

        utilities.PrintAsMatrix("Output after Round 1", newStateArray);
        std::string round1Output = utilities.DecimalArrayToHexString(newStateArray);
        utilities.WriteToFile("../data/result.txt", round1Output);
        std::cout << "Sub Key 1 as hex string: " << std::endl
                  << subKey1HexString << std::endl;
        std::cout << "Output of Round 1 as hex string: " << std::endl
                  << round1Output;

        // Round 1 End
    }

    /**
     * @brief Method to generate subkey based on previous round key.
     * It also sets the generated subkey in matrix format in given 2D input array.
     * @param encryptionKey The intial key or previous round subkey.
     * @param subKey1 This is an output parameter to write generated subkey in matrix format.
     * @return std::string Returns the subkey generated as a hex string.
     */
    std::string AesImplementation::GetSubKey(std::string encryptionKey, int subKey1[4][4])
    {
        int encryptionKeyInWords[4][4], w4[4], gw3[4];

        utilities.HexStringToMatrix(encryptionKey, encryptionKeyInWords, 1);
        utilities.PrintAsMatrix("SubKey 0", encryptionKeyInWords);

        G(encryptionKeyInWords[3], 1, gw3);

        for (int i = 0; i < 4; i++)
        {
            subKey1[i][0] = encryptionKeyInWords[0][i] ^ gw3[i];
        }

        for (int i = 1; i < 4; i++)
        {
            for (int j = 1; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    subKey1[k][i] = subKey1[k][i - 1] ^ encryptionKeyInWords[i][k];
                }
            }
        }

        utilities.PrintAsMatrix("SubKey1 ", subKey1);

        std::string subKey1String = utilities.DecimalArrayToHexString(subKey1);

        return subKey1String;
    }

    /**
     * @brief Implementation of the 'g' function in Sub Key schedule algorithm
     * @param word word from key
     * @param roundConstant round constant
     * @param output output of 'g' function
     * @return int*
     */
    void AesImplementation::G(int word[4], int roundConstant, int output[4])
    {
        int newWord[4];
        // Shift left by one

        for (int j = 0; j < 4; j++)
        {
            output[j] = word[(j + 1) % 4];
        }

        // Subsitutiion with S-box
        for (int k = 0; k < 4; k++)
        {
            output[k] = sbox[output[k]];
        }

        // XOR with round constant
        output[0] = output[0] ^ roundConstant;
    }

    /**
     * @brief Stores plain text of 16 bytes in 4X4 matrix
     *
     * @param plainText
     * @param initialState
     */
    void AesImplementation::SetInitialState(std::string plainText, int initialState[4][4])
    {
        for (int i = 0, k = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                initialState[j][i] = plainText[k];
                k++;
            }
        }
    }
    /**
     * @brief Perform Add key operation (XOR of intial state with Sub Key) and set the values in currentState
     *
     * @param roundKey The Subkey in matrix format
     * @param initialState Intial State
     * @param currentState  Output Current state
     */
    void AesImplementation::AddKey(int roundKey[4][4], int initialState[4][4], int currentState[4][4])
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                currentState[i][j] = initialState[i][j] ^ roundKey[i][j];
            }
        }
    }

    /**
     * @brief Perfoms substitution of each byte with corresponding byte in S-Box in place.
     *
     * @param currentState Input state.
     */
    void AesImplementation::SubBytes(int currentState[4][4])
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                currentState[i][j] = sbox[currentState[i][j]];
            }
        }
    }

    /**
     * @brief Shift Rows by shifting bytes to the left based on row number
     *
     * @param currentState
     */
    void AesImplementation::ShiftRows(int currentState[4][4])
    {
        for (int i = 0; i < 4; i++)
        {
            utilities.RotateArrayToLeft(currentState[i], i);
        }
    }
    /**
     * @brief GF(2^8) Multiply with Mix Column Matrix and store in newState array
     *
     * @param currentState
     * @param newState
     */
    void AesImplementation::MixColumns(int currentState[4][4], int newState[4][4])
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    int mul;
                    int max = 255;
                    int mod = 0x11b;
                    if (mixColumnMatrix[i][k] == 1)
                    {
                        mul = currentState[k][j];
                    }
                    else if (mixColumnMatrix[i][k] == 2)
                    {
                        mul = currentState[k][j] * 02;
                    }
                    else
                    {
                        int temp = (currentState[k][j] * 2);
                        mul = temp ^ currentState[k][j];
                    }

                    if (mul > 255)
                    {
                        mul = mul ^ mod;
                    }
                    if (k == 0)
                    {
                        newState[i][j] = mul;
                    }
                    else
                    {
                        newState[i][j] ^= mul;
                    }
                }
            }
        }
    }

}