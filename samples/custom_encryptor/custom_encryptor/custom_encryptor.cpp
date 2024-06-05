#include <algorithm> // Include this to use std::remove
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

/* 
 * This function performs a custom encryption on each byte of the input data
 * by adding a fixed value (0xFE) to each byte.
 *
 * @param data: Pointer to the data to be encrypted
 * @param data_len: Length of the data
 *
 * The function iterates over each byte of the data and adds 0xFE to it.
 */
void custom_encrypt(unsigned char* data, size_t data_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] = data[i] + 0xFE;
    }
}

/* 
 * This function converts a string of hex values into a vector of bytes.
 *
 * @param input: The string containing hexadecimal values
 *
 * @return A vector of bytes corresponding to the hexadecimal values in the input string
 *
 * The function processes the input string in chunks of 4 characters,
 * converts each chunk to a byte and stores the bytes in a vector.
 */
std::vector<unsigned char> stringToBytes(const std::string& input) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < input.length(); i += 4) {
        unsigned char byte = std::stoi(input.substr(i + 2, 2), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

/* 
 * This function converts a vector of bytes back to a string with each byte
 * represented as \xHH and organizes the string into lines.
 *
 * @param bytes: The vector of bytes to convert
 * @param line_length: The maximum length of each line in the output string
 *
 * @return A formatted string where each byte is represented as \xHH
 *
 * The function processes the byte vector, converts each byte to a hexadecimal
 * string and organizes the output into lines with a specified maximum length.
 */
std::string bytesToString(const std::vector<unsigned char>& bytes, size_t line_length = 60) {
    std::ostringstream result;
    result << std::hex << std::setfill('0');
    size_t current_length = 0;

    for (size_t i = 0; i < bytes.size(); ++i) {
        if (current_length == 0) {
            result << "\"";  // Start new line with a double quote
        }

        result << "\\x" << std::setw(2) << static_cast<int>(bytes[i]);
        current_length += 4;  // Add 4 for each "\xYY"

        if (current_length >= line_length || i == bytes.size() - 1) {
            result << "\"\n";  // Close the string and start a new line
            current_length = 0;
        }
    }

    if (current_length != 0) {
        result << "\"\n";  // Ensure the last line is closed if not already
    }

    return result.str();
}

/* 
 * The main function reads an input file containing
 * a hexadecimal encoded buffer, decrypts the buffer using XOR and writes
 * the decrypted buffer to an output file.
 */
int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>\n";
        return 1;
    }

    std::ifstream infile(argv[1]);
    if (!infile.is_open()) {
        std::cerr << "Error opening input file\n";
        return 1;
    }

    std::string line, bufferContent;
    bool startBuffer = false;
    while (std::getline(infile, line)) {
        if (line.find("unsigned char buf[] =") != std::string::npos) {
            startBuffer = true;
            continue;
        }
        if (startBuffer) {
            if (line.find("\";") != std::string::npos) {
                bufferContent += line.substr(0, line.length() - 2); // Remove trailing ";
                break;
            }
            bufferContent += line;
        }
    }
    infile.close();

    // Remove all newline and quote characters
    bufferContent.erase(std::remove(bufferContent.begin(), bufferContent.end(), '\n'), bufferContent.end());
    bufferContent.erase(std::remove(bufferContent.begin(), bufferContent.end(), '\"'), bufferContent.end());

    std::vector<unsigned char> buffer = stringToBytes(bufferContent);

    custom_encrypt(buffer.data(), buffer.size());

    // Convert bytes back to string
    std::string modifiedBuffer = bytesToString(buffer);

    std::ofstream outfile(argv[2]);
    if (!outfile.is_open()) {
        std::cerr << "Error opening output file\n";
        return 1;
    }

    outfile << "unsigned char buf[] = \n";
    outfile << bytesToString(buffer, 60);
    outfile << ";\n";

    outfile.close();
    return 0;
}
