# SmashHash

## Abstract

We have designed SmashHash as a versatile encryption tool that allows users to securely transform and protect their data. The program offers a robust implementation of various encryption methods, including hashing algorithms and the Caesar cipher. By providing a simple and intuitive interface, SmashHash enables users to encrypt and decrypt files effortlessly, ensuring that sensitive information remains protected from unauthorized access. The program caters to individuals who seek a straightforward yet effective encryption solution for their everyday needs.

## Requirements

We have designed SmashHash to be compatible with the following systems and dependencies:
- Python 3.x
- `tkinter` for the graphical user interface
- `hashlib` for implementing hashing algorithms
- Basic text files (e.g., `.txt`) for input and output

Additionally, SmashHash can be run on any platform that supports Python, including Windows, macOS, and Linux.

## Installation

To install SmashHash, please follow these steps:

1. Ensure that Python 3.x is installed on your machine.
2. Download the project files from the provided repository or source.
3. Install the required libraries by running:
   ```
   pip install tkinter
   ```
4. Once the dependencies are installed, navigate to the project directory and execute the program by running:
   ```
   python smashhash.py
   ```

## Usage

Using SmashHash is straightforward. Upon launching the program, you will be presented with a user-friendly interface that allows you to select between encryption and decryption modes. The following steps outline the process:

1. Select Encryption or Decryption:
   We provide two main functions for file processing—encryption and decryption. Users can choose between these functions depending on the task at hand.

2. Choose Encryption Method:
   We offer multiple encryption methods, including:
   - Hashing: MD5, SHA-1, and SHA-256 algorithms.
   - Caesar Cipher: A substitution cipher where each letter is shifted by a user-specified value.

3. File Handling:
   Once the encryption method is selected, users can select the file they wish to encrypt or decrypt. The program will process the file and save the results to a new file, ensuring the original data remains intact.

4. Viewing Results:
   After the encryption or decryption is completed, the output file will be stored in the same directory with an appropriate name indicating the method used. The user can exit the program to view the results.

## File Handling

Our program handles files securely, ensuring that the original content is never altered. When you select a file for encryption or decryption, SmashHash processes the file and generates a new output file with a descriptive name, such as `smashhash_MD5_Data.txt`. If a file with the same name already exists, the program increments the file name to avoid overwriting any previous results (e.g., `smashhash_MD5_Data_1.txt`).

## Customization

SmashHash is designed to be easily customizable. Users who are comfortable with Python programming can extend the program by adding additional encryption algorithms or modifying the existing methods. For example, by adding new functions to the `smashhash.py` file, additional ciphers can be incorporated seamlessly into the interface.

## Additional Notes

We have ensured that SmashHash is intuitive and easy to use, even for those unfamiliar with encryption. All encryption and decryption processes are executed with minimal user input, and the interface guides the user through each step. In case of errors, meaningful messages are displayed to assist the user in resolving issues.


## Authors

Said Abdel Halim - 202320009
Fawzi Attal - 202320583

## Date 8/23/204