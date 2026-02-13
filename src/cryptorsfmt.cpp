#include <string>
#include <iostream>
#include "global.h"
#include "clipp.h"
#include "encrypt.h"
#include "decrypt.h"
#include "encrypt_m2.h"
#include "decrypt_m2.h"

std::string cryptorsfmt_ver = "0.2";

int block_size;

enum Mode {
    mode_1 = 1,
    mode_2
};

void modeSelection(Options *o);
bool testArgs(Options *o);
bool argparse(int argc, char* argv[], Options *o);


int main(int argc, char* argv[])
{
    Options args;

    if(!argparse(argc, argv, &args)) return 1;

    if(!testArgs(&args))
    {
        std::cerr << "Program stopped due to an argument parsing error." << std::endl;
        return 1;
    }

    //start the required mode for encryption/decryption
    modeSelection(&args);

    return 0;
}

void modeSelection(Options *o)
{
    int mode = 0;

    try
    {
        mode = std::stoi(o->mode);
    }
    catch(const std::invalid_argument& e)
    {
        std::cerr << "Invalid argument (-m): " << o->mode << '\n';
    }
    catch (const std::out_of_range& e) {
        std::cerr << "Out of Range error (-m): " << o->mode << '\n';
    }

    switch (mode)
    {
    case mode_1:
        if(o->encrypt)
            ENCRYPT en(o);
        else
            DECRYPT dc(o);
        break;
    
    case mode_2:
        if(o->encrypt)
            ENCRYPT_M2 en(o);
        else
            DECRYPT_M2 dc(o);
        break;

    default:
        std::cerr << "Unknown encryption mode selected. -m can only be set to '1' or '2'.\n";
        break;
    }
}

bool testArgs(Options *o)
{
    if(o->version)
    {
        std::cout << "CryptorSFMT Version: " << cryptorsfmt_ver << std::endl;
        exit(EXIT_SUCCESS);
    }

    if(o->pw.length() > maxPasswordLength)
    {
        std::cerr << "Password length should not exceed 64 characters.";
        return false;
    }

    if(o->decrypt && o->encrypt)
    {
        std::cerr << "Only -d or -e can be used. Not both at the same time." << std::endl;
        return false;
    }

    if(o->pw.empty() && o->keyfile.empty())
    {
        std::cerr << "CryptorSFMT requires either a password, a keyfile or both. None was provided." << std::endl;
        return false;
    }

    if(!(o->decrypt || o->encrypt)) o->encrypt = true;

    if(o->infile.empty()) o->stdi = true;

    if(o->outfile.empty()) o->stdo = true;

    return true;
}

bool argparse(int argc, char* argv[], Options *o)
{
    bool inputState = true;

    clipp::group cli = (
        clipp::option("-p").doc("password used for de-/encryption") & clipp::value("password", o->pw),
        clipp::option("-k").doc("optional keyfile, min keyfile length is 2 byte, max length is 4992 byte, only the first 4992 byte of a keyfile will be used, those should be random bytes as well") & clipp::value("", o->keyfile),
        clipp::option("-i").doc("input file, if omitted cryptorsfmt will read from stdin") & clipp::value("", o->infile),
        clipp::option("-o").doc("output file, if omitted cryptorsfmt will write to stdout") & clipp::value("", o->outfile),
        clipp::option("-m").doc("encryption mode, can be 1 or 2, if omitted defaults to mode 1, if mode was set to 2 for encryption it MUST be set also for decryption") & clipp::value("", o->mode),
        clipp::option("-e").set(o->encrypt).doc("encrypt file, if omitted cryptorsfmt defaults to encryption mode"),
        clipp::option("-d").set(o->decrypt).doc("decrypt file"),
        clipp::option("-v").set(o->version).doc("print version, all other options will be ignored"),
        clipp::option("-h").set(o->help).doc("print help")
    );

    if((!clipp::parse(argc, argv, cli) || o->help) && !o->version)
    {
        std::cerr << clipp::make_man_page(cli, argv[0]);
        inputState = false;
    }

    return inputState;
}
