//-------------------------------------------------------------------------------------------------
// <copyright file="main.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include <fstream>
#include <iterator>
#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <string.h>
#include <stdlib.h>
#ifndef PLATFORM_UNIX
#include <filesystem>
#else
#include <experimental/filesystem>
#endif
#include "TestUtil.h"
#include "Tpm.h"
#include "Tss2Util.h"
#include "Exceptions.h"
#include "AttestationTypes.h"
#include <numeric>

using namespace std;

#define MAX_PATH 260 // This is standard for Windows and some flavours of Linux.

static Tpm g_tpm{};

#ifndef PLATFORM_UNIX
/*implementation of get opt for Windows*/
//Pointer to argument name
static char* optarg { nullptr };
//The variable optind is the index of the next element to be processed in argv
static int optind { 1 };

/*
* The getopt() function parses the command - line arguments.Its
* arguments argc and argv are the argument count and array as passed to
* the main() function on program invocation
*/
static int getopt(int argc, char *const argv[], const char *optstring)
{

    //Error and -1 returns are the same as for getopt(), plus '?'
    // for an ambiguous match or an extraneous parameter.
     if (
        (argv == nullptr) ||
        (optind >= argc) ||
        (argv[optind][0] != '-') ||
        (argv[optind][0] == 0)
        )
    {
        return -1;
    }

    int opt = argv[optind][1];
    const char *p = strchr(optstring, opt);

    if (p == NULL)
    {
        return '?';
    }
    if (p[1] == ':')
    {
        optind++;
        if (optind >= argc)
        {
            return '?';
        }
        optarg = argv[optind];
        optind++;
    }
    return opt;
}
#endif //!PLATFORM_UNIX


/**
* Returns the path of the file name from temp directory.
*/
static
auto prepend_tempdir_path(const char* filename)
{
#ifndef PLATFORM_UNIX
    std::string file_path { std::filesystem::temp_directory_path().string() };
    if (file_path[file_path.length() - 1] != std::filesystem::path::preferred_separator)
    {
        file_path += std::filesystem::path::preferred_separator;
    }
#else
    std::string file_path { std::experimental::filesystem::temp_directory_path().string() };

    if (file_path[file_path.length() - 1] != std::experimental::filesystem::path::preferred_separator)
    {
        file_path += std::experimental::filesystem::path::preferred_separator;
    }
#endif
    file_path += filename;

    if (file_path.length() > MAX_PATH)
    {
        throw std::runtime_error("Temp File length > MAX_PATH"); // todo: standardize the exceptions
    }
    return file_path;
}

/**
 * Output more helpful errors for some common error conditions
 */
void output_tss2_error(Tss2Exception& e)
{
    cout << "Error: " << e.what() << endl;

    if (e.get_rc() == TSS2_TCTI_RC_IO_ERROR) {
        // No TPM device file
        cout << "Could not open tpm device file" << endl;
        cout << "Either there in not a TPM on this machine or this application is not running as root" << endl;
    }
}

/**
 * Gets the version of this computer's TPM and prints it to stdout
 */
void process_get_tpmversion()
{
    attest::TpmVersion version = g_tpm.GetVersion();
    switch (version) {
        case attest::TpmVersion::V2_0:
            cout << "TPM Version 2.0" << endl;
            break;
        case attest::TpmVersion::V1_2:
            cout << "TPM Version 1.2" << endl;
            break;
        default:
            cout << "Unknown TPM version" << endl;
            break;
    }
}

/**
 * Retrieves EK pub from NVRAM and writes the packed TPM2B_PUBLIC
 * to tmp directory %tmp%/ek.pub
 */
void process_get_ekpub()
{
    auto ekpubFile = prepend_tempdir_path("ek.pub");
    auto ekPub = g_tpm.GetEkPub();
    std::ofstream ekpubf(ekpubFile);
    std::ostream_iterator<unsigned char> ekpubItr(ekpubf);
    std::copy(ekPub.begin(), ekPub.end(), ekpubItr);
    cout << "Wrote EK Pub to " << ekpubFile << endl;
}

/**
 * Retrieves EK cert from NVRAM and writes it to tmp directory %tmp%/ek.cert
 */
void process_get_ekcert()
{
    auto ekcertFile = prepend_tempdir_path("ek.cer");
    auto ekcert = g_tpm.GetEkNvCert();
    std::ofstream ekcertf(ekcertFile);
    std::ostream_iterator<unsigned char> ekcertItr(ekcertf);
    std::copy(ekcert.begin(), ekcert.end(), ekcertItr);
    cout << "Wrote EK Cert to " << ekcertFile << endl;
}

/**
 * Retrieves AIK pub from NVRAM and writes the packed TPM2B_PUBLIC
 * to tmp directory %tmp%/aik.pub
 */
void process_get_aikpub()
{
    auto aikpubFile = prepend_tempdir_path("aik.pub");
    auto aikPub = g_tpm.GetAIKPub();
    std::ofstream aikpubf(aikpubFile);
    std::ostream_iterator<unsigned char> aikpubItr(aikpubf);
    std::copy(aikPub.begin(), aikPub.end(), aikpubItr);
    cout << "Wrote AIK Pub to " << aikpubFile << endl;
}

/**
 * Retrieves AIK cert from NVRAM and writes it to tmp directory %tmp%/aik.cert
 */
void process_get_aikcert()
{
    auto aikcertFile = prepend_tempdir_path("aik.cert");
    auto aikcert = g_tpm.GetAIKCert();
    std::ofstream aikcertf(aikcertFile);
    std::ostream_iterator<unsigned char> aikcertItr(aikcertf);
    std::copy(aikcert.begin(), aikcert.end(), aikcertItr);
    cout << "Wrote AIK Cert to " << aikcertFile << endl;
}

/*
 * Retrieves quote over PCRs and writes it to tmp directory %tmp%/pcrquote_HASHALG
 * Retrieves signature of quote using AIK pub and writes it to tmp directory %tmp%/pcrsig_HASHALG
 * HashAlgs supported: Sha1, Sha256, Sha384
 */
void process_get_pcrquote()
{
    Tss2Ctx tmpCtx;
    attest::PcrList pcrs(Tss2Util::GetPcrCount(tmpCtx));
    //Populate the pcrs with the increasing values.
    std::iota(pcrs.begin(), pcrs.end(), 0);

    std::vector<string> pcrquoteFiles = { prepend_tempdir_path("pcrquote_sha1"),prepend_tempdir_path("pcrquote_sha256"), prepend_tempdir_path("pcrquote_sha384") };
    std::vector<string> pcrsigFiles = { prepend_tempdir_path("pcrsig_sha1"), prepend_tempdir_path("pcrsig_sha256"), prepend_tempdir_path("pcrsig_sha384") };
    std::vector<attest::HashAlg> hashAlgs = {attest::HashAlg::Sha1, attest::HashAlg::Sha256, attest::HashAlg::Sha384};

    for (int i = 0; i < hashAlgs.size(); i++)
    {
        auto pcrquoteFile = pcrquoteFiles[i];
        auto pcrsigFile = pcrsigFiles[i];
        std::ofstream pcrquotef(pcrquoteFile);
        std::ofstream pcrsigf(pcrsigFile);
        std::ostream_iterator<unsigned char> pcrquoteItr(pcrquotef);
        std::ostream_iterator<unsigned char> pcrsigItr(pcrsigf);

        auto pcrQuote = g_tpm.GetPCRQuote(pcrs, hashAlgs[i]);
        std::copy(pcrQuote.quote.begin(), pcrQuote.quote.end(), pcrquoteItr);
        std::copy(pcrQuote.signature.begin(), pcrQuote.signature.end(), pcrsigItr);
        cout << "Wrote PCR Quote to " << pcrquoteFile << endl;
        cout << "Wrote PCR Signature to " << pcrsigFile << endl;
    }
}

/*
 * Retrieves PCR values from TPM and writes it to tmp directory %tmp%/pcrlist
 *
 * Formats it in the same manner as tpm2_pcrlist so that it can be
 * compared directly using diff to the contents of tpm2_pcrlist
 */
void process_get_pcrvalues()
{
    auto pcrvalsFile = prepend_tempdir_path("pcrlist");
    std::ofstream pcrvalsf(pcrvalsFile);
    Tss2Ctx tmpCtx;
    attest::PcrList pcrs(Tss2Util::GetPcrCount(tmpCtx));
    //Populate the pcrs with the increasing values.
    std::iota(pcrs.begin(), pcrs.end(), 0);

    std::vector<attest::HashAlg> hashAlgs = {attest::HashAlg::Sha1, attest::HashAlg::Sha256, attest::HashAlg::Sha384 };

    // formatting to be the same as tpm2_pcrlist command
    for (auto &hashAlg : hashAlgs) {
        switch (hashAlg) {
            case attest::HashAlg::Sha1:
                pcrvalsf << "sha1:" << endl;
                break;
            case attest::HashAlg::Sha256:
                pcrvalsf << "sha256:" << endl;
                break;
            case attest::HashAlg::Sha384:
                pcrvalsf << "sha384:" << endl;
                break;
        }

        auto pcrValues = g_tpm.GetPCRValues(pcrs, hashAlg);
        for (auto &pcrVal : pcrValues.pcrs) {
            pcrvalsf << "  " << dec << (int) pcrVal.index;
            if (pcrVal.index < 10) {
                pcrvalsf << " : ";
            } else {
                pcrvalsf << ": ";
            }
            pcrvalsf << "0x" << hex << uppercase;

            for (auto &byte : pcrVal.digest) {
                // this ensures leading zero not lost when printing out byte
                pcrvalsf << setfill('0') << setw(2) << (int) byte;
            }
            pcrvalsf << endl;
        }
    }

    cout << "Wrote PCR Values to " << pcrvalsFile << endl;
}

/**
 * Retrieves boot measurements log from sysfs and writes it to
 * tmp directory %tmp%/bios_measurements
 */
void process_get_tcglog()
{
    auto tcglogFile = prepend_tempdir_path("bios_measurements");
    auto tcgLog = g_tpm.GetTcgLog();
    std::ofstream tcglogf(tcglogFile);
    std::ostream_iterator<unsigned char> tcglogItr(tcglogf);
    std::copy(tcgLog.begin(), tcgLog.end(), tcglogItr);
    cout << "Wrote TCG Log to " << tcglogFile << endl;
}

/**
 * Generates an EK in the TPM. Will not read from nvram
 */
void process_create_ek()
{
    try
    {
        g_tpm.RemovePersistentEk();
    }
    catch(exception& e)
    {
        // Best effort since the EK may not be there
        cout << e.what() << endl;
    }
    cout << "Generating new EK. This may take a few seconds..." << endl;
    // Force ekpub creation
    auto ekPub = g_tpm.GetEkPub();
    cout << "Generated new EK" << endl;
}

/**
 * Seals some mock data and uses the tpm to unseal it
 */
void process_unseal()
{
    Tss2Ctx tmpCtx;
    std::vector<unsigned char> inPub;
    std::vector<unsigned char> inPriv;
    std::vector<unsigned char> encryptedSeed;

    attest::HashAlg hashAlg = attest::HashAlg::Sha256;
    attest::PcrSet pcrSet;
    pcrSet.hashAlg = hashAlg;

    // Seal/unseal data to first 14 PCRs
    for (int i = 0; i < 14; i++)
    {
        pcrSet.pcrs.push_back(attest::PcrValue());
        pcrSet.pcrs[i].index = i;
    }

    TestUtil::PopulateCurrentPcrs(tmpCtx, pcrSet);

    // Fake seal data
    std::vector<unsigned char> clearKey{'A', 'B', 'C'};
    TestUtil::SealSeedToEk(tmpCtx, pcrSet, hashAlg, clearKey, inPub, inPriv, encryptedSeed);

    auto data = g_tpm.Unseal(inPub, inPriv, encryptedSeed, pcrSet, hashAlg, false);

    cout << "Expected Seed: 0x";
    std::ios state(NULL);
    state.copyfmt(std::cout);
    cout << hex;
    for (auto& byte : clearKey)
    {
        // this ensures leading zero not lost when printing out byte
        cout << setfill('0') << setw(2) << (int)byte;
    }
    cout.copyfmt(state);
    cout << endl;

    cout << "Actual decrypted seed: 0x";
    state.copyfmt(std::cout);
    cout << hex;
    for (auto& byte : data)
    {
        cout << (int)byte;
    }
    cout.copyfmt(state);
    cout << endl;
}

using test_function = void(*)();

static unordered_map<string, test_function> g_tests = {
    {"tpmversion", process_get_tpmversion},
    {"ekpub", process_get_ekpub},
    {"ekcert", process_get_ekcert},
    {"aikpub", process_get_aikpub},
    {"aikcert", process_get_aikcert},
    {"pcrquote", process_get_pcrquote},
    {"pcrvalues", process_get_pcrvalues},
    {"tcglog", process_get_tcglog},
    {"generateek", process_create_ek},
    {"unseal", process_unseal}
};

void print_usage() {
    cout << "Usage: TpmUtil <commands>" << endl;
    cout << "\nSupported Commands:" << endl;
    cout << "\tall" << endl;
    cout << "\thardware_tpm" << endl;
    cout << "\tgen2_vtpm" << endl;
    for (auto it : g_tests)
    {
        cout << "\t" << it.first << endl;
    }
    cout << endl;
}

/**
 * Runs a test with name cmd_name
 *
 * returns true if test exists and succeeds. Else returns false
 */
bool process_command(string cmd_name)
{
    auto it = g_tests.find(cmd_name);
    if (it != g_tests.end())
    {
        cout << "Processing Action: " << it->first << endl;
        try {
            (*it->second)();
        } catch (Tss2Exception& e) {
            output_tss2_error(e);
            cout << endl;
            return false;
        } catch (std::exception& e) {
            cout << "Error for command '" << cmd_name << "': " << e.what() << endl << endl;
            return false;
        }
        cout << endl;
    }
    else
    {
        cout << "Unknown command " << cmd_name << endl;
        return false;
    }

    return true;
}

/**
 * Runs every test except AIK tests
 *
 * returns true if all tests succeed. Else returns false
 */
bool process_hardware_tpm()
{
    bool all_succeeded = true;
    for (auto it : g_tests)
    {
        // ignore aik tests
        if (it.first.compare("aikpub") == 0 ||
            it.first.compare("aikcert") == 0) continue;

        // Will only be true if all commands return true
        all_succeeded = process_command(it.first) && all_succeeded;
    }

    return all_succeeded ? 0 : 1;
}

/**
 * Runs every test except EK tests
 *
 * returns true if all tests succeed. Else returns false
 */
bool process_gen2_vtpm()
{
    // TODO: populate aik pub and cert with data before running test

    bool all_succeeded = true;
    for (auto it : g_tests)
    {
        // ignore ek tests
        if (it.first.compare("ekpub") == 0 ||
            it.first.compare("ekcert") == 0 ||
            it.first.compare("generateek") == 0) continue;

        // Will only be true if all commands return true
        all_succeeded = process_command(it.first) && all_succeeded;
    }

    return all_succeeded ? 0 : 1;
}
/**
 * Runs every test in g_tests
 *
 * returns true if all tests succeed. Else returns false
 */
bool process_all()
{
    bool all_succeeded = true;
    for (auto it : g_tests)
    {
        // Will only be true if all commands return true
        all_succeeded = process_command(it.first) && all_succeeded;
    }

    return all_succeeded ? 0 : 1;
}

/**
 * Runs all tests specified in commandline arguments
 */
int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        exit(1);
    }

#ifdef PLATFORM_UNIX
    // Turn off Esys logging. Its too noisy and libtpm2 will log any
    // noteworthy failures
    setenv("TSS2_LOG" , "all+NONE", 1);
#endif //PLATFORM_UNIX

    for (int i = 1; i < argc; i++) {
        string cmd(argv[i]);

        // If command is all, run them all and exit
        if (cmd.compare("all") == 0) {
            cout << endl;
            return process_all() ? 0 : 1;
        }
        else if (cmd.compare("hardware_tpm") == 0) {
            cout << endl;
            return process_hardware_tpm() ? 0 : 1;
        }
        else if (cmd.compare("gen2_vtpm") == 0) {
            cout << endl;
            return process_gen2_vtpm() ? 0 : 1;
        }
        else
        {
            return process_command(cmd) ? 0 : 1;
        }
    }

    return 0;
}
