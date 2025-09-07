#include "WFPakCrypt.h"
#include <iostream>

void InitRSA(unsigned char* rsa_key)
{
	ltc_mp = ltm_desc;
	register_hash(&sha1_desc);
	register_hash(&sha256_desc);
	register_cipher(&twofish_desc);
	register_prng(&yarrow_desc);
	rng_make_prng(128, find_prng("yarrow"), &g_yarrow_prng_state, NULL);
	rsa_import(rsa_key, 140, &g_rsa_key_public_for_sign);
}

bool DecryptPak(const char* fin, const char* fout) {
	file f = fopen_(fin, "r");
	file fo = fopen_(fout, "w");

	if (f == NULL || fo == NULL)
		return false;

	ZipDir zipDir;
	if (!zipDir.FindCDREnd(f))
		return false;
	if (!zipDir.Prepare(f))
		return false;
	if (!zipDir.BuildFileEntryMap(f, fo, false))
		return false;

	if (fo)
		fclose_(fo);
	if (f)
		fclose_(f);

	return true;
}

bool isDirectory(const char* path) {
	DWORD attr = GetFileAttributesA(path);
	return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

bool isFile(const char* path) {
	DWORD attr = GetFileAttributesA(path);
	return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

std::vector<unsigned char> parseHexFile(const char* filename) {
	std::ifstream file(filename);
	if (!file) {
		std::cerr << "Failed to open file: " << filename << std::endl;
		return std::vector<unsigned char>();
	}

	std::vector<unsigned char> result;
	std::string token;

	while (file >> token) {
		unsigned int byte;
		std::stringstream ss;
		ss << std::hex << token;												
		ss >> byte;
		result.push_back(static_cast<unsigned char>(byte));
	}

	return result;
}

void findPakFiles(const std::string& directory, std::vector<char*>& pakFiles) {
	std::string searchPath = directory + "\\*";

	WIN32_FIND_DATAA findData;
	HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

	if (hFind == INVALID_HANDLE_VALUE)
		return;

	do {
		const char* name = findData.cFileName;

		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
			continue;

		std::string fullPath = directory + "\\" + name;

		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			findPakFiles(fullPath, pakFiles);
		}
		else {
			const char* ext = strrchr(name, '.');
			if (ext && _stricmp(ext, ".pak") == 0) {
				char* pathCopy = new char[fullPath.length() + 1];
				strcpy(pathCopy, fullPath.c_str());
				pakFiles.push_back(pathCopy);
			}
		}

	} while (FindNextFileA(hFind, &findData));

	FindClose(hFind);
}

int main(int argc, char** argv) {

	if (argc < 2) {
		printf("Usage: WFPakCrypt.exe <pak_or_directory_path>\n");
		return 1;
	}

	std::string rsaFile = std::string(argv[0]).substr(0, std::string(argv[0]).find_last_of("\\/")) + "\\rsa.txt";
	std::ifstream testFile(rsaFile);
	if (!testFile) {
		printf("rsa.txt not found!\n");
		return 1;
	}

	std::vector<unsigned char> keyData = parseHexFile(rsaFile.c_str());

	unsigned char* g_RSAKeyData = new unsigned char[keyData.size()];
	for (size_t i = 0; i < keyData.size(); ++i) {
		g_RSAKeyData[i] = keyData[i];
	}

	InitRSA(g_RSAKeyData);

	std::string inputPath = argv[1];
	std::vector<char*> pakFiles;

	if (isFile(inputPath.c_str())) {
		char* buf = new char[inputPath.length() + 1];
		strcpy(buf, inputPath.c_str());
		pakFiles.push_back(buf);
	}
	else if (isDirectory(inputPath.c_str())) {
		findPakFiles(inputPath, pakFiles);
	}
	else {
		printf("Invalid path or unsupported type.\n");
	}

	for (char* path : pakFiles) {
		std::string zipPath = std::string(path) + ".zip";

		if (!DecryptPak(path, zipPath.c_str()))
			return 1;

		printf("%s decrypted\n", path);
	}

	return 0;
} 