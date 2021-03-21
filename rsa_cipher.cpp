#include "rsa_cipher.h"

#include <cmath>
#include <random>
#include <iostream>

std::map<wchar_t, uint8_t> alpha{
	{ L'а', 1 },  { L'б', 2 },  { L'в', 3 },
	{ L'г', 4 },  { L'д', 5 },  { L'е', 6 },
	{ L'ё', 7 },  { L'ж', 8 },  { L'з', 9 },
	{ L'и', 10 }, { L'й', 11 }, { L'к', 12 },
	{ L'л', 13 }, { L'м', 14 }, { L'н', 15 },
	{ L'о', 16 }, { L'п', 17 }, { L'р', 18 },
	{ L'с', 19 }, { L'т', 20 }, { L'у', 21 },
	{ L'ф', 22 }, { L'х', 23 }, { L'ц', 24 },
	{ L'ч', 25 }, { L'ш', 26 }, { L'щ', 27 },
	{ L'ъ', 28 }, { L'ы', 29 }, { L'ь', 30 },
	{ L'э', 31 }, { L'ю', 32 }, { L'я', 33 },
	{ L' ', 34 }
};

std::map<uint8_t, wchar_t> reverse_alpha{
	{ 1, L'а' },  { 2, L'б' },  { 3, L'в' },
	{ 4, L'г' },  { 5, L'д' },  { 6, L'е' },
	{ 7, L'ё', }, { 8, L'ж' },  { 9, L'з' },
	{ 10, L'и' }, { 11, L'й' }, { 12, L'к' },
	{ 13, L'л' }, { 14, L'м' }, { 15, L'н' },
	{ 16, L'о' }, { 17, L'п' }, { 18, L'р' },
	{ 19, L'с' }, { 20, L'т' }, { 21, L'у' },
	{ 22, L'ф' }, { 23, L'х' }, { 24, L'ц' },
	{ 25, L'ч' }, { 26, L'ш' }, { 27, L'щ' },
	{ 28, L'ъ' }, { 29, L'ы' }, { 30, L'ь' },
	{ 31, L'э' }, { 32, L'ю' }, { 33, L'я' },
	{ 34, L' ' }
};

struct GcdExtResult {
	uint32_t divisor{};
	int32_t x{};
	int32_t y{};
};

GcdExtResult GcdExt(uint32_t __a, uint32_t __b) {
	if (__b == 0) {
		return GcdExtResult{ __a, 1, 0 };
	}

	GcdExtResult result = GcdExt(__b, __a % __b);

	return GcdExtResult{ result.divisor, result.y,
		result.x - result.y * static_cast<int32_t>(__a / __b) };
}

bool IsPrime(uint32_t __number) {
	for (size_t i = 2; i < static_cast<uint32_t>(std::sqrt(__number)); ++i) {
		if (!(__number % i)) {
			return false;
		}
	}

	return true;
}

uint32_t GetPrimeNumber(uint32_t __max) {
	std::random_device randomDevice;
	std::uniform_int_distribution<uint32_t> distribution(1, __max);

	uint32_t result = distribution(randomDevice);

	while (!IsPrime(result)) {
		--result;
	}

	return result;
}

std::vector<bool> GetBits(uint32_t __number) {
	std::vector<bool> result;

	while (__number != 0) {
		result.insert(result.begin(), __number % 2);
		__number /= 2;
	}

	return result;
}

uint32_t ModularProduct(uint32_t __a, uint32_t __b, uint32_t __modulus) {
	return (static_cast<uint64_t>(__a % __modulus) *
		static_cast<uint64_t>(__b % __modulus) % __modulus);
}

uint32_t BinaryPower(uint32_t __number, uint32_t __power, uint32_t __modulus) {
	auto bits = GetBits(__power);
	uint32_t result{ __number };

	for (size_t i = 1; i < bits.size(); ++i) {
		result = ModularProduct(result, result, __modulus);

		if (bits[i] == true) {
			result = ModularProduct(result, __number, __modulus);
		}
	}

	return result;
}

RsaCipher::RsaCipher() {
	std::wcout << L"Инициализация шифратора..." << std::endl;
	std::wcout << L"Генерация основания n..." << std::endl;

	uint32_t pNumber = GetPrimeNumber(1 << 15);
	uint32_t qNumber = GetPrimeNumber(1 << 15);

	while (pNumber == qNumber) {
		qNumber = GetPrimeNumber(1 << 15);
	}

	modulus_ = pNumber * qNumber;

	std::wcout << L"Основание n = " << modulus_ << std::endl;
	std::wcout << L"Генерация ключей e и d..." << std::endl;

	uint32_t eulerNumber = (pNumber - 1) * (qNumber - 1);

	std::random_device randomDevice;
	std::uniform_int_distribution<uint32_t> distribution(2, eulerNumber * 2);

	uint32_t eNumber = distribution(randomDevice);

	auto gcdResult = GcdExt(eulerNumber, eNumber);

	while (gcdResult.divisor != 1 || gcdResult.y <= 0) {
		eNumber = distribution(randomDevice);
		gcdResult = GcdExt(eulerNumber, eNumber);
	}

	public_key_ = eNumber;
	private_key_ = gcdResult.y;

	std::wcout << L"Открытый ключ e = " << public_key_ << std::endl;
	std::wcout << L"Закрытый ключ d = " << private_key_ << std::endl;
	std::wcout << L"Инициализация завершена\n" << std::endl;
}

std::vector<uint32_t> RsaCipher::Encrypt(const std::wstring& __message) {
	std::vector<uint32_t> result;
	uint32_t temp{};

	for (size_t i = 0; i < __message.size(); ++i) {
		if (i % 2) {
			temp = (static_cast<uint32_t>(alpha.at(__message[i - 1])) << 6) |
				alpha.at(__message[i]);
		}
		else if (i == __message.size() - 1) {
			temp = static_cast<uint32_t>(alpha.at(__message[i])) << 6;
		}
		else {
			continue;
		}
		
		result.push_back(BinaryPower(temp, public_key_, modulus_));
	}

	return result;
}

std::wstring RsaCipher::Decrypt(const std::vector<uint32_t>& __message) {
	std::wstring result;

	for (size_t i = 0; i < __message.size(); ++i) {
		uint32_t block = BinaryPower(__message[i], private_key_, modulus_);

		result.push_back(reverse_alpha.at(block >> 6));
		if ((block & 0x0000003F) != 0) {
			result.push_back(reverse_alpha.at(block & 0x0000003F));
		}
	}

	return result;
}