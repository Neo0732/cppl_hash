#define forMD5

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>

class MD5 {
private:
    // MD5 알고리즘에서 사용하는 초기 해시값 (little-endian)
    uint32_t h[4] = {
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476
    };
    
    // 각 라운드에서 사용하는 시프트 값들
    static const int s[64];
    
    // 각 라운드에서 사용하는 상수값들 (sin 함수 기반)
    static const uint32_t K[64];
    
    // 좌측 회전 연산 (비트 시프트)
    uint32_t leftRotate(uint32_t value, int shift) {
        return (value << shift) | (value >> (32 - shift));
    }
    
    // MD5의 핵심 함수들 - 각 라운드에서 사용
    uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (~x & z);
    }
    
    uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
        return (x & z) | (y & ~z);
    }
    
    uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }
    
    uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
        return y ^ (x | ~z);
    }
    
    // 메시지를 512비트 블록으로 패딩
    std::vector<uint8_t> padMessage(const std::string& message) {
        std::vector<uint8_t> padded;
        
        // 원본 메시지를 바이트 배열로 변환
        for (char c : message) {
            padded.push_back(static_cast<uint8_t>(c));
        }
        
        // 메시지 길이를 비트 단위로 저장 (패딩 전)
        uint64_t originalLength = message.length() * 8;
        
        // 패딩: 먼저 1비트(0x80) 추가
        padded.push_back(0x80);
        
        // 메시지 길이가 512비트 블록에서 448비트가 될 때까지 0 패딩
        // (마지막 64비트는 원본 길이 정보용)
        while (padded.size() % 64 != 56) {
            padded.push_back(0x00);
        }
        
        // 원본 메시지 길이를 64비트 little-endian으로 추가
        for (int i = 0; i < 8; i++) {
            padded.push_back(static_cast<uint8_t>(originalLength >> (i * 8)));
        }
        
        return padded;
    }
    
public:
    // 메인 해싱 함수
    std::string hash(const std::string& message) {
        // 1. 메시지 패딩
        std::vector<uint8_t> paddedMessage = padMessage(message);
        
        // 2. 512비트(64바이트) 블록 단위로 처리
        for (size_t i = 0; i < paddedMessage.size(); i += 64) {
            processBlock(&paddedMessage[i]);
        }
        
        // 3. 최종 해시값을 16진수 문자열로 변환
        return toHexString();
    }
    
private:
    // 각 512비트 블록을 처리하는 핵심 함수
    void processBlock(const uint8_t* block) {
        // 블록을 16개의 32비트 워드로 변환 (little-endian)
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = static_cast<uint32_t>(block[i * 4]) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
        }
        
        // 현재 해시값을 작업 변수에 복사
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        
        // 4라운드, 각 라운드마다 16번의 연산 수행
        for (int i = 0; i < 64; i++) {
            uint32_t f, g;
            
            // 라운드별로 다른 함수와 인덱스 사용
            if (i < 16) {
                // 라운드 1: F 함수 사용
                f = F(b, c, d);
                g = i;
            } else if (i < 32) {
                // 라운드 2: G 함수 사용
                f = G(b, c, d);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                // 라운드 3: H 함수 사용
                f = H(b, c, d);
                g = (3 * i + 5) % 16;
            } else {
                // 라운드 4: I 함수 사용
                f = I(b, c, d);
                g = (7 * i) % 16;
            }
            
            // MD5의 핵심 연산: 덧셈, 회전, 재배치
            f = f + a + K[i] + w[g];
            a = d;
            d = c;
            c = b;
            b = b + leftRotate(f, s[i]);
        }
        
        // 이 블록의 결과를 누적 해시값에 더함
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
    }
    
    // 최종 해시값을 16진수 문자열로 변환
    std::string toHexString() {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        
        // little-endian 순서로 각 바이트를 16진수로 변환
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                ss << std::setw(2) << ((h[i] >> (j * 8)) & 0xFF);
            }
        }
        
        return ss.str();
    }
};

// 정적 멤버 변수 정의
const int MD5::s[64] = {
    // 라운드 1의 시프트 값들
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    // 라운드 2의 시프트 값들
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    // 라운드 3의 시프트 값들
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    // 라운드 4의 시프트 값들
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

const uint32_t MD5::K[64] = {
    // sin 함수를 기반으로 한 상수값들 (2^32 * abs(sin(i+1)))
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// 사용 예제
int main() {
    MD5 md5;
    std::string input;
    
    std::cout << "MD5 해시 계산기" << std::endl;
    std::cout << "텍스트를 입력하세요: ";
    std::getline(std::cin, input);
    
    std::string hash = md5.hash(input);
    
    std::cout << "\n입력: " << input << std::endl;
    std::cout << "MD5 해시: " << hash << std::endl;
    
    // 테스트 케이스들
    std::cout << "\n=== 테스트 케이스 ===" << std::endl;
    std::cout << "빈 문자열: " << md5.hash("") << std::endl;
    std::cout << "\"a\": " << md5.hash("a") << std::endl;
    std::cout << "\"abc\": " << md5.hash("abc") << std::endl;
    std::cout << "\"Hello, World!\": " << md5.hash("Hello, World!") << std::endl;
    
    return 0;
}