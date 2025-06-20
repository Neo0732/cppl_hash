#define ItIsFinal

#include <iostream> // C++ 헤더
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>

class SHA1 { //SHA1 처리부 정의
public: // 패딩+사전처리 등
    SHA1() {reset();}

    void update(const std::string&s) { // 입력값 받아오기
        for (char c:s) { // 입력값만큼 반복:
            update((uint8_t)c); // 바이트 단위로 분할
        }
    }

    void update(uint8_t data) { // 위에서 분할한 값 받아오기
        buffer[bufferIndex++]=data; // 받아서 버퍼로 쏘기, 인덱스에 버퍼 위치 저장
        messageLength+=8; // 전체 입력값의 비트값 추적
        if (bufferIndex==64) { // 버퍼 가득 찼다면?
            processBlock();
            bufferIndex=0; // 버퍼 비우기
        }
    }

    std::string final() { // 패딩절차 및 해시 반환부
        buffer[bufferIndex++]=0x80; // 원문에 끝부분 표시
        if (bufferIndex>56) { // 버퍼 남은공간 56 넘으면:
            while (bufferIndex<64) buffer[bufferIndex++]=0x00;
            processBlock();
            bufferIndex=0; // 64바이트까지 0으로 치환, 프로세스 블락 호출해 새로고침
        }
        while (bufferIndex<56) buffer[bufferIndex++]=0x00; // 다시 버퍼 56바이트까지 0으로 채운 후 마지막 8자리에 원문 길이를 빅-엔디언으로 저장

        uint64_t len=messageLength;
        for (int i=7;i>=0;--i) {
            buffer[bufferIndex++]=(uint8_t)((len>>(i*8))&0xFF);
        }
        processBlock(); // 패딩 끝내고 프로세스 블락 함수 호출 -> 새로고침

        std::ostringstream result;
        for (int i=0;i<5;++i) {
            result<<std::hex<<std::setw(8)<<std::setfill('0')<<digest[i]; // 5개의 32비트 해시값 -> 8자리의 16진수 문자열 변환
        }
        reset(); // 내부 초기화
        return result.str();
    }

private: // 해시 처리+반환
    uint32_t digest[5]; // SHA1 160비트 해시 저장소
    uint8_t buffer[64]; // 원문 512비트 임시 저장 버퍼
    size_t bufferIndex; // 버퍼에 저장된 데이터 주소/위치
    uint64_t messageLength; // 원문 메시지 비트 길이 추적

    void reset() { // 내부 초기화 함수 정의
        digest[0]=0x67452301; // SHA1 표준 약속된 함숫값
        digest[1]=0xEFCDAB89; // SHA1 표준 약속된 함숫값
        digest[2]=0x98BADCFE; // SHA1 표준 약속된 함숫값
        digest[3]=0x10325476; // SHA1 표준 약속된 함숫값
        digest[4]=0xC3D2E1F0; // SHA1 표준 약속된 함숫값
        bufferIndex=0; // 버퍼 데이터 위칫값 초기화
        messageLength=0; // 비트 길잇값 초기화
    }

    void processBlock() { // 프로세스 블락 함수 정의 => 버퍼 데이터 -> SHA1 해시
        uint32_t w[80];
        for (int i=0;i<16;++i) {
            w[i]=(buffer[i*4]<<24) | (buffer[i*4+1]<<16) |
                   (buffer[i*4+2]<<8) | buffer[i*4+3];
        }
        for (int i=16;i<80;++i) {
            w[i]=rotl(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
        } // 4바이트씩 묶음, 16개짜리 32비트 형식으로 변환

        uint32_t a=digest[0], b=digest[1], c=digest[2], d=digest[3], e=digest[4]; // SHA1 메인 루프(80라운드)

        for (int i=0;i<80;++i) {
            uint32_t f, k;
            if (i<20) { // 루프1
                f=(b&c) | ((~b)&d);
                k=0x5A827999;
            } else if (i<40) { // 루프2
                f=b^c^d;
                k=0x6ED9EBA1;
            } else if (i<60) { // 루프3
                f=(b&c) | (b&d) | (c&d);
                k=0x8F1BBCDC;
            } else { // 루프4
                f=b^c^d;
                k=0xCA62C1D6;
            }
            uint32_t temp=rotl(a, 5)+f+e+k+w[i];
            e=d;
            d=c;
            c=rotl(b, 30);
            b=a;
            a=temp;
        }
        // a~e 임시변수 + f, k 상수 => 해시 생성 -> 다이제스트 함숫값 배열에 쌓아 저장

        digest[0]+=a;
        digest[1]+=b;
        digest[2]+=c;
        digest[3]+=d;
        digest[4]+=e;
    }

    uint32_t rotl(uint32_t value, int bits) { // 최종 32비트 결괏값 -> 왼쪽으로 비트시프트 처리해 옮기기
        return (value<<bits) | (value>>(32 - bits)); // --최종 SHA1 해시 반환--
    }
}
;

class MD5 { // MD5 처리부 정의
private: // 패딩+사전처리
    uint32_t h[4]={ // MD5 알고리즘 초기 해시값 리틀-엔디언으로 정의
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476
    };
    
    static const int s[64]; // 변환 라운드에서 사용하는 시프트 값
    
    static const uint32_t K[64]; // 변환 라운드에서 사용하는 상수값
    
    uint32_t leftRotate(uint32_t value, int shift) {
        return (value<<shift) | (value>>(32-shift));
    }
    // 왼쪽 이전 비트시프트 처리

    uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
        return (x&y) | (~x&z);
    }
    
    uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
        return (x&z) | (y&~z);
    }
    
    uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
        return x^y^z;
    }
    
    uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
        return y^(x|~z);
    }
    // 각 라운드에 활용되는 MD5의 주사용 함수
    
    // 원문을 512비트 블록으로 패딩
    std::vector<uint8_t> padMessage(const std::string& message) {
        std::vector<uint8_t> padded;
        
        for (char c : message) {
            padded.push_back(static_cast<uint8_t>(c));
        }
        // 원문을 바이트 배열로 변환
        
        uint64_t originalLength=message.length()*8;
        // 원문 길이를 비트 단위로 저장
        
        padded.push_back(0x80); // 패딩 위해 먼저 1비트 추가
        
        while (padded.size()%64!=56) {
            padded.push_back(0x00);
        }
        // 원문 길이 512비트 -> 448비트가 될 때까지 0으로 패딩, 끝 64비트는 원문 길이 저장
        
        for (int i=0;i<8;i++) {
            padded.push_back(static_cast<uint8_t>(originalLength>>(i*8)));
        }
        // 원문 길이를 64비트 리틀-엔디안 형식으로 추가

        return padded;
    }
    
public: // 해시 처리+반환
    std::string hash(const std::string& message) {
        std::vector<uint8_t> paddedMessage=padMessage(message);
        // 패딩 결괏값 불러오기

        for (size_t i=0;i<paddedMessage.size();i+=64) {
            processBlock(&paddedMessage[i]);
        }
        // 512비트 단위로 원문 처리
        
        return toHexString();
        // 최종 해시값을 16진수 문자열로
    }
    
private: // 512비트 블록 처리
    void processBlock(const uint8_t* block) {
        // 원문을 16개의 32비트 조각으로 변환
        uint32_t w[16];
        for (int i=0;i<16;i++) {
            w[i] = static_cast<uint32_t>(block[i*4]) |
                   (static_cast<uint32_t>(block[i*4+1])<<8) |
                   (static_cast<uint32_t>(block[i*4+2])<<16) |
                   (static_cast<uint32_t>(block[i*4+3])<<24);
        }
        
        // 해시값을 주 변수에 복사
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3];
        
        // 4라운드 16회의 연산 수행, 루프당 다른 함수F,G와 인덱스 사용
        for (int i=0;i<64;i++) {
            uint32_t f, g;
            
            if (i<16) { // 루프1
                f=F(b, c, d);
                g=i;
            } else if (i<32) { // 루프2
                f=G(b, c, d);
                g=(5*i+1)%16;
            } else if (i<48) { // 루프3
                f=H(b, c, d);
                g=(3*i+5)%16;
            } else { // 루프4
                f=I(b, c, d);
                g=(7*i)%16;
            }
            
            // MD5 표준 마무리 연산(덧셈/회전/재배열)
            f=f+a+K[i]+w[g];
            a=d;
            d=c;
            c=b;
            b=b+leftRotate(f, s[i]);
        }
        
        // 루프 결과를 해시값에 누적
        h[0]+=a;
        h[1]+=b;
        h[2]+=c;
        h[3]+=d;
    }
    
    // 최종 해시값을 16진수 문자열로 변환
    std::string toHexString() {
        std::stringstream ss;
        ss<<std::hex<<std::setfill('0');
        
        // 리틀 엔디안 순서로 바이트를 16진수로 변환
        for (int i=0;i<4;i++) {
            for (int j=0;j<4;j++) {
                ss<<std::setw(2)<<((h[i]>>(j*8))&0xFF);
            }
        }
        
        return ss.str();
    }
};

// MD5 표준 정적변수 정의
const int MD5::s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, // 루프1
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, // 루프2
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, // 루프3
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 // 루프4
};

const uint32_t MD5::K[64] = {
    // sin 기반 MD5 표준 상수값 (2^32*abs(sin(i+1)))
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

int main () {
    int type=0;
    printf("텍스트 해싱 툴 v0.0.1\nSHA1으로 변환하려면 '1', MD5로 변환하려면 '2'를 입력하십시오... ");
    scanf("%d", &type);

    if (type==1) {
        printf("\n선택한 모드가 SHA1 모드입니다.");
        SHA1 sha1;
        char UserInputStr[1024];
        std::cout<<"\nSHA1으로 해시 처리할 1024자 이하의 문자열을 입력하십시오... ";
        std::scanf("%1023s", UserInputStr);
        std::string inputStr(UserInputStr);
        sha1.update(inputStr);
        std::string hash=sha1.final();
        std::cout<<"\nSHA1 해시입니다: "<<hash<<std::endl;
        printf("\n\n반환 코드 200(OK)으로 프로그램 종료함");
        return 200;
    }
    
    else if (type==2) {
            printf("\n선택한 모드가 MD5 모드입니다.");
            MD5 md5;
            char UserInputStr[1024];
            std::cout << "\nMD5로 해시 처리할 1024자 이하의 문자열을 입력하십시오... ";
            std::scanf("%1023s", UserInputStr);
            std::string inputStr(UserInputStr);
            std::string hash = md5.hash(inputStr);
            std::cout << "\nMD5 해시입니다: "<< hash << std::endl;
            printf("\n\n반환 코드 200(OK)으로 프로그램 종료함");
            return 200;
    }
    
    else {
        printf("\n유효한 입력이 아닙니다.\n한 자리의 숫자 '1' 혹은 '2'를 입력했는지 확인하여 주십시오.\n\n종료 코드 400(BadRequest)으로 프로세스 종료함");
        return 400;
    }
}