#include <iostream>
#include <vector>
#include <array>
#include <cstring>

const uint32_t constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t initial_hashes[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

inline uint32_t rightRotate(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32 - bits));
}

std::vector<uint8_t> padMessage(const std::string& message) {
    size_t original_len = message.length();
    size_t padded_len = original_len + 1; // Include the 0x80 byte
    while (padded_len % 64 != 56) {
        padded_len++;
    }

    std::vector<uint8_t> padded_message(padded_len + 8); // +8 for the length
    std::memcpy(padded_message.data(), message.c_str(), original_len);
    padded_message[original_len] = 0x80; // Append the 0x80 byte

    uint64_t bit_length = original_len * 8;
    for (int i = 0; i < 8; i++) {
        padded_message[padded_len + i] = (bit_length >> (56 - 8 * i)) & 0xFF;
    }

    return padded_message;
}

std::array<uint32_t, 8> sha256Transform(const std::vector<uint8_t>& message) {
    std::array<uint32_t, 8> hash_values = {initial_hashes[0], initial_hashes[1], initial_hashes[2], initial_hashes[3],
                                           initial_hashes[4], initial_hashes[5], initial_hashes[6], initial_hashes[7]};

    size_t chunks = message.size() / 64;
    for (size_t i = 0; i < chunks; i++) {
        uint32_t w[64];
        const uint8_t* chunk = message.data() + i * 64;

        for (int j = 0; j < 16; j++) {
            w[j] = (chunk[j*4] << 24) | (chunk[j*4 + 1] << 16) | (chunk[j*4 + 2] << 8) | (chunk[j*4 + 3]);
        }

        for (int j = 16; j < 64; j++) {
            uint32_t s0 = rightRotate(w[j-15], 7) ^ rightRotate(w[j-15], 18) ^ (w[j-15] >> 3);
            uint32_t s1 = rightRotate(w[j-2], 17) ^ rightRotate(w[j-2], 19) ^ (w[j-2] >> 10);
            w[j] = w[j-16] + s0 + w[j-7] + s1;
        }

        uint32_t a = hash_values[0];
        uint32_t b = hash_values[1];
        uint32_t c = hash_values[2];
        uint32_t d = hash_values[3];
        uint32_t e = hash_values[4];
        uint32_t f = hash_values[5];
        uint32_t g = hash_values[6];
        uint32_t h = hash_values[7];

        for (int j = 0; j < 64; j++) {
            uint32_t s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + s1 + ch + constants[j] + w[j];
            uint32_t s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash_values[0] += a;
        hash_values[1] += b;
        hash_values[2] += c;
        hash_values[3] += d;
        hash_values[4] += e;
        hash_values[5] += f;
        hash_values[6] += g;
        hash_values[7] += h;
    }

    return hash_values;
}

std::string sha256(const std::string& message) {
    std::vector<uint8_t> padded_message = padMessage(message);
    std::array<uint32_t, 8> hash_values = sha256Transform(padded_message);

    std::string hash_hex_str;
    for (uint32_t val : hash_values) {
        char buf[9];
        snprintf(buf, sizeof(buf), "%08x", val);
        hash_hex_str += std::string(buf);
    }

    return hash_hex_str;
}

int main() {
    std::string input = R"(
John the Baptist Prepares the Way
1 The beginning of the good news about Jesus the Messiah,[a] the Son of God,[b] 2 as it is written in Isaiah the prophet:

"I will send my messenger ahead of you,
    who will prepare your way"[c]—
3 "a voice of one calling in the wilderness,
'Prepare the way for the Lord,
    make straight paths for him.'"[d]

4 And so John the Baptist appeared in the wilderness, preaching a baptism of repentance for the forgiveness of sins. 5 The whole Judean countryside and all the people of Jerusalem went out to him. Confessing their sins, they were baptized by him in the Jordan River. 6 John wore clothing made of camel’s hair, with a leather belt around his waist, and he ate locusts and wild honey. 7 And this was his message: "After me comes the one more powerful than I, the straps of whose sandals I am not worthy to stoop down and untie. 8 I baptize you with[e] water, but he will baptize you with[f] the Holy Spirit."

The Baptism and Testing of Jesus
9 At that time Jesus came from Nazareth in Galilee and was baptized by John in the Jordan. 10 Just as Jesus was coming up out of the water, he saw heaven being torn open and the Spirit descending on him like a dove. 11 And a voice came from heaven: "You are my Son, whom I love; with you I am well pleased."

12 At once the Spirit sent him out into the wilderness, 13 and he was in the wilderness forty days, being tempted[g] by Satan. He was with the wild animals, and angels attended him.

Jesus Announces the Good News
14 After John was put in prison, Jesus went into Galilee, proclaiming the good news of God. 15 "The time has come," he said. "The kingdom of God has come near. Repent and believe the good news!"

Jesus Calls His First Disciples
16 As Jesus walked beside the Sea of Galilee, he saw Simon and his brother Andrew casting a net into the lake, for they were fishermen. 17 "Come, follow me," Jesus said, "and I will send you out to fish for people." 18 At once they left their nets and followed him.

19 When he had gone a little farther, he saw James son of Zebedee and his brother John in a boat, preparing their nets. 20 Without delay he called them, and they left their father Zebedee in the boat with the hired men and followed him.

Jesus Drives Out an Impure Spirit
21 They went to Capernaum, and when the Sabbath came, Jesus went into the synagogue and began to teach. 22 The people were amazed at his teaching, because he taught them as one who had authority, not as the teachers of the law. 23 Just then a man in their synagogue who was possessed by an impure spirit cried out, 24 "What do you want with us, Jesus of Nazareth? Have you come to destroy us? I know who you are—the Holy One of God!"

25 "Be quiet!" said Jesus sternly. "Come out of him!" 26 The impure spirit shook the man violently and came out of him with a shriek.

27 The people were all so amazed that they asked each other, "What is this? A new teaching—and with authority! He even gives orders to impure spirits and they obey him." 28 News about him spread quickly over the whole region of Galilee.

Jesus Heals Many
29 As soon as they left the synagogue, they went with James and John to the home of Simon and Andrew. 30 Simon’s mother-in-law was in bed with a fever, and they immediately told Jesus about her. 31 So he went to her, took her hand and helped her up. The fever left her and she began to wait on them.

32 That evening after sunset the people brought to Jesus all the sick and demon-possessed. 33 The whole town gathered at the door, 34 and Jesus healed many who had various diseases. He also drove out many demons, but he would not let the demons speak because they knew who he was.

Jesus Prays in a Solitary Place
35 Very early in the morning, while it was still dark, Jesus got up, left the house and went off to a solitary place, where he prayed. 36 Simon and his companions went to look for him, 37 and when they found him, they exclaimed: "Everyone is looking for you!"

38 Jesus replied, "Let us go somewhere else—to the nearby villages—so I can preach there also. That is why I have come." 39 So he traveled throughout Galilee, preaching in their synagogues and driving out demons.

Jesus Heals a Man With Leprosy
40 A man with leprosy[h] came to him and begged him on his knees, "If you are willing, you can make me clean."

41 Jesus was indignant.[i] He reached out his hand and touched the man. "I am willing," he said. "Be clean!" 42 Immediately the leprosy left him and he was cleansed.

43 Jesus sent him away at once with a strong warning: "See that you don’t tell this to anyone. But go, show yourself to the priest and offer the sacrifices that Moses commanded for your cleansing, as a testimony to them." 45 Instead he went out and began to talk freely, spreading the news. As a result, Jesus could no longer enter a town openly but stayed outside in lonely places. Yet the people still came to him from everywhere.
)";

    std::string output = sha256(input);
    std::cout << output << std::endl;
    return 0;
}