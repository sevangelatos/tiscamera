#ifndef MRX_MCV_STEGANOGRAPHY_H
#define MRX_MCV_STEGANOGRAPHY_H

#include <cstddef>
#include <cstdint>

namespace mrx {
namespace mcv {

#pragma pack(push, 4)
struct ExtraData {
  uint32_t signature = 0xF00DCAFE;
  uint64_t frame_count = 0;
  uint32_t checksum = 0;  // Must be last field.

  uint32_t ComputeChecksum() const {
    // Compute checksum
    uint32_t csum = 0;
    const uint32_t *extra_data = reinterpret_cast<const uint32_t *>(this);
    while (extra_data != &checksum) {
      csum = (*extra_data) ^ csum;
      extra_data++;
    }
    return csum;
  }

  bool IsValid() const {
    return signature == 0xF00DCAFE && checksum == ComputeChecksum();
  }
};
#pragma pack(pop)

/**
 * @brief Decode ExtraData encoded in the low-bits of the data buffer
 * @param data_ptr The source data buffer
 * @param data_size The source data buffer size
 * @param extra Structure with the decoded data
 * @return True on success, false otherwise
 */
bool SteganographyDecodeData(const void *data_ptr, size_t data_size,
                             ExtraData &extra);

/**
 * @brief Encode ExtraData in the low-bits of the data buffer
 * @param dst The destination data buffer
 * @param dst_size The destination data buffer size
 * @param ex Structure with the data to be encoded
 * @return True on success, false otherwise
 */
bool SteganographyEncodeData(unsigned char *dst, size_t dst_size,
                             const ExtraData &ex);

/**
 * @brief Encode arbitrary data in the low-bits of the data buffer
 * @param dst The destination data buffer
 * @param dst_size The destination data buffer size
 * @param data_ptr The data to be encoded
 * @param data_size The length of data to be encoded
 * @return True on success, false otherwise
 */
bool SteganographyEncodeData(unsigned char *dst, size_t dst_size,
                             const void *data_ptr, size_t data_size);

}  // namespace mcv
}  // namespace mrx

#endif  // MRX_MCV_STEGANOGRAPHY_H
