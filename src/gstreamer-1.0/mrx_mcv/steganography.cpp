#include "mrx_mcv/steganography.h"
namespace mrx {
namespace mcv {

bool SteganographyDecodeData(const void *data_ptr, size_t data_size,
                             ExtraData &extra) {
  const size_t required_size = sizeof(ExtraData) * 8;
  const unsigned char *data = static_cast<const unsigned char *>(data_ptr);

  if (data_size < required_size) {
    return false;
  }

  unsigned char *dst = reinterpret_cast<unsigned char *>(&extra);

  for (size_t i = 0; i < sizeof(ExtraData); i++) {
    *dst = static_cast<unsigned char>(
        ((0x1 & data[0]) << 0) | ((0x1 & data[1]) << 1) |
        ((0x1 & data[2]) << 2) | ((0x1 & data[3]) << 3) |
        ((0x1 & data[4]) << 4) | ((0x1 & data[5]) << 5) |
        ((0x1 & data[6]) << 6) | ((0x1 & data[7]) << 7));

    dst += 1;
    data += 8;
  }

  return extra.IsValid();
}

bool SteganographyEncodeData(unsigned char *dst, size_t dst_size,
                             const ExtraData &ex) {
  ExtraData tmp = ex;
  tmp.checksum = tmp.ComputeChecksum();
  if (!tmp.IsValid()) {
    return false;
  }
  return SteganographyEncodeData(dst, dst_size, &tmp, sizeof(tmp));
}

bool SteganographyEncodeData(unsigned char *dst, size_t dst_size,
                             const void *data_ptr, size_t data_size) {
  const size_t required_size = data_size * 8;
  const unsigned char *data = static_cast<const unsigned char *>(data_ptr);

  if (dst_size < required_size) {
    return false;
  }

  for (size_t i = 0; i < data_size; i++) {
    unsigned char c = data[i];
    for (size_t bit = 0; bit < 8; bit++) {
      *dst = (*dst & ~0x1) | ((c >> bit) & 0x1);
      dst += 1;
    }
  }
  return true;
}

}  // namespace mcv
}  // namespace mrx
