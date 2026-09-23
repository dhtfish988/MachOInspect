#include <macho_inspect/inspection.hpp>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *bytes,
                                      std::size_t length) {
  auto input = macho_inspect::Bytes(bytes, length);
  if (length > 1024 * 1024)
    return 0;
  (void)macho_inspect::InspectionSession().inspect_bytes(input);
  try {
    (void)macho_inspect::SigningEnvelope::decode(input);
  } catch (const std::exception &) {
  }
  try {
    (void)macho_inspect::decode_der(input);
  } catch (const std::exception &) {
  }
  try {
    (void)macho_inspect::decode_plist(input);
  } catch (const std::exception &) {
  }
  return 0;
}
