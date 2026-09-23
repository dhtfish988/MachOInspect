#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace macho_inspect {
using ClaimValue = nlohmann::ordered_json;
using Bytes = std::span<const std::uint8_t>;
inline constexpr std::uint64_t maximum_input_bytes = 512ULL * 1024 * 1024;
inline constexpr std::size_t maximum_document_bytes = 16 * 1024 * 1024;

struct Diagnostic {
  std::string stage;
  std::string message;
  std::uint64_t offset = 0;
};
class DecodeFailure final : public std::runtime_error {
public:
  Diagnostic diagnostic;
  DecodeFailure(std::string stage, std::string message,
                std::uint64_t offset = 0)
      : std::runtime_error(message),
        diagnostic{std::move(stage), std::move(message), offset} {}
};

class ByteCursor {
  Bytes bytes_;
  std::string stage_;
  std::uint64_t origin_;

public:
  explicit ByteCursor(Bytes bytes, std::string stage = "binary",
                      std::uint64_t origin = 0)
      : bytes_(bytes), stage_(std::move(stage)), origin_(origin) {}
  std::size_t size() const { return bytes_.size(); }
  Bytes bytes() const { return bytes_; }
  void require(std::uint64_t offset, std::uint64_t length) const;
  ByteCursor region(std::uint64_t offset, std::uint64_t length) const;
  std::uint64_t integer(std::uint64_t offset, unsigned width,
                        bool big_endian = true) const;
  std::string text(std::uint64_t offset, std::uint64_t length,
                   bool require_nul = false) const;
};

struct SegmentRecord {
  std::string label;
  std::uint64_t virtual_address = 0, virtual_size = 0, file_offset = 0,
                file_length = 0;
  std::uint32_t maximum_protection = 0, initial_protection = 0,
                section_count = 0;
};
struct ImageSlice {
  std::uint64_t file_offset = 0, byte_length = 0;
  std::uint32_t cpu_kind = 0, cpu_variant = 0, image_kind = 0, header_flags = 0;
  bool wide = false, big_endian = false;
  std::string architecture;
  std::vector<SegmentRecord> segments;
  std::vector<std::pair<std::uint32_t, std::string>> dependencies;
  std::vector<std::string> search_paths;
  std::optional<std::pair<std::uint64_t, std::uint64_t>> signature_range;
  ClaimValue commands = ClaimValue::array(), encryption = nullptr,
             build = nullptr;
};
class ImageCatalog {
public:
  static std::vector<ImageSlice> decode(Bytes input);
  static bool recognises(Bytes prefix);
};

struct DirectoryRecord {
  std::uint32_t slot = 0, version = 0, attributes = 0;
  std::string identifier, team_identifier, algorithm, digest;
  std::uint8_t algorithm_code = 0, digest_width = 0, platform = 0;
  std::uint64_t page_bytes = 0, covered_bytes = 0, executable_base = 0,
                executable_limit = 0, executable_flags = 0;
  std::uint32_t code_slots = 0, special_slots = 0, encoded_bytes = 0;
  std::map<std::uint32_t, std::string> special_digests;
};
struct SigningEnvelope {
  std::vector<DirectoryRecord> directories;
  std::optional<std::vector<std::uint8_t>> plist_claims, der_claims;
  std::uint64_t cms_bytes = 0;
  ClaimValue entries = ClaimValue::array();
  static SigningEnvelope decode(Bytes input);
  const DirectoryRecord &primary() const;
  const DirectoryRecord &preferred() const;
};
struct EntitlementDocument {
  std::optional<ClaimValue> plist, der;
  std::vector<Diagnostic> errors;
  ClaimValue selected = ClaimValue::object();
  std::string source = "absent";
  bool disagree = false;
  ClaimValue differences = ClaimValue::array();
  static EntitlementDocument decode(const SigningEnvelope &signature);
};
ClaimValue decode_plist(Bytes input);
ClaimValue decode_der(Bytes input);
std::string calculate_digest(Bytes input, const std::string &algorithm);
std::string digest_file(const std::filesystem::path &path,
                        const std::string &algorithm);
std::vector<std::uint8_t> read_input(const std::filesystem::path &path,
                                     std::uint64_t limit = maximum_input_bytes);
std::string to_hex(Bytes bytes);

enum class Impact { info, low, medium, high };
std::string impact_name(Impact impact);
Impact parse_impact(const std::string &name);
struct Observation {
  std::string code;
  Impact impact = Impact::info;
  std::string message, explanation;
  ClaimValue evidence = ClaimValue::object();
};
struct ImageResult {
  ImageSlice image;
  std::optional<SigningEnvelope> signing;
  EntitlementDocument claims;
  std::vector<Observation> observations;
  std::vector<Diagnostic> errors;
};
class InspectionRule {
public:
  static std::vector<Observation> evaluate(const ImageResult &facts);
};
struct SealAssessment {
  std::string executable;
  std::string linkage = "unrecorded";
  ClaimValue checks = ClaimValue::array(), unlisted = ClaimValue::array();
  std::vector<Observation> observations;
  std::vector<Diagnostic> errors;
};
struct BundleDescriptor {
  std::filesystem::path root, content, manifest, executable;
  bool flat = false;
  static std::optional<BundleDescriptor>
  discover(const std::filesystem::path &root);
};
class BundleAccess {
public:
  static std::filesystem::path resolve(const std::filesystem::path &root,
                                       const std::filesystem::path &relative,
                                       bool follow_leaf = true);
};
class ResourceManifest {
public:
  static SealAssessment inspect(const BundleDescriptor &bundle,
                                const std::vector<ImageResult> &images);
};
struct InspectionResult {
  std::string path;
  std::uint64_t byte_length = 0;
  std::vector<ImageResult> images;
  std::optional<SealAssessment> resources;
  std::vector<Diagnostic> errors;
  bool failed() const;
  std::vector<Observation> observations() const;
};
struct InspectionOptions {
  bool check_resources = true;
};
class InspectionSession {
public:
  InspectionResult inspect_bytes(Bytes input,
                                 const std::string &label = "<memory>") const;
  InspectionResult inspect_file(const std::filesystem::path &path) const;
  InspectionResult inspect_path(const std::filesystem::path &path,
                                InspectionOptions options = {}) const;
};
class JsonEmitter {
public:
  static ClaimValue render(const std::vector<InspectionResult> &results);
};
class TextEmitter {
public:
  static std::string render(const std::vector<InspectionResult> &results,
                            Impact minimum = Impact::info, bool verbose = false,
                            bool summary = false);
};
} // namespace macho_inspect
