#include <fstream>
#include <iostream>
#include <macho_inspect/inspection.hpp>
#include <plist/plist.h>
#include <unistd.h>
using namespace macho_inspect;
namespace fs = std::filesystem;
namespace {
unsigned passed = 0, failed = 0;
void check(bool condition, const std::string &name) {
  if (condition)
    ++passed;
  else {
    ++failed;
    std::cerr << "FAIL: " << name << '\n';
  }
}
void write(const fs::path &path, const std::string &value) {
  fs::create_directories(path.parent_path());
  std::ofstream stream(path, std::ios::binary);
  stream << value;
}
plist_t native(const ClaimValue &value) {
  if (value.is_object()) {
    auto node = plist_new_dict();
    for (auto item = value.begin(); item != value.end(); ++item)
      plist_dict_set_item(node, item.key().c_str(), native(item.value()));
    return node;
  }
  if (value.is_array()) {
    auto node = plist_new_array();
    for (const auto &item : value)
      plist_array_append_item(node, native(item));
    return node;
  }
  if (value.is_binary()) {
    const auto &bytes = value.get_binary();
    return plist_new_data(reinterpret_cast<const char *>(bytes.data()),
                          bytes.size());
  }
  if (value.is_string())
    return plist_new_string(value.get_ref<const std::string &>().c_str());
  if (value.is_boolean())
    return plist_new_bool(value.get<bool>());
  if (value.is_number())
    return plist_new_real(value.get<double>());
  return plist_new_null();
}
void save(const fs::path &path, const ClaimValue &value) {
  auto node = native(value);
  char *xml = nullptr;
  std::uint32_t length = 0;
  if (plist_to_xml(node, &xml, &length) != PLIST_ERR_SUCCESS)
    throw std::runtime_error("fixture plist encoding failed");
  write(path, std::string(xml, length));
  plist_mem_free(xml);
  plist_free(node);
}
bool has(const SealAssessment &report, const std::string &code) {
  return std::any_of(report.observations.begin(), report.observations.end(),
                     [&](const auto &item) { return item.code == code; });
}
ClaimValue hash_value(const std::string &value) {
  auto hex = calculate_digest(
      Bytes(reinterpret_cast<const std::uint8_t *>(value.data()), value.size()),
      "sha256");
  std::vector<std::uint8_t> bytes;
  for (std::size_t index = 0; index < hex.size(); index += 2)
    bytes.push_back(static_cast<std::uint8_t>(
        std::stoul(hex.substr(index, 2), nullptr, 16)));
  return ClaimValue::binary(bytes);
}
} // namespace
int main() {
  try {
    std::string pattern =
        (fs::temp_directory_path() / "macho-inspect-resource-tests-XXXXXX")
            .string();
    if (!mkdtemp(pattern.data()))
      throw std::runtime_error("mkdtemp failed");
    fs::path workspace = pattern;
    struct Cleanup {
      fs::path path;
      ~Cleanup() {
        std::error_code error;
        fs::remove_all(path, error);
      }
    } cleanup{workspace};
    auto base = workspace / "App/Contents";
    fs::create_directories(base);
    BundleDescriptor bundle{workspace / "App",
                            base,
                            base / "_CodeSignature/CodeResources",
                            {},
                            false};
    auto assess = [&](ClaimValue document) {
      save(bundle.manifest, document);
      return ResourceManifest::inspect(bundle, {});
    };
    ClaimValue document = {
        {"files2", {{"Resources/item", {{"hash2", hash_value("original")}}}}},
        {"rules2",
         {{"^Resources/", {{"weight", 20}}}, {"^.*", {{"omit", true}}}}}};
    write(base / "Resources/item", "original");
    auto report = assess(document);
    check(report.errors.empty() && report.observations.empty(),
          "synthetic clean seal");
    write(base / "Resources/item", "changed");
    check(has(assess(document), "resource-hash-mismatch"), "hash mismatch");
    write(base / "Resources/item", "original");
    write(base / "Resources/unlisted", "later");
    check(has(assess(document), "resource-unsealed"), "unlisted file");
    auto exempt = document;
    exempt["rules2"]["^Resources/unlisted$"] = {{"omit", true}, {"weight", 30}};
    check(!has(assess(exempt), "resource-unsealed"),
          "higher-weight omission wins");
    auto order = document;
    order["rules2"] = ClaimValue::object();
    order["rules2"]["^Resources/"] = {{"omit", true}, {"weight", 1}};
    order["rules2"]["^Resources/.*"] = {{"weight", 1}};
    check(!has(assess(order), "resource-unsealed"),
          "equal-weight original insertion order");
    order["rules2"] = ClaimValue::object();
    order["rules2"]["^Resources/.*"] = {{"weight", 1}};
    order["rules2"]["^Resources/"] = {{"omit", true}, {"weight", 1}};
    check(has(assess(order), "resource-unsealed"),
          "equal-weight reverse insertion order");
    auto v1 = document;
    v1["rules"] = {{"^Resources/", {{"omit", true}}}};
    check(!has(assess(v1), "resource-unsealed"),
          "v1 omission remains effective");
    fs::remove(base / "Resources/unlisted");
    auto bad_regex = document;
    bad_regex["rules2"] = {{"[", true}};
    check(!assess(bad_regex).errors.empty(),
          "invalid regular expression is incomplete");
    fs::remove(base / "Resources/item");
    check(has(assess(document), "resource-missing"), "missing sealed file");
    fs::create_directory(base / "Resources/item");
    check(has(assess(document), "resource-type-changed"),
          "file changed into directory");
    fs::remove(base / "Resources/item");
    write(base / "Resources/item", "original");
    auto unknown = document;
    unknown["files2"]["Resources/item"]["hash2"] =
        ClaimValue::binary(std::vector<std::uint8_t>(17, 1));
    check(has(assess(unknown), "resource-hash-unsupported"),
          "unsupported digest size");
    auto symbolic = document;
    symbolic["files2"]["Resources/link"] = {{"symlink", "item"}};
    fs::create_symlink("item", base / "Resources/link");
    check(assess(symbolic).observations.empty(),
          "sealed symlink compares target text");
    fs::remove(base / "Resources/link");
    fs::create_symlink("other", base / "Resources/link");
    check(has(assess(symbolic), "resource-symlink-changed"),
          "changed dangling symlink");
    fs::remove(base / "Resources/link");
    write(base / "Resources/link", "file");
    check(has(assess(symbolic), "resource-type-changed"),
          "symlink changed into file");
    fs::remove(base / "Resources/link");
    auto nested = document;
    nested["files2"]["Nested"] = {{"requirement", "identifier test.nested"}};
    check(has(assess(nested), "resource-missing"), "missing nested code");
    fs::create_directory(base / "Nested");
    report = assess(nested);
    check(report.observations.empty() &&
              report.checks[0]["identity_verification"] == "not_performed",
          "nested code identity explicitly unevaluated");
    fs::remove(base / "Nested");
    fs::create_directory(workspace / "outside-nested");
    fs::create_directory_symlink(workspace / "outside-nested", base / "Nested");
    check(has(assess(nested), "resource-path-escape"), "nested code escape");
    fs::remove(base / "Nested");
    auto traversal = document;
    traversal["files2"]["../../outside"] = {{"hash2", hash_value("x")}};
    check(has(assess(traversal), "resource-path-escape"),
          "relative path escape");
    traversal = document;
    traversal["files2"]["/tmp/not-read"] = {{"hash2", hash_value("x")}};
    check(has(assess(traversal), "resource-path-escape"),
          "absolute path escape");
    write(base / "real/item", "original");
    fs::remove_all(base / "Resources");
    fs::create_directory_symlink(base / "real", base / "Resources");
    check(assess(document).observations.empty(),
          "parent symlink within bundle hashes correctly");
    fs::remove(base / "Resources");
    fs::create_directories(base / "Resources");
    write(base / "Resources/item", "original");
    fs::remove_all(base / "real");
    auto many = document;
    for (unsigned index = 0; index < 55; ++index)
      many["files2"]["Resources/missing-" + std::to_string(index)] = {
          {"hash2", hash_value("missing")}};
    report = assess(many);
    check(report.observations.size() == 41 &&
              has(report, "resource-problems-remain"),
          "resource findings capped with remaining count");
    save(bundle.manifest, document);
    auto encoded = read_input(bundle.manifest);
    ImageResult image;
    image.signing = SigningEnvelope{};
    DirectoryRecord record;
    record.algorithm = "sha256";
    record.special_digests[3] = calculate_digest(encoded, "sha256");
    image.signing->directories.push_back(record);
    check(ResourceManifest::inspect(bundle, {image}).linkage == "match",
          "manifest matches CodeDirectory special slot");
    auto other = image;
    other.signing->directories[0].special_digests[3] = std::string(64, '0');
    check(ResourceManifest::inspect(bundle, {image, other}).linkage ==
              "mismatch",
          "all recorded architecture seals must agree");
    fs::remove(bundle.manifest);
    check(ResourceManifest::inspect(bundle, {image}).linkage == "absent",
          "recorded absent seal");
    check(ResourceManifest::inspect(bundle, {}).linkage == "unrecorded",
          "unrecorded absent seal");
    write(bundle.manifest, "broken plist");
    check(!ResourceManifest::inspect(bundle, {}).errors.empty(),
          "malformed resource manifest is an error");
    std::cout << passed << " resource checks passed; " << failed << " failed\n";
    return failed ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
}
