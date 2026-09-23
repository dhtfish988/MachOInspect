#include <macho_inspect/inspection.hpp>

namespace macho_inspect {
bool InspectionResult::failed() const {
  if (!errors.empty() || (resources && !resources->errors.empty()))
    return true;
  return std::any_of(images.begin(), images.end(), [](const auto &image) {
    return !image.errors.empty() || !image.claims.errors.empty();
  });
}
std::vector<Observation> InspectionResult::observations() const {
  std::vector<Observation> collected;
  for (const auto &image : images)
    for (auto item : image.observations) {
      item.evidence["architecture"] = image.image.architecture;
      collected.push_back(std::move(item));
    }
  if (resources)
    collected.insert(collected.end(), resources->observations.begin(),
                     resources->observations.end());
  std::stable_sort(collected.begin(), collected.end(),
                   [](const auto &first, const auto &second) {
                     return first.impact != second.impact
                                ? first.impact > second.impact
                                : first.code < second.code;
                   });
  return collected;
}
InspectionResult
InspectionSession::inspect_bytes(Bytes bytes, const std::string &label) const {
  InspectionResult result;
  result.path = label;
  result.byte_length = bytes.size();
  try {
    if (bytes.size() > maximum_input_bytes)
      throw DecodeFailure("input", "input exceeds byte limit");
    for (auto slice : ImageCatalog::decode(bytes)) {
      ImageResult image;
      image.image = std::move(slice);
      if (image.image.signature_range)
        try {
          auto [offset, length] = *image.image.signature_range;
          image.signing = SigningEnvelope::decode(
              ByteCursor(bytes, "signature")
                  .region(image.image.file_offset, image.image.byte_length)
                  .region(offset, length)
                  .bytes());
          image.claims = EntitlementDocument::decode(*image.signing);
        } catch (const DecodeFailure &error) {
          image.errors.push_back(error.diagnostic);
        }
      image.observations = InspectionRule::evaluate(image);
      result.images.push_back(std::move(image));
    }
  } catch (const DecodeFailure &error) {
    result.errors.push_back(error.diagnostic);
  } catch (const std::exception &error) {
    result.errors.push_back({"inspection", error.what(), 0});
  }
  return result;
}
InspectionResult
InspectionSession::inspect_file(const std::filesystem::path &path) const {
  try {
    auto bytes = read_input(path);
    return inspect_bytes(bytes, path.string());
  } catch (const DecodeFailure &error) {
    InspectionResult result;
    result.path = path.string();
    result.errors.push_back(error.diagnostic);
    return result;
  } catch (const std::exception &error) {
    InspectionResult result;
    result.path = path.string();
    result.errors.push_back({"input", error.what(), 0});
    return result;
  }
}
InspectionResult
InspectionSession::inspect_path(const std::filesystem::path &path,
                                InspectionOptions options) const {
  try {
    auto bundle = BundleDescriptor::discover(path);
    if (!bundle)
      return inspect_file(path);
    InspectionResult result;
    if (!bundle->executable.empty())
      result = inspect_file(bundle->executable);
    else
      result.errors.push_back({"bundle", "no executable found in bundle", 0});
    result.path = path.string();
    if (options.check_resources)
      result.resources = ResourceManifest::inspect(*bundle, result.images);
    return result;
  } catch (const DecodeFailure &error) {
    InspectionResult result;
    result.path = path.string();
    result.errors.push_back(error.diagnostic);
    return result;
  } catch (const std::exception &error) {
    InspectionResult result;
    result.path = path.string();
    result.errors.push_back({"bundle", error.what(), 0});
    return result;
  }
}
} // namespace macho_inspect
