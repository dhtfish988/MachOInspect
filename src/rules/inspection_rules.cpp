#include <macho_inspect/inspection.hpp>
#include <set>

namespace macho_inspect {
std::string impact_name(Impact impact) {
  switch (impact) {
  case Impact::high:
    return "high";
  case Impact::medium:
    return "medium";
  case Impact::low:
    return "low";
  case Impact::info:
    return "info";
  }
  return "info";
}
Impact parse_impact(const std::string &name) {
  if (name == "high")
    return Impact::high;
  if (name == "medium")
    return Impact::medium;
  if (name == "low")
    return Impact::low;
  if (name == "info")
    return Impact::info;
  throw DecodeFailure("options", "unknown severity: " + name);
}
std::vector<Observation> InspectionRule::evaluate(const ImageResult &facts) {
  const auto &image = facts.image;
  std::vector<Observation> result;
  auto add = [&](std::string code, Impact level, std::string message,
                 std::string explanation,
                 ClaimValue evidence = ClaimValue::object()) {
    result.push_back({std::move(code), level, std::move(message),
                      std::move(explanation), std::move(evidence)});
  };
  if (image.image_kind == 2 && !(image.header_flags & 0x200000))
    add("no-pie", Impact::high, "Position independence is not declared",
        "MH_PIE is clear in this executable's header.");
  if (image.header_flags & 0x20000)
    add("executable-stack", Impact::high, "Executable stack requested",
        "MH_ALLOW_STACK_EXECUTION is set.");
  for (const auto &segment : image.segments)
    if ((segment.initial_protection & 6) == 6)
      add("wx-segment", Impact::high,
          "Writable and executable segment: " + segment.label,
          "The initial mapping protection includes both write and execute.",
          {{"segment", segment.label},
           {"initial_protection", segment.initial_protection}});
  ClaimValue weak = ClaimValue::array(), relative = ClaimValue::array();
  for (const auto &[kind, path] : image.dependencies) {
    if (kind == 0x80000018)
      weak.push_back(path);
    if (path.starts_with("@rpath/"))
      relative.push_back(path);
  }
  if (!weak.empty())
    add("weak-dylibs", Impact::low, "Optional library dependencies",
        "Review whether missing dependencies can be supplied from writable "
        "locations.",
        {{"libraries", weak}});
  if (!relative.empty() && !image.search_paths.empty())
    add("rpath-resolution", Impact::info, "Libraries use run-path search",
        "The declared search order affects which dependency is selected.",
        {{"search_paths", image.search_paths}, {"libraries", relative}});
  if (!image.encryption.is_null() && image.encryption["identifier"] != 0)
    add("encrypted", Impact::info, "Encrypted range declared",
        "Static bytes in the declared encrypted range do not represent decoded "
        "instructions.",
        image.encryption);
  if (!image.signature_range) {
    add("unsigned", image.image_kind == 2 ? Impact::high : Impact::medium,
        "No embedded signature declared",
        "No LC_CODE_SIGNATURE is present in this slice.");
    return result;
  }
  if (!facts.signing) {
    add("signature-unparsable", Impact::high,
        "Signature structure could not be decoded",
        "See the structured parsing error. No signature validity conclusion is "
        "available.");
    return result;
  }
  const auto &signature = *facts.signing;
  const auto &primary = signature.preferred();
  bool adhoc = primary.attributes & 2;
  if (adhoc)
    add("adhoc-signature", Impact::medium, "Ad-hoc signing metadata",
        "The ad-hoc flag declares no certificate-backed identity. This "
        "inspection does not recompute code pages.",
        {{"identifier", primary.identifier}});
  else if (!signature.cms_bytes)
    add("no-cms-signature", Impact::medium, "CMS payload is absent",
        "The signature is not marked ad-hoc but has no nonempty CMS wrapper.");
  if (primary.attributes & 0x20000)
    add("linker-signed", Impact::info, "Linker signing flag declared",
        "This flag commonly appears on linker output before a separate signing "
        "step.");
  if (!adhoc && signature.cms_bytes && primary.team_identifier.empty() &&
      !primary.platform)
    add("no-team-identifier", Impact::low, "Team identifier is absent",
        "The inspected CodeDirectory does not declare a development team.");
  std::set<unsigned> kinds;
  for (const auto &record : signature.directories)
    kinds.insert(record.algorithm_code);
  if (kinds == std::set<unsigned>{1})
    add("sha1-only", Impact::high, "Only SHA-1 directories declared",
        "No stronger alternative CodeDirectory is present.");
  else if (kinds.contains(1))
    add("sha1-legacy-directory", Impact::info,
        "SHA-1 directory accompanies another algorithm",
        "Legacy compatibility metadata remains present; inspect the alternate "
        "algorithms.");
  for (auto [flag, code, level, description] :
       std::vector<std::tuple<unsigned, std::string, Impact, std::string>>{
           {4, "cs-get-task-allow", Impact::high, "Task-access flag declared"},
           {0x20, "cs-invalid-allowed", Impact::high,
            "Invalid-signature execution flag declared"},
           {8, "cs-installer", Impact::low, "Installer flag declared"}})
    if (primary.attributes & flag)
      add(code, level, description,
          "This is a recorded CodeDirectory flag, not a measurement of "
          "permissions granted by the operating system.");
  if (image.image_kind == 2 && !(primary.attributes & 0x10000)) {
    if (primary.platform)
      add("platform-binary", Impact::info, "Platform identifier declared",
          "The hardened-runtime rule exempts slices that declare a platform "
          "identifier; the identifier is not authenticated here.",
          {{"platform", primary.platform}});
    else
      add("no-hardened-runtime", Impact::medium,
          "Hardened runtime is not declared",
          "CS_RUNTIME is clear in the inspected CodeDirectory.");
  }
  const std::vector<std::tuple<unsigned, std::string, Impact, std::string>>
      execution = {
          {0x10, "allow-unsigned", Impact::high,
           "Unsigned execution permission requested"},
          {0x20, "debugger", Impact::high, "Debugger permission requested"},
          {0x40, "jit", Impact::medium, "JIT execution permission requested"},
          {0x80, "skip-lv", Impact::high,
           "Library-validation exception requested"},
          {0x100, "can-load-cdhash", Impact::high,
           "Code-hash loading permission requested"},
          {0x200, "can-exec-cdhash", Impact::high,
           "Code-hash execution permission requested"}};
  for (const auto &[flag, code, level, message] : execution)
    if (primary.executable_flags & flag)
      add("execseg-" + code, level, message,
          "The executable-segment flags declare this capability; actual "
          "authorization is not inspected.");
  for (const auto &error : facts.claims.errors)
    add(error.stage == "der" ? "entitlements-der-unparsable"
                             : "entitlements-plist-unparsable",
        Impact::medium, "Entitlement document could not be decoded",
        error.message);
  if (facts.claims.disagree)
    add("entitlements-slot-mismatch", Impact::high,
        "Entitlement declarations disagree",
        "The plist and DER slots decode to different typed values. Both "
        "declarations are retained in the report.",
        {{"differences", facts.claims.differences}});
  if (facts.claims.plist && !facts.claims.der)
    add("entitlements-no-der", Impact::low,
        "Only the plist declaration was decoded",
        "No usable DER entitlement declaration was found.");
  static const std::map<std::string, std::pair<Impact, std::string>>
      named_claims = {
          {"com.apple.security.get-task-allow",
           {Impact::high, "Requests debugger attachment to this process"}},
          {"com.apple.security.cs.debugger",
           {Impact::high, "Requests debugger capabilities"}},
          {"com.apple.security.cs.disable-library-validation",
           {Impact::high, "Requests loading libraries without the normal "
                          "signing-team restriction"}},
          {"com.apple.security.cs.allow-unsigned-executable-memory",
           {Impact::high, "Requests unsigned executable memory"}},
          {"com.apple.security.cs.disable-executable-page-protection",
           {Impact::high, "Requests relaxed protection of executable pages"}},
          {"com.apple.security.cs.allow-dyld-environment-variables",
           {Impact::high, "Requests loader environment overrides"}},
          {"com.apple.private.security.no-sandbox",
           {Impact::high, "Requests a sandbox exemption"}},
          {"task_for_pid-allow", {Impact::high, "Requests task-port access"}},
          {"platform-application",
           {Impact::high, "Declares platform-application status"}},
          {"com.apple.security.cs.allow-jit",
           {Impact::medium, "Requests JIT memory"}},
          {"com.apple.system-task-ports",
           {Impact::medium, "Requests system task-port access"}},
          {"com.apple.security.cs.allow-relative-library-loads",
           {Impact::medium, "Requests relative library loading"}},
          {"com.apple.private.tcc.allow",
           {Impact::medium, "Requests TCC exceptions"}},
          {"com.apple.rootless.install",
           {Impact::medium, "Requests protected-path installation access"}},
          {"com.apple.rootless.install.heritable",
           {Impact::medium,
            "Requests inheritable protected-path installation access"}},
          {"keychain-access-groups",
           {Impact::low, "Declares shared keychain groups"}},
          {"com.apple.security.app-sandbox",
           {Impact::info, "Requests App Sandbox confinement"}}};
  const std::vector<std::tuple<std::string, Impact, std::string>> prefixes = {
      {"com.apple.security.temporary-exception.", Impact::medium,
       "Requests a sandbox exception"},
      {"com.apple.security.cs.", Impact::medium,
       "Declares a code-signing capability"},
      {"com.apple.private.", Impact::low,
       "Declares an Apple-private entitlement"},
      {"com.apple.security.device.", Impact::info, "Requests device access"},
      {"com.apple.security.files.", Impact::info, "Requests file access"},
      {"com.apple.security.network.", Impact::info, "Requests network access"}};
  for (auto entry = facts.claims.selected.begin();
       entry != facts.claims.selected.end(); ++entry) {
    if (entry.value().is_boolean() && !entry.value().get<bool>())
      continue;
    auto known = named_claims.find(entry.key());
    std::optional<std::pair<Impact, std::string>> classification;
    if (known != named_claims.end())
      classification = known->second;
    else
      for (const auto &[prefix, level, message] : prefixes)
        if (entry.key().starts_with(prefix)) {
          classification = {{level, message}};
          break;
        }
    if (classification)
      add("entitlement:" + entry.key(), classification->first,
          "Declared entitlement: " + entry.key(),
          classification->second +
              ". The operating system's actual grant is not established.",
          {{"value", entry.value()}, {"source", facts.claims.source}});
  }
  auto signature_offset = image.signature_range->first;
  if (primary.covered_bytes && primary.covered_bytes < signature_offset)
    add("signature-gap", Impact::high, "Signature coverage metadata ends early",
        "The declared code limit precedes the signature region.",
        {{"covered_bytes", primary.covered_bytes},
         {"signature_offset", signature_offset},
         {"uncovered_bytes", signature_offset - primary.covered_bytes}});
  if (primary.page_bytes && primary.covered_bytes) {
    auto needed = primary.covered_bytes / primary.page_bytes +
                  (primary.covered_bytes % primary.page_bytes != 0);
    if (primary.code_slots < needed)
      add("code-slot-shortfall", Impact::high, "Too few code-hash slots",
          "The declared slot count is insufficient for the declared coverage "
          "and page size.");
  }
  return result;
}
} // namespace macho_inspect
