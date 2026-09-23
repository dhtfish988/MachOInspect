#include <iostream>
#include <macho_inspect/inspection.hpp>
int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: inspect-consumer PATH\n";
    return 2;
  }
  auto result = macho_inspect::InspectionSession().inspect_path(argv[1]);
  std::cout << macho_inspect::JsonEmitter::render({result}).dump(2) << '\n';
  return result.failed() ? 2 : 0;
}
