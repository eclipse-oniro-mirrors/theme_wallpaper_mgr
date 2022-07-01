#ifndef CMDRESOLVER_COMMAND_H
#define CMDRESOLVER_COMMAND_H
#include <functional>
#include <string>
#include <vector>
namespace OHOS {
namespace MiscServices {
class Command {
public:
    using Action = std::function<bool(const std::vector<std::string> &input, std::string &output)>;
    Command(const std::vector<std::string> &argsFormat, const std::string &help, const Action &action);
    std::string ShowHelp();
    bool DoAction(const std::vector<std::string> &vector, std::string &output);
    std::string GetOption();
    std::string GetFormat();

private:
    std::vector<std::string> format_;
    std::string help_;
    Action action_;
};
} // namespace MiscServices
} // namespace OHOS
#endif//CMDRESOLVER_COMMAND_H